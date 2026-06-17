"""
Shared async task utilities for tool wrappers.

Add ``--async-start`` / ``--async-status`` to any long-running security tool
wrapper with minimal boilerplate.  The pattern is the same one used by
``nmap_json_scan.py``, extracted here so other tools can reuse it.

Usage inside a tool wrapper::

    from _async_utils import add_async_args, async_start, async_status, utc_now

    # In parse_args():
    add_async_args(parser, "toolname")

    # In main(), before the real work:
    if args.async_status:
        return async_status(args, started_at)

    # ... authorisation / binary checks ...

    if args.async_start:
        return async_start(args, argv, "toolname", started_at)

Each async task creates a directory under ``/tmp/codex-async-tasks/``::

    <task_id>/
      task.json     – metadata (pid, command, status, paths)
      stdout.log
      stderr.log
      result.json   – the tool's ``--output`` file
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_async_dir() -> Path:
    return Path("/tmp/codex-async-tasks")


def process_running(pid: int) -> bool:
    """Return True if *pid* is still alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ---------------------------------------------------------------------------
# argparse helpers
# ---------------------------------------------------------------------------

def add_async_args(parser: argparse.ArgumentParser, tool_name: str) -> None:
    """Register ``--async-start``, ``--async-status`` and ``--async-dir`` on *parser*."""
    parser.add_argument(
        "--async-start",
        action="store_true",
        help=f"Start {tool_name} in the background and return a task id.",
    )
    parser.add_argument(
        "--async-status",
        help="Read async task status and result by task id.",
    )
    parser.add_argument(
        "--async-dir",
        help=f"Directory for async task state.  Defaults to {default_async_dir()}.",
    )


# ---------------------------------------------------------------------------
# start / status
# ---------------------------------------------------------------------------

def _task_dir(args: argparse.Namespace) -> Path:
    return Path(args.async_dir).expanduser() if getattr(args, "async_dir", None) else default_async_dir()


def async_start(
    args: argparse.Namespace,
    argv: list[str],
    tool_name: str,
    started_at: str,
) -> int:
    """Re-invoke the current script in the background without async flags.

    Returns exit code (0 on success).
    """
    task_id = f"{tool_name}-{uuid.uuid4().hex[:12]}"
    task_root = _task_dir(args)
    task_dir = task_root / task_id
    task_dir.mkdir(parents=True, exist_ok=True)

    result_path = task_dir / "result.json"
    stdout_path = task_dir / "stdout.log"
    stderr_path = task_dir / "stderr.log"
    metadata_path = task_dir / "task.json"

    # Build the command — strip async flags, replace --output with our result path
    command = [sys.executable, str(Path(sys.argv[0]).resolve())]
    skip_next = False
    for value in argv:
        if skip_next:
            skip_next = False
            continue
        if value == "--async-start":
            continue
        if value in {"--async-status", "--async-dir"}:
            skip_next = True
            continue
        if value == "--output":
            skip_next = True  # drop the user-supplied output path
            continue
        command.append(value)
    command.extend(["--output", str(result_path)])

    # Open files, then spawn
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, \
         open(stderr_path, "w", encoding="utf-8") as stderr_file:
        process = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )

    metadata = {
        "ok": True,
        "task_id": task_id,
        "pid": process.pid,
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "command": command,
        "task_dir": str(task_dir),
        "result_path": str(result_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    _write_json(metadata_path, metadata)

    # Also write to the user-requested output so callers can discover the task id
    output_path = getattr(args, "output", None)
    if output_path:
        _write_json(Path(output_path), metadata)

    print(json.dumps(metadata, indent=2))
    return 0


def async_status(args: argparse.Namespace, started_at: str) -> int:
    """Read the status (and result) of a previously-started async task.

    Returns 0 (completed), 1 (failed), or 2 (not found).
    """
    task_root = _task_dir(args)
    task_dir = task_root / args.async_status
    metadata_path = task_dir / "task.json"

    if not metadata_path.exists():
        payload = {
            "ok": False,
            "error": {
                "type": "async_task_not_found",
                "message": f"Async task not found: {args.async_status}",
            },
            "started_at": started_at,
            "finished_at": utc_now(),
        }
        print(json.dumps(payload, indent=2))
        return 2

    metadata = _read_json(metadata_path)
    result_path = Path(metadata["result_path"])
    pid = int(metadata["pid"])
    running = process_running(pid)
    result = _read_json(result_path) if result_path.exists() else None

    if result is not None:
        status = "completed" if result.get("ok") else "failed"
    elif running:
        status = "running"
    else:
        status = "failed"

    metadata["status"] = status
    metadata["finished_at"] = (
        result.get("finished_at") if result else (None if running else utc_now())
    )
    _write_json(metadata_path, metadata)

    # Grab tail of stderr for diagnostics (last 200 lines)
    stderr_tail = ""
    stderr_path = Path(metadata.get("stderr_path", ""))
    if stderr_path.exists():
        try:
            lines = stderr_path.read_text(encoding="utf-8", errors="replace").splitlines()
            stderr_tail = "\n".join(lines[-200:])
        except Exception:
            pass

    payload = {
        "ok": status == "completed",
        "task_id": args.async_status,
        "status": status,
        "pid": pid,
        "running": running,
        "started_at": metadata.get("started_at"),
        "finished_at": metadata.get("finished_at"),
        "task_dir": str(task_dir),
        "result_path": str(result_path),
        "stderr_tail": stderr_tail,
        "result": result,
    }
    print(json.dumps(payload, indent=2))
    return 0 if status != "failed" else 1


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

def _write_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _read_json(path: Path) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None
