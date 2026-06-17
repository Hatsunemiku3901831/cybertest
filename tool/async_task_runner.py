#!/usr/bin/env python3
"""
Universal async task runner for long-running security tools.

Runs any shell command in the background, tracks its progress, and lets you
poll for completion.  Designed for tools whose scans routinely exceed the
10-minute Bash-tool timeout in Claude Code (nmap, nuclei, katana, masscan,
sqlmap, ZAP, etc.).

Usage::

    # Start a background task
    python3 tool/async_task_runner.py --start --command "nuclei -u https://example.com -o nuclei.json"

    # Check status
    python3 tool/async_task_runner.py --status <task_id>

    # Block until completion (with optional timeout)
    python3 tool/async_task_runner.py --wait <task_id> --timeout 3600

    # List all tasks
    python3 tool/async_task_runner.py --list

    # Clean up completed tasks (keep last N)
    python3 tool/async_task_runner.py --clean --keep 20

Each task lives under ``/tmp/codex-async-tasks/<task_id>/``::

    task.json     – metadata (pid, command, status, paths)
    stdout.log    – captured stdout
    stderr.log    – captured stderr
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Reuse the shared async module for consistency
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _async_utils import (  # noqa: E402
    default_async_dir,
    process_running,
    utc_now,
)

# ---------------------------------------------------------------------------
# helpers
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


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

def cmd_start(args: argparse.Namespace) -> int:
    """Spawn *args.command* in the background and print the task id."""
    task_id = f"cmd-{uuid.uuid4().hex[:12]}"
    task_root = default_async_dir()
    task_dir = task_root / task_id
    task_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = task_dir / "stdout.log"
    stderr_path = task_dir / "stderr.log"
    metadata_path = task_dir / "task.json"

    # Launch via shell so pipelines and redirects work
    started_at = utc_now()
    with open(stdout_path, "w", encoding="utf-8") as stdout_file, \
         open(stderr_path, "w", encoding="utf-8") as stderr_file:
        process = subprocess.Popen(
            args.command,
            shell=True,
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
        "command": args.command,
        "task_dir": str(task_dir),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    _write_json(metadata_path, metadata)

    print(json.dumps(metadata, indent=2))
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace) -> int:
    """Print status and (if done) result for a previously-started task."""
    task_id = getattr(args, "status", None) or getattr(args, "task_id")
    task_dir = default_async_dir() / task_id
    metadata_path = task_dir / "task.json"

    if not metadata_path.exists():
        print(json.dumps({
            "ok": False,
            "error": {"type": "task_not_found", "message": f"Task not found: {task_id}"},
        }, indent=2))
        return 2

    metadata = _read_json(metadata_path)
    pid = int(metadata["pid"])
    running = process_running(pid)

    # Read partial output on demand
    stdout_snip = ""
    stderr_snip = ""
    tail_lines = getattr(args, "tail", 0)
    if tail_lines:
        for key, target in [("stdout_path", "stdout_snip"), ("stderr_path", "stderr_snip")]:
            p = Path(metadata.get(key, ""))
            snippet = ""
            if p.exists():
                try:
                    snippet = "\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[-tail_lines:])
                except Exception:
                    snippet = "<read error>"
            if target == "stdout_snip":
                stdout_snip = snippet
            else:
                stderr_snip = snippet

    # Exit code is not reliably available cross-process; rely on running state
    # and the tool's own result.json (for wrapper tools) or stdout.log content.
    status = "running" if running else "completed"

    metadata["status"] = status
    if not running:
        metadata["finished_at"] = utc_now()
    _write_json(metadata_path, metadata)

    payload = {
        "ok": status == "completed",
        "task_id": task_id,
        "status": status,
        "pid": pid,
        "running": running,
        "started_at": metadata.get("started_at"),
        "finished_at": metadata.get("finished_at"),
        "task_dir": str(task_dir),
    }
    if tail_lines:
        payload["stdout_tail"] = stdout_snip
        payload["stderr_tail"] = stderr_snip

    print(json.dumps(payload, indent=2))
    return 0 if status == "completed" else (1 if status == "failed" else 0)


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------

def cmd_wait(args: argparse.Namespace) -> int:
    """Block until the task finishes or *timeout* is reached."""
    task_id = getattr(args, "wait", None) or getattr(args, "task_id")
    task_dir = default_async_dir() / task_id
    metadata_path = task_dir / "task.json"
    if not metadata_path.exists():
        print(json.dumps({
            "ok": False,
            "error": {"type": "task_not_found", "message": f"Task not found: {task_id}"},
        }, indent=2))
        return 2

    metadata = _read_json(metadata_path)
    pid = int(metadata["pid"])
    deadline = time.time() + args.timeout

    while time.time() < deadline:
        if not process_running(pid):
            # Done — print final status
            ns = argparse.Namespace(status=task_id, tail=args.tail)
            return cmd_status(ns)
        time.sleep(args.interval)

    # Timeout reached
    print(json.dumps({
        "ok": False,
        "task_id": task_id,
        "status": "running",
        "error": {"type": "wait_timeout", "message": f"Task still running after {args.timeout}s"},
    }, indent=2))
    return 124


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> int:
    """List all known tasks."""
    root = default_async_dir()
    if not root.exists():
        print(json.dumps({"ok": True, "tasks": []}, indent=2))
        return 0

    tasks = []
    for task_dir in sorted(root.iterdir(), key=lambda p: p.name, reverse=True):
        if not task_dir.is_dir():
            continue
        meta = _read_json(task_dir / "task.json")
        if meta is None:
            continue
        tasks.append({
            "task_id": meta.get("task_id", task_dir.name),
            "status": meta.get("status", "unknown"),
            "pid": meta.get("pid"),
            "started_at": meta.get("started_at"),
            "finished_at": meta.get("finished_at"),
            "command": meta.get("command", ""),
        })

    # Filter by status if requested
    if args.filter_status:
        tasks = [t for t in tasks if t["status"] == args.filter_status]

    # Limit
    if args.limit and len(tasks) > args.limit:
        tasks = tasks[:args.limit]

    print(json.dumps({"ok": True, "count": len(tasks), "tasks": tasks}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------

def cmd_clean(args: argparse.Namespace) -> int:
    """Remove completed/failed task directories, keeping the most recent N."""
    root = default_async_dir()
    if not root.exists():
        print(json.dumps({"ok": True, "removed": 0}, indent=2))
        return 0

    completed = []
    for task_dir in root.iterdir():
        if not task_dir.is_dir():
            continue
        meta = _read_json(task_dir / "task.json")
        if meta is None:
            continue
        status = meta.get("status", "unknown")
        if status in ("completed", "failed"):
            completed.append((meta.get("finished_at", ""), task_dir))

    # Sort by finished_at descending (newest first), keep the last --keep
    completed.sort(key=lambda x: x[0], reverse=True)
    to_remove = completed[args.keep:]
    for _, task_dir in to_remove:
        import shutil
        shutil.rmtree(task_dir, ignore_errors=True)

    print(json.dumps({"ok": True, "removed": len(to_remove), "kept": len(completed) - len(to_remove)}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a long-lived command in the background and poll for completion."
    )
    sub = parser.add_subparsers(dest="action", required=True)

    # start
    p_start = sub.add_parser("start", aliases=["--start"], help="Start a background task")
    p_start.add_argument("--command", "-c", required=True, help="Shell command to run in background.")

    # status
    p_status = sub.add_parser("status", aliases=["--status"], help="Check task status")
    p_status.add_argument("task_id", help="Task id from start.")
    p_status.add_argument("--tail", type=int, default=20, help="Show last N lines of stdout/stderr.")

    # wait
    p_wait = sub.add_parser("wait", aliases=["--wait"], help="Block until task completes")
    p_wait.add_argument("task_id", help="Task id from start.")
    p_wait.add_argument("--timeout", type=int, default=3600, help="Maximum seconds to wait.")
    p_wait.add_argument("--interval", type=float, default=5.0, help="Poll interval in seconds.")
    p_wait.add_argument("--tail", type=int, default=0, help="Show last N lines of output on completion.")

    # list
    p_list = sub.add_parser("list", aliases=["--list"], help="List recent tasks")
    p_list.add_argument("--limit", "-n", type=int, help="Max tasks to show.")
    p_list.add_argument("--filter-status", choices=["running", "completed", "failed"])

    # clean
    p_clean = sub.add_parser("clean", aliases=["--clean"], help="Remove completed tasks")
    p_clean.add_argument("--keep", type=int, default=20, help="Keep the N most recent completed tasks.")

    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    action = args.action

    # Normalise alias names
    if action.startswith("--"):
        action = action[2:]

    handlers = {
        "start": cmd_start,
        "status": cmd_status,
        "wait": cmd_wait,
        "list": cmd_list,
        "clean": cmd_clean,
    }

    handler = handlers.get(action)
    if handler is None:
        print(json.dumps({"ok": False, "error": {"message": f"Unknown action: {action}"}}, indent=2))
        return 2

    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
