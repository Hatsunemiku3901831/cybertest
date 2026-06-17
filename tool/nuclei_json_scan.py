#!/usr/bin/env python3
"""
ProjectDiscovery nuclei JSONL wrapper for authorized template-based scanning.

Examples:
  ./tool/nuclei_json_scan.py --authorized --target https://example.com
  ./tool/nuclei_json_scan.py --authorized --input urls.txt --severity high,critical --output nuclei.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Shared async utilities (--async-start / --async-status)
from _async_utils import add_async_args, async_start, async_status


DEFAULT_TIMEOUT = 1800
DEFAULT_SEVERITY = "medium,high,critical"
DEFAULT_TOOL_HOME = "/tmp/codex-projectdiscovery-home"
DEFAULT_LOCAL_TEMPLATES = Path(__file__).resolve().parent / "nuclei-templates"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_json_lines(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    raw_lines: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raw_lines.append(line)
            continue
        if isinstance(value, dict):
            records.append(value)
        else:
            raw_lines.append(line)
    return records, raw_lines


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def has_templates(path: Path) -> bool:
    if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
        return True
    if not path.is_dir():
        return False
    return any(child.suffix.lower() in {".yaml", ".yml"} for child in path.rglob("*"))


def collect_template_paths(args: argparse.Namespace) -> list[str]:
    template_paths: list[str] = []
    if args.templates:
        template_paths.append(args.templates)
    if not args.no_local_templates and has_templates(DEFAULT_LOCAL_TEMPLATES):
        template_paths.append(str(DEFAULT_LOCAL_TEMPLATES))
    return template_paths


def build_command(args: argparse.Namespace, targets: list[str], input_path: Path | None) -> list[str]:
    command = [
        args.nuclei_binary,
        "-jsonl",
        "-silent",
        "-no-color",
        "-severity",
        args.severity,
    ]
    if len(targets) == 1:
        command.extend(["-u", targets[0]])
    else:
        command.extend(["-l", str(input_path)])
    for template_path in collect_template_paths(args):
        command.extend(["-templates", template_path])
    if args.tags:
        command.extend(["-tags", args.tags])
    if args.rate_limit:
        command.extend(["-rate-limit", str(args.rate_limit)])
    if args.disable_update_check:
        command.append("-duc")
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def build_env(tool_home: str | None) -> dict[str, str] | None:
    if not tool_home:
        return None
    Path(tool_home).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = tool_home
    return env


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run nuclei and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="URL/host target. Repeat for multiple targets.")
    parser.add_argument("--input", help="File containing one target per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--severity", default=DEFAULT_SEVERITY, help="Comma-separated severities.")
    parser.add_argument("--templates", help="Template path or directory.")
    parser.add_argument(
        "--no-local-templates",
        action="store_true",
        help="Do not add tool/nuclei-templates local high-signal templates.",
    )
    parser.add_argument("--tags", help="Comma-separated nuclei tags.")
    parser.add_argument("--rate-limit", type=int, help="Optional nuclei request rate limit.")
    parser.add_argument("--disable-update-check", action="store_true", help="Disable nuclei update check.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw nuclei argument.")
    parser.add_argument(
        "--tool-home",
        default=DEFAULT_TOOL_HOME,
        help="HOME directory for the wrapped nuclei process.",
    )
    parser.add_argument("--nuclei-binary", default="nuclei", help="Path to nuclei binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    add_async_args(parser, "nuclei")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    # Async task status check (no authorization needed to poll)
    if args.async_status:
        return async_status(args, started_at)

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the targets are in scope.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    targets = load_targets(args)
    if not targets:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_targets", "message": "Provide --target or --input."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if shutil.which(args.nuclei_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"nuclei binary not found: {args.nuclei_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    if args.async_start:
        return async_start(args, argv, "nuclei", started_at)

    with tempfile.TemporaryDirectory(prefix="nuclei-json-") as tmpdir:
        input_path = None
        if len(targets) > 1:
            input_path = Path(tmpdir) / "targets.txt"
            input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command = build_command(args, targets, input_path)
        env = build_env(args.tool_home)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            emit(
                {
                    "ok": False,
                    "error": {"type": "timeout", "message": f"nuclei exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124

    records, raw_lines = parse_json_lines(completed.stdout)
    payload = {
        "ok": completed.returncode == 0,
        "tool": "nuclei",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": targets,
        "severity": args.severity,
        "local_templates": None if args.no_local_templates else str(DEFAULT_LOCAL_TEMPLATES),
        "command": command,
        "returncode": completed.returncode,
        "results": records,
        "raw_stdout_lines": raw_lines,
        "stderr": completed.stderr,
    }
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
