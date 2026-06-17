#!/usr/bin/env python3
"""Dalfox JSON wrapper for authorized XSS testing."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 1200


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


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


def build_command(args: argparse.Namespace) -> list[str]:
    mode = "file" if args.input else "url"
    target = args.input if args.input else args.target
    command = [args.dalfox_binary, mode, target, "--format", "json", "--silence", "--worker", str(args.workers)]
    if args.only_discovery:
        command.append("--only-discovery")
    if args.skip_bav:
        command.append("--skip-bav")
    if args.blind:
        command.extend(["--blind", args.blind])
    if args.cookie:
        command.extend(["--cookie", args.cookie])
    for header in args.header:
        command.extend(["--header", header])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run dalfox and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", help="Target URL for dalfox url mode.")
    parser.add_argument("--input", help="File of URLs for dalfox file mode.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--workers", type=int, default=10, help="Dalfox worker count.")
    parser.add_argument("--cookie", help="Cookie header value.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--blind", help="Blind XSS callback URL.")
    parser.add_argument("--only-discovery", action="store_true", help="Only discover reflected parameters.")
    parser.add_argument("--skip-bav", action="store_true", help="Skip BAV checks.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw dalfox argument.")
    parser.add_argument("--dalfox-binary", default="dalfox", help="Path to dalfox binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    if not args.authorized:
        emit({"ok": False, "error": {"type": "authorization_required", "message": "Pass --authorized only after confirming scope."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    if not args.target and not args.input:
        emit({"ok": False, "error": {"type": "missing_target", "message": "Provide --target or --input."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    if shutil.which(args.dalfox_binary) is None:
        emit({"ok": False, "error": {"type": "binary_not_found", "message": f"dalfox binary not found: {args.dalfox_binary}"}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 127

    command = build_command(args)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        emit({"ok": False, "error": {"type": "timeout", "message": f"dalfox exceeded {args.timeout} seconds"}, "command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 124
    records, raw_lines = parse_json_lines(completed.stdout)
    payload = {
        "ok": completed.returncode == 0,
        "tool": "dalfox",
        "started_at": started_at,
        "finished_at": utc_now(),
        "target": args.target,
        "input": args.input,
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
