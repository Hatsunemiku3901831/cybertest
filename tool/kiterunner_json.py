#!/usr/bin/env python3
"""Kiterunner JSON wrapper for authorized API route discovery."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 1800


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


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def build_command(args: argparse.Namespace, targets: list[str]) -> list[str]:
    command = [args.kiterunner_binary, "scan"]
    command.extend(targets)
    command.extend(["-w", args.wordlist, "-x", str(args.concurrency), "-o", "json"])
    if args.fail_status_codes:
        command.extend(["--fail-status-codes", args.fail_status_codes])
    if args.quiet:
        command.append("-q")
    for header in args.header:
        command.extend(["-H", header])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Kiterunner and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="Base URL target. Repeat for multiple targets.")
    parser.add_argument("--input", help="File containing one base URL per line.")
    parser.add_argument("--wordlist", required=True, help="Kiterunner .kite wordlist or route wordlist.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--concurrency", type=int, default=20, help="Kiterunner concurrency.")
    parser.add_argument("--fail-status-codes", default="400,401,404,405,501,502,503,504", help="Status codes treated as misses.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--quiet", action="store_true", help="Pass -q to kiterunner.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw Kiterunner argument.")
    parser.add_argument("--kiterunner-binary", default="kr", help="Path to kr binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    if not args.authorized:
        emit({"ok": False, "error": {"type": "authorization_required", "message": "Pass --authorized only after confirming scope."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    targets = load_targets(args)
    if not targets:
        emit({"ok": False, "error": {"type": "missing_targets", "message": "Provide --target or --input."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    if shutil.which(args.kiterunner_binary) is None:
        emit({"ok": False, "error": {"type": "binary_not_found", "message": f"kiterunner binary not found: {args.kiterunner_binary}"}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 127

    command = build_command(args, targets)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        emit({"ok": False, "error": {"type": "timeout", "message": f"kiterunner exceeded {args.timeout} seconds"}, "command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 124

    records, raw_lines = parse_json_lines(completed.stdout)
    payload = {
        "ok": completed.returncode == 0,
        "tool": "kiterunner",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": targets,
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
