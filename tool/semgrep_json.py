#!/usr/bin/env python3
"""
Semgrep JSON wrapper for source-code scanning.

Examples:
  ./tool/semgrep_json.py --target .
  ./tool/semgrep_json.py --target backend --config p/security-audit --output semgrep.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
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


def build_command(args: argparse.Namespace, semgrep_output: Path) -> list[str]:
    command = [
        args.semgrep_binary,
        "scan",
        "--json",
        "--output",
        str(semgrep_output),
        "--timeout",
        str(args.rule_timeout),
    ]
    for config in args.config:
        command.extend(["--config", config])
    if args.error:
        command.append("--error")
    if args.metrics_off:
        command.append("--metrics=off")
    for exclude in args.exclude:
        command.extend(["--exclude", exclude])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    command.append(args.target)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Semgrep and emit normalized JSON.")
    parser.add_argument("--target", default=".", help="File or directory to scan.")
    parser.add_argument("--config", action="append", default=["auto"], help="Semgrep config. Repeat as needed.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude path pattern.")
    parser.add_argument("--error", action="store_true", help="Return non-zero when findings are present.")
    parser.add_argument("--metrics-off", action="store_true", default=True, help="Disable Semgrep metrics.")
    parser.add_argument("--rule-timeout", type=int, default=30, help="Per-rule timeout in seconds.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw semgrep argument.")
    parser.add_argument("--semgrep-binary", default="semgrep", help="Path to semgrep binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if shutil.which(args.semgrep_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"semgrep binary not found: {args.semgrep_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="semgrep-json-") as tmpdir:
        semgrep_output = Path(tmpdir) / "semgrep.json"
        command = build_command(args, semgrep_output)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            emit(
                {
                    "ok": False,
                    "error": {"type": "timeout", "message": f"semgrep exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124
        if semgrep_output.exists() and semgrep_output.stat().st_size > 0:
            try:
                semgrep_json: dict[str, Any] = json.loads(semgrep_output.read_text(encoding="utf-8"))
                parse_error = None
            except json.JSONDecodeError as exc:
                semgrep_json = {}
                parse_error = str(exc)
        else:
            semgrep_json = {}
            parse_error = "semgrep did not produce JSON output"

    payload = {
        "ok": completed.returncode in {0, 1} and parse_error is None,
        "tool": "semgrep",
        "started_at": started_at,
        "finished_at": utc_now(),
        "target": args.target,
        "configs": args.config,
        "command": command,
        "returncode": completed.returncode,
        "result": semgrep_json,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
