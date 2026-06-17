#!/usr/bin/env python3
"""Gitleaks JSON wrapper for secret discovery with redacted output."""

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


DEFAULT_TIMEOUT = 1200
SECRET_KEYS = {"secret", "match", "line", "offender"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if key.lower() in SECRET_KEYS else redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def build_command(args: argparse.Namespace, report_path: Path) -> list[str]:
    command = [
        args.gitleaks_binary,
        "detect",
        "--source",
        args.source,
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-banner",
    ]
    if args.redact:
        command.append("--redact")
    if args.no_git:
        command.append("--no-git")
    if args.config:
        command.extend(["--config", args.config])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run gitleaks and emit normalized JSON.")
    parser.add_argument("--source", default=".", help="Source directory or repository to scan.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--config", help="Optional gitleaks config path.")
    parser.add_argument("--no-git", action="store_true", help="Scan files without git history.")
    parser.add_argument("--redact", action="store_true", default=True, help="Pass --redact and also redact normalized output.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw gitleaks argument.")
    parser.add_argument("--gitleaks-binary", default="gitleaks", help="Path to gitleaks binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    if shutil.which(args.gitleaks_binary) is None:
        emit({"ok": False, "error": {"type": "binary_not_found", "message": f"gitleaks binary not found: {args.gitleaks_binary}"}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 127

    with tempfile.TemporaryDirectory(prefix="gitleaks-json-") as tmpdir:
        report_path = Path(tmpdir) / "gitleaks.json"
        command = build_command(args, report_path)
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=args.timeout)
        except subprocess.TimeoutExpired as exc:
            emit({"ok": False, "error": {"type": "timeout", "message": f"gitleaks exceeded {args.timeout} seconds"}, "command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
            return 124
        if report_path.exists() and report_path.stat().st_size > 0:
            try:
                findings: Any = json.loads(report_path.read_text(encoding="utf-8"))
                parse_error = None
            except json.JSONDecodeError as exc:
                findings = []
                parse_error = str(exc)
        else:
            findings = []
            parse_error = None

    payload = {
        "ok": completed.returncode in {0, 1} and parse_error is None,
        "tool": "gitleaks",
        "started_at": started_at,
        "finished_at": utc_now(),
        "source": args.source,
        "command": command,
        "returncode": completed.returncode,
        "results": redact(findings),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
