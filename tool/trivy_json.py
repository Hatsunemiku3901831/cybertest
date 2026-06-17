#!/usr/bin/env python3
"""
Trivy JSON wrapper for filesystem, image, repository, and config scanning.

Examples:
  ./tool/trivy_json.py --mode fs --target .
  ./tool/trivy_json.py --mode image --target nginx:latest --severity HIGH,CRITICAL
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


def build_command(args: argparse.Namespace, trivy_output: Path) -> list[str]:
    command = [
        args.trivy_binary,
        args.mode,
        "--format",
        "json",
        "--output",
        str(trivy_output),
        "--severity",
        args.severity,
    ]
    if args.scanners:
        command.extend(["--scanners", args.scanners])
    if args.ignore_unfixed:
        command.append("--ignore-unfixed")
    if args.skip_db_update:
        command.append("--skip-db-update")
    if args.skip_java_db_update:
        command.append("--skip-java-db-update")
    if args.no_progress:
        command.append("--no-progress")
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    command.append(args.target)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Trivy and emit normalized JSON.")
    parser.add_argument("--mode", choices=["fs", "image", "repo", "config", "rootfs"], default="fs")
    parser.add_argument("--target", default=".", help="Scan target path, image, or repository.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--severity", default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", help="Comma-separated severities.")
    parser.add_argument("--scanners", help="Comma-separated scanners, for example vuln,secret,misconfig,license.")
    parser.add_argument("--ignore-unfixed", action="store_true", help="Ignore unfixed vulnerabilities.")
    parser.add_argument("--skip-db-update", action="store_true", help="Do not update vulnerability DB.")
    parser.add_argument("--skip-java-db-update", action="store_true", help="Do not update Java vulnerability DB.")
    parser.add_argument("--no-progress", action="store_true", default=True, help="Disable progress output.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw trivy argument.")
    parser.add_argument("--trivy-binary", default="trivy", help="Path to trivy binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if shutil.which(args.trivy_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"trivy binary not found: {args.trivy_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="trivy-json-") as tmpdir:
        trivy_output = Path(tmpdir) / "trivy.json"
        command = build_command(args, trivy_output)
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
                    "error": {"type": "timeout", "message": f"trivy exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124
        if trivy_output.exists() and trivy_output.stat().st_size > 0:
            try:
                trivy_json: dict[str, Any] = json.loads(trivy_output.read_text(encoding="utf-8"))
                parse_error = None
            except json.JSONDecodeError as exc:
                trivy_json = {}
                parse_error = str(exc)
        else:
            trivy_json = {}
            parse_error = "trivy did not produce JSON output"

    payload = {
        "ok": completed.returncode == 0 and parse_error is None,
        "tool": "trivy",
        "started_at": started_at,
        "finished_at": utc_now(),
        "mode": args.mode,
        "target": args.target,
        "command": command,
        "returncode": completed.returncode,
        "result": trivy_json,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
