#!/usr/bin/env python3
"""
OWASP ZAP baseline JSON wrapper for authorized web baseline scanning.

Examples:
  ./tool/zap_baseline.py --authorized --target https://example.com --output zap.json
  ./tool/zap_baseline.py --authorized --target https://example.com --minutes 2 --ajax
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


def build_command(args: argparse.Namespace, report_name: str, workdir: Path) -> list[str]:
    if args.docker:
        return [
            args.docker_binary,
            "run",
            "--rm",
            "-v",
            f"{workdir}:/zap/wrk",
            args.zap_image,
            "zap-baseline.py",
            "-t",
            args.target,
            "-J",
            report_name,
            "-m",
            str(args.minutes),
        ] + optional_flags(args)
    return [
        args.zap_binary,
        "-t",
        args.target,
        "-J",
        str(workdir / report_name),
        "-m",
        str(args.minutes),
    ] + optional_flags(args)


def optional_flags(args: argparse.Namespace) -> list[str]:
    flags: list[str] = []
    if args.ajax:
        flags.append("-j")
    if args.alpha:
        flags.append("-a")
    if args.config:
        flags.extend(["-c", args.config])
    for extra_arg in args.extra_arg:
        flags.append(extra_arg)
    return flags


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OWASP ZAP baseline and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", required=True, help="Target URL.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--minutes", type=int, default=1, help="Spider duration in minutes.")
    parser.add_argument("--ajax", action="store_true", help="Use Ajax spider.")
    parser.add_argument("--alpha", action="store_true", help="Include alpha passive scan rules.")
    parser.add_argument("--config", help="ZAP baseline config file.")
    parser.add_argument("--docker", action="store_true", help="Run via Docker instead of local zap-baseline.py.")
    parser.add_argument("--zap-image", default="ghcr.io/zaproxy/zaproxy:stable", help="Docker image for ZAP.")
    parser.add_argument("--docker-binary", default="docker", help="Path to docker binary.")
    parser.add_argument("--zap-binary", default="zap-baseline.py", help="Path to zap-baseline.py.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw ZAP baseline argument.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the target is in scope.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    binary = args.docker_binary if args.docker else args.zap_binary
    if shutil.which(binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"required binary not found: {binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="zap-baseline-") as tmpdir:
        workdir = Path(tmpdir)
        report_name = "zap-report.json"
        report_path = workdir / report_name
        command = build_command(args, report_name, workdir)
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
                    "error": {"type": "timeout", "message": f"ZAP baseline exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124
        if report_path.exists() and report_path.stat().st_size > 0:
            try:
                zap_json: dict[str, Any] = json.loads(report_path.read_text(encoding="utf-8"))
                parse_error = None
            except json.JSONDecodeError as exc:
                zap_json = {}
                parse_error = str(exc)
        else:
            zap_json = {}
            parse_error = "ZAP did not produce JSON report"

    payload = {
        "ok": completed.returncode in {0, 1, 2} and parse_error is None,
        "tool": "zap-baseline",
        "started_at": started_at,
        "finished_at": utc_now(),
        "target": args.target,
        "command": command,
        "returncode": completed.returncode,
        "result": zap_json,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
