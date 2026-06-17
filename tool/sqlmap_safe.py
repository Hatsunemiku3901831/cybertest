#!/usr/bin/env python3
"""
Conservative sqlmap wrapper for authorized, low-impact SQL injection checks.

Examples:
  ./tool/sqlmap_safe.py --authorized --url "https://example.com/item?id=1"
  ./tool/sqlmap_safe.py --authorized --request-file request.txt --technique BEUSTQ
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


DEFAULT_TIMEOUT = 1800
BANNED_EXTRA_ARGS = {
    "--dump",
    "--dump-all",
    "--os-shell",
    "--os-pwn",
    "--os-smbrelay",
    "--os-bof",
    "--priv-esc",
    "--sql-shell",
    "--sql-query",
    "--sql-file",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--reg-read",
    "--reg-add",
    "--reg-del",
    "--crawl",
    "--forms",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict, output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def validate_extra_args(extra_args: list[str]) -> str | None:
    for arg in extra_args:
        key = arg.split("=", 1)[0]
        if key in BANNED_EXTRA_ARGS:
            return arg
    return None


def build_command(args: argparse.Namespace, output_dir: Path) -> list[str]:
    command = [
        args.sqlmap_binary,
        "--batch",
        "--risk",
        "1",
        "--level",
        "1",
        "--smart",
        "--disable-coloring",
        "--output-dir",
        str(output_dir),
    ]
    if args.url:
        command.extend(["-u", args.url])
    if args.request_file:
        command.extend(["-r", args.request_file])
    if args.method:
        command.extend(["--method", args.method])
    if args.data:
        command.extend(["--data", args.data])
    if args.cookie:
        command.extend(["--cookie", args.cookie])
    if args.technique:
        command.extend(["--technique", args.technique])
    if args.dbms:
        command.extend(["--dbms", args.dbms])
    if args.param:
        command.extend(["-p", args.param])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    for header in args.header:
        command.extend(["--headers", header])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run sqlmap in a conservative, non-dumping mode.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="Target URL.")
    target.add_argument("--request-file", help="Raw HTTP request file.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--method", help="HTTP method.")
    parser.add_argument("--data", help="Request body.")
    parser.add_argument("--cookie", help="Cookie header value.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--technique", help="Technique mask, for example BEUSTQ.")
    parser.add_argument("--dbms", help="Expected DBMS.")
    parser.add_argument("--param", help="Specific parameter to test.")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw sqlmap argument.")
    parser.add_argument("--sqlmap-binary", default="sqlmap", help="Path to sqlmap binary.")
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

    banned = validate_extra_args(args.extra_arg)
    if banned:
        emit(
            {
                "ok": False,
                "error": {"type": "unsafe_argument", "message": f"sqlmap argument is not allowed: {banned}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if shutil.which(args.sqlmap_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"sqlmap binary not found: {args.sqlmap_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="sqlmap-safe-") as tmpdir:
        output_dir = Path(tmpdir) / "sqlmap-output"
        command = build_command(args, output_dir)
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
                    "error": {"type": "timeout", "message": f"sqlmap exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124

    stdout = completed.stdout
    payload = {
        "ok": completed.returncode == 0,
        "tool": "sqlmap",
        "mode": "safe-check",
        "started_at": started_at,
        "finished_at": utc_now(),
        "command": command,
        "returncode": completed.returncode,
        "injection_indicators": {
            "appears_injectable": "is vulnerable" in stdout or "appears to be" in stdout,
            "dbms_detected": "back-end DBMS" in stdout,
        },
        "stdout": stdout,
        "stderr": completed.stderr,
        "safety": {
            "risk": 1,
            "level": 1,
            "dumping_disabled": True,
            "os_shell_disabled": True,
            "file_read_write_disabled": True,
        },
    }
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
