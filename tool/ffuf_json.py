#!/usr/bin/env python3
"""
ffuf JSON wrapper for authorized content and parameter discovery.

Examples:
  ./tool/ffuf_json.py --authorized --url https://example.com/FUZZ --wordlist words.txt
  ./tool/ffuf_json.py --authorized --url https://example.com/FUZZ --wordlist words.txt --filter-code 404
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


DEFAULT_TIMEOUT = 1200


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def load_ffuf_output(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_command(args: argparse.Namespace, ffuf_output: Path) -> list[str]:
    command = [
        args.ffuf_binary,
        "-noninteractive",
        "-s",
        "-of",
        "json",
        "-o",
        str(ffuf_output),
        "-u",
        args.url,
        "-w",
        args.wordlist,
        "-rate",
        str(args.rate),
        "-t",
        str(args.threads),
        "-timeout",
        str(args.request_timeout),
    ]
    if args.method:
        command.extend(["-X", args.method])
    if args.data:
        command.extend(["-d", args.data])
    if args.cookie:
        command.extend(["-b", args.cookie])
    if args.extensions:
        command.extend(["-e", args.extensions])
    if args.match_code:
        command.extend(["-mc", args.match_code])
    if args.filter_code:
        command.extend(["-fc", args.filter_code])
    if args.filter_size:
        command.extend(["-fs", args.filter_size])
    if args.filter_words:
        command.extend(["-fw", args.filter_words])
    if args.filter_lines:
        command.extend(["-fl", args.filter_lines])
    if args.auto_calibrate:
        command.append("-ac")
    if args.follow_redirects:
        command.append("-r")
    if args.recursion:
        command.append("-recursion")
        command.extend(["-recursion-depth", str(args.recursion_depth)])
    if args.proxy:
        command.extend(["-x", args.proxy])
    for header in args.header:
        command.extend(["-H", header])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def has_fuzz_keyword(args: argparse.Namespace) -> bool:
    values = [args.url, args.wordlist, args.data or "", args.cookie or ""]
    values.extend(args.header)
    return any("FUZZ" in value for value in values)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ffuf and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--url", required=True, help="Target URL containing FUZZ.")
    parser.add_argument("--wordlist", required=True, help="Wordlist path, optionally with :KEYWORD suffix.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--rate", type=int, default=20, help="Maximum requests per second.")
    parser.add_argument("--threads", type=int, default=10, help="Number of ffuf worker threads.")
    parser.add_argument("--request-timeout", type=int, default=10, help="Per-request timeout in seconds.")
    parser.add_argument("--method", help="HTTP method.")
    parser.add_argument("--data", help="Request body for POST/PUT fuzzing.")
    parser.add_argument("--cookie", help="Cookie header value.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--extensions", help="Comma-separated extensions for FUZZ.")
    parser.add_argument("--match-code", help='Matched status codes, for example "200,204,301" or "all".')
    parser.add_argument("--filter-code", help="Filtered status codes, for example 404,403.")
    parser.add_argument("--filter-size", help="Filtered response sizes.")
    parser.add_argument("--filter-words", help="Filtered word counts.")
    parser.add_argument("--filter-lines", help="Filtered line counts.")
    parser.add_argument("--auto-calibrate", action="store_true", help="Enable ffuf auto-calibration.")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects.")
    parser.add_argument("--recursion", action="store_true", help="Enable recursive discovery.")
    parser.add_argument("--recursion-depth", type=int, default=1, help="Maximum recursion depth.")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw ffuf argument.")
    parser.add_argument("--ffuf-binary", default="ffuf", help="Path to ffuf binary.")
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
    if not has_fuzz_keyword(args):
        emit(
            {
                "ok": False,
                "error": {"type": "missing_fuzz_keyword", "message": "URL or wordlist mapping must contain FUZZ."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2
    if shutil.which(args.ffuf_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"ffuf binary not found: {args.ffuf_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="ffuf-json-") as tmpdir:
        ffuf_output = Path(tmpdir) / "ffuf.json"
        command = build_command(args, ffuf_output)
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
                    "error": {"type": "timeout", "message": f"ffuf exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 124
        try:
            ffuf_json = load_ffuf_output(ffuf_output)
        except json.JSONDecodeError as exc:
            ffuf_json = {}
            parse_error = str(exc)
        else:
            parse_error = None

    payload = {
        "ok": completed.returncode == 0 and parse_error is None,
        "tool": "ffuf",
        "started_at": started_at,
        "finished_at": utc_now(),
        "command": command,
        "returncode": completed.returncode,
        "results": ffuf_json.get("results", []),
        "config": ffuf_json.get("config", {}),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_error", "message": parse_error}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
