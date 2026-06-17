#!/usr/bin/env python3
"""
ProjectDiscovery httpx JSON wrapper for authorized web probing.

Examples:
  ./tool/httpx_probe.py --authorized --target https://example.com
  ./tool/httpx_probe.py --authorized --input urls.txt --output httpx.json
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


DEFAULT_TIMEOUT = 600


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


def build_command(args: argparse.Namespace, input_path: Path) -> list[str]:
    command = [
        args.httpx_binary,
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-length",
        "-location",
        "-follow-redirects",
        "-list",
        str(input_path),
    ]
    if args.include_response_header:
        command.append("-include-response-header")
    if args.ports:
        command.extend(["-ports", args.ports])
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
    parser = argparse.ArgumentParser(description="Run httpx and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="URL, host, or CIDR target. Repeat as needed.")
    parser.add_argument("--input", help="File containing one URL/host per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--ports", help="Optional httpx port list, for example 80,443,8080.")
    parser.add_argument(
        "--include-response-header",
        action="store_true",
        help="Include response headers in httpx JSON output.",
    )
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw httpx argument.")
    parser.add_argument("--tool-home", help="Optional HOME directory for the wrapped httpx process.")
    parser.add_argument("--httpx-binary", default="httpx", help="Path to httpx binary.")
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

    if shutil.which(args.httpx_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"httpx binary not found: {args.httpx_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="httpx-probe-") as tmpdir:
        input_path = Path(tmpdir) / "targets.txt"
        input_path.write_text("\n".join(targets) + "\n", encoding="utf-8")
        command = build_command(args, input_path)
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
                    "error": {"type": "timeout", "message": f"httpx exceeded {args.timeout} seconds"},
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
        "tool": "httpx",
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
