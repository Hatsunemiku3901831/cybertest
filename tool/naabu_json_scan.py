#!/usr/bin/env python3
"""
ProjectDiscovery naabu JSON wrapper for authorized fast port discovery.

Examples:
  ./tool/naabu_json_scan.py --authorized --target example.com --ports 1-65535
  ./tool/naabu_json_scan.py --authorized --input hosts.txt --output naabu.json
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
    return sorted(dict.fromkeys(targets))


def build_env(tool_home: str | None) -> dict[str, str] | None:
    if not tool_home:
        return None
    Path(tool_home).mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = tool_home
    return env


def build_command(args: argparse.Namespace, input_path: Path) -> list[str]:
    command = [
        args.naabu_binary,
        "-json",
        "-silent",
        "-list",
        str(input_path),
        "-p",
        args.ports,
        "-rate",
        str(args.rate),
    ]
    if args.exclude_cdn:
        command.append("-exclude-cdn")
    if args.verify:
        command.append("-verify")
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run naabu and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="Host/IP target. Repeat as needed.")
    parser.add_argument("--input", help="File containing one target per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--ports", default="1-65535", help="Ports to scan, for example 80,443 or 1-65535.")
    parser.add_argument("--rate", type=int, default=1000, help="Maximum packets per second.")
    parser.add_argument("--exclude-cdn", action="store_true", help="Ask naabu to exclude CDN/WAF targets where supported.")
    parser.add_argument("--verify", action="store_true", help="Enable naabu result verification where supported.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw naabu argument.")
    parser.add_argument("--tool-home", help="Optional HOME directory for wrapped naabu.")
    parser.add_argument("--naabu-binary", default="naabu", help="Path to naabu binary.")
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

    if shutil.which(args.naabu_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"naabu binary not found: {args.naabu_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="naabu-json-") as tmpdir:
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
                    "error": {"type": "timeout", "message": f"naabu exceeded {args.timeout} seconds"},
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
        "tool": "naabu",
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
