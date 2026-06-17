#!/usr/bin/env python3
"""
ProjectDiscovery subfinder JSON wrapper for authorized passive subdomain enumeration.

Examples:
  ./tool/subfinder_json.py --authorized --domain example.com
  ./tool/subfinder_json.py --authorized --domain example.com --all --recursive --output subdomains.json
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


DEFAULT_TIMEOUT = 900


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


def load_domains(args: argparse.Namespace) -> list[str]:
    domains = list(args.domain or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


def build_command(args: argparse.Namespace, domains: list[str], input_path: Path | None) -> list[str]:
    command = [args.subfinder_binary, "-json", "-silent"]
    if len(domains) == 1:
        command.extend(["-d", domains[0]])
    else:
        command.extend(["-dL", str(input_path)])
    if args.all:
        command.append("-all")
    if args.recursive:
        command.append("-recursive")
    if args.collect_sources:
        command.append("-cs")
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
    parser = argparse.ArgumentParser(description="Run subfinder and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--domain", action="append", help="Root domain. Repeat for multiple domains.")
    parser.add_argument("--input", help="File containing one root domain per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--all", action="store_true", help="Use all configured subfinder sources.")
    parser.add_argument("--recursive", action="store_true", help="Use recursive sources.")
    parser.add_argument("--collect-sources", action="store_true", help="Include source data when supported.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw subfinder argument.")
    parser.add_argument("--tool-home", help="Optional HOME directory for the wrapped subfinder process.")
    parser.add_argument("--subfinder-binary", default="subfinder", help="Path to subfinder binary.")
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
                    "message": "Pass --authorized only after confirming the domains are in scope.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    domains = load_domains(args)
    if not domains:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_domains", "message": "Provide --domain or --input."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if shutil.which(args.subfinder_binary) is None:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "binary_not_found",
                    "message": f"subfinder binary not found: {args.subfinder_binary}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="subfinder-json-") as tmpdir:
        input_path = None
        if len(domains) > 1:
            input_path = Path(tmpdir) / "domains.txt"
            input_path.write_text("\n".join(domains) + "\n", encoding="utf-8")
        command = build_command(args, domains, input_path)
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
                    "error": {"type": "timeout", "message": f"subfinder exceeded {args.timeout} seconds"},
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
        "tool": "subfinder",
        "started_at": started_at,
        "finished_at": utc_now(),
        "domains": domains,
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
