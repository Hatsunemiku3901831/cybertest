#!/usr/bin/env python3
"""
ProjectDiscovery dnsx JSON wrapper for authorized DNS baseline collection.

Examples:
  ./tool/dnsx_json.py --authorized --target example.com
  ./tool/dnsx_json.py --authorized --input subdomains.txt --resolver 1.1.1.1 --output dnsx.json
"""

from __future__ import annotations

import argparse
import ipaddress
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
            records.append(enrich_record(value))
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
        args.dnsx_binary,
        "-json",
        "-silent",
        "-l",
        str(input_path),
        "-a",
        "-aaaa",
        "-cname",
        "-ns",
        "-resp",
    ]
    for resolver in args.resolver:
        command.extend(["-resolver", resolver])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def ip_flags(values: list[str]) -> dict[str, bool]:
    private_ip = False
    fake_ip = False
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            private_ip = True
        if ip.version == 4 and ipaddress.ip_address("198.18.0.0") <= ip <= ipaddress.ip_address("198.19.255.255"):
            fake_ip = True
    return {"private_ip": private_ip, "fake_ip": fake_ip}


def values_from_record(record: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    return values


def enrich_record(record: dict[str, Any]) -> dict[str, Any]:
    ips = values_from_record(record, ("a", "aaaa", "host", "resolver"))
    record["codex_dns_flags"] = ip_flags(ips)
    return record


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run dnsx and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="Domain/host target. Repeat as needed.")
    parser.add_argument("--input", help="File containing one domain/host per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--resolver", action="append", default=[], help="Resolver IP or resolver file supported by dnsx.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw dnsx argument.")
    parser.add_argument("--tool-home", help="Optional HOME directory for wrapped dnsx.")
    parser.add_argument("--dnsx-binary", default="dnsx", help="Path to dnsx binary.")
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

    if shutil.which(args.dnsx_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"dnsx binary not found: {args.dnsx_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    with tempfile.TemporaryDirectory(prefix="dnsx-json-") as tmpdir:
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
                    "error": {"type": "timeout", "message": f"dnsx exceeded {args.timeout} seconds"},
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
        "tool": "dnsx",
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
