#!/usr/bin/env python3
"""
Historical URL collector wrapper for authorized attack-surface discovery.

Currently wraps waybackurls and emits normalized JSON.

Examples:
  ./tool/url_history_collect.py --authorized --target example.com
  ./tool/url_history_collect.py --authorized --input hosts.txt --output history.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_TIMEOUT = 900


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.target or [])
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return sorted(dict.fromkeys(normalize_target(item) for item in targets if normalize_target(item)))


def normalize_target(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    return value.split("/")[0]


def parse_urls(stdout: str, source_target: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        url = line.strip()
        if not url or url in seen or "://" not in url:
            continue
        seen.add(url)
        records.append({"url": url, "source": "waybackurls", "target": source_target})
    return records


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect historical URLs and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", action="append", help="Domain/host/URL target. Repeat as needed.")
    parser.add_argument("--input", help="File containing one target per line.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--waybackurls-binary", default="waybackurls", help="Path to waybackurls binary.")
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

    if shutil.which(args.waybackurls_binary) is None:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "binary_not_found",
                    "message": f"waybackurls binary not found: {args.waybackurls_binary}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    all_records: list[dict[str, Any]] = []
    per_target: list[dict[str, Any]] = []
    returncode = 0
    for target in targets:
        command = [args.waybackurls_binary, target]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            per_target.append(
                {
                    "target": target,
                    "ok": False,
                    "error": {"type": "timeout", "message": f"waybackurls exceeded {args.timeout} seconds"},
                    "command": exc.cmd,
                }
            )
            continue
        records = parse_urls(completed.stdout, target)
        all_records.extend(records)
        per_target.append(
            {
                "target": target,
                "ok": completed.returncode == 0,
                "command": command,
                "returncode": completed.returncode,
                "url_count": len(records),
                "stderr": completed.stderr,
            }
        )
        if completed.returncode != 0 and returncode == 0:
            returncode = completed.returncode

    dedup: dict[str, dict[str, Any]] = {}
    for record in all_records:
        dedup.setdefault(record["url"], record)

    payload = {
        "ok": returncode == 0,
        "tool": "waybackurls",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": targets,
        "returncode": returncode,
        "results": sorted(dedup.values(), key=lambda item: item["url"]),
        "per_target": per_target,
    }
    emit(payload, args.output)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
