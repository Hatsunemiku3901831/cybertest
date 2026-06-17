#!/usr/bin/env python3
"""
wafw00f JSON wrapper for authorized Web Application Firewall detection.

Identifies WAF/CDN/security proxy products in front of web targets.
Critical for distinguishing WAF behavior from real application behavior,
planning bypass strategies, and correctly attributing scan results.

Supports single URL, multiple URLs, and input-file modes.

Examples:
  # Single URL detection
  ./tool/wafw00f_json.py --authorized --target https://example.com

  # Find all matching WAFs (don't stop at first match)
  ./tool/wafw00f_json.py --authorized --target https://example.com --findall

  # Multiple targets
  ./tool/wafw00f_json.py --authorized --target https://example.com --target https://api.example.com

  # Through Burp proxy
  ./tool/wafw00f_json.py --authorized --target https://example.com --proxy http://127.0.0.1:8080
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

DEFAULT_TIMEOUT = 120


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_wafw00f_json(stdout: str) -> list[dict[str, Any]]:
    """Parse wafw00f JSON array output into a list."""
    if not stdout.strip():
        return []
    try:
        results = json.loads(stdout)
        if isinstance(results, list):
            return results
        # Unexpected format — wrap as single result
        return [{"_parse_error": True, "_raw": str(results)[:500]}]
    except json.JSONDecodeError:
        return [{"_parse_error": True, "_raw": stdout[:500]}]


def build_summary(raw_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a compact summary from wafw00f results.

    With --findall, wafw00f may emit multiple entries per URL (one per
    detected WAF, plus a trailing 'None' entry).  This function merges
    entries by URL, keeping the best WAF hit per target.
    """
    # Merge by URL: keep the first positive detection, or fall back to the first negative
    merged: dict[str, dict[str, Any]] = {}
    for entry in raw_results:
        if entry.get("_parse_error"):
            continue
        url = entry.get("url", "unknown")
        if url not in merged:
            merged[url] = entry
        elif merged[url].get("detected"):
            # Already have a positive hit — skip duplicates
            continue
        elif entry.get("detected"):
            # Replace negative with positive
            merged[url] = entry

    targets_total = len(merged)
    waf_names: list[str] = []
    clean_targets: list[str] = []
    hosts: list[dict[str, Any]] = []

    for url, entry in merged.items():
        detected = entry.get("detected", False)
        firewall = entry.get("firewall")
        manufacturer = entry.get("manufacturer")

        if detected and firewall:
            if firewall not in waf_names:
                waf_names.append(firewall)
        else:
            clean_targets.append(url)

        hosts.append(
            {
                "url": url,
                "waf_detected": detected,
                "waf_name": firewall,
                "waf_manufacturer": manufacturer,
            }
        )

    # Also include parse errors
    for entry in raw_results:
        if entry.get("_parse_error"):
            hosts.append(entry)

    return {
        "total_targets": targets_total,
        "targets_with_waf": targets_total - len(clean_targets),
        "targets_clean": len(clean_targets),
        "waf_names": sorted(waf_names),
        "clean_targets": clean_targets,
        "hosts": hosts,
    }


def build_command(args: argparse.Namespace) -> list[str]:
    command = [
        args.wafw00f_binary,
        "-f", "json",
        "-o", "-",
    ]
    if args.findall:
        command.append("-a")
    if args.noredirect:
        command.append("-r")
    if args.test:
        command.extend(["-t", args.test])
    if args.proxy:
        command.extend(["-p", args.proxy])
    if args.timeout_seconds:
        command.extend(["-T", str(args.timeout_seconds)])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    # Targets — wafw00f takes URLs as positional arguments
    if args.input_file:
        command.extend(["-i", args.input_file])
    command.extend(args.target)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run wafw00f and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", required=True, action="append", help="Target URL(s). Repeat for multiple targets.")
    parser.add_argument("--input-file", "-i", help="Read targets from a file (csv, json, or text).")
    parser.add_argument("--output", "-o", help="Optional normalized JSON output file.")
    parser.add_argument("--findall", "-a", action="store_true", help="Find all matching WAFs, not just the first.")
    parser.add_argument("--noredirect", "-r", action="store_true", help="Do not follow 3xx redirects.")
    parser.add_argument("--test", "-t", help="Test for a specific WAF by name.")
    parser.add_argument("--proxy", "-p", help="HTTP proxy (e.g. http://127.0.0.1:8080).")
    parser.add_argument("--timeout-seconds", "-T", type=int, help="Per-request timeout in seconds.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw wafw00f argument.")
    parser.add_argument("--wafw00f-binary", default="wafw00f", help="Path to wafw00f binary.")
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

    if shutil.which(args.wafw00f_binary) is None:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "binary_not_found",
                    "message": f"wafw00f binary not found: {args.wafw00f_binary}. Install with: brew install wafw00f",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    command = build_command(args)
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
                "error": {
                    "type": "timeout",
                    "message": f"wafw00f exceeded {args.timeout} seconds",
                },
                "command": exc.cmd,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 124

    raw_results = parse_wafw00f_json(completed.stdout)
    summary = build_summary(raw_results)
    parse_errors = [r for r in raw_results if r.get("_parse_error")]

    payload = {
        "ok": completed.returncode == 0 and len(parse_errors) == 0,
        "tool": "wafw00f",
        "started_at": started_at,
        "finished_at": utc_now(),
        "command": command,
        "returncode": completed.returncode,
        "total_targets": summary["total_targets"],
        "targets_with_waf": summary["targets_with_waf"],
        "targets_clean": summary["targets_clean"],
        "waf_names": summary["waf_names"],
        "hosts": summary["hosts"],
        "stderr": completed.stderr if completed.stderr else "",
    }
    if parse_errors:
        payload["ok"] = False
        payload["error"] = {
            "type": "json_parse_warning",
            "message": f"{len(parse_errors)} results could not be parsed.",
        }
    emit(payload, args.output)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
