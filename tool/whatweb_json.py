#!/usr/bin/env python3
"""
whatweb JSON wrapper for authorized web technology fingerprinting.

Identifies CMS, frameworks, server software, analytics, CDN, JavaScript
libraries and other technologies from HTTP responses and page content.

Examples:
  # Single URL
  ./tool/whatweb_json.py --authorized --target https://example.com

  # Aggressive scan with higher timeout
  ./tool/whatweb_json.py --authorized --target https://example.com --aggression 3

  # Multiple targets from file
  ./tool/whatweb_json.py --authorized --target https://example.com --target https://api.example.com

  # Output to file
  ./tool/whatweb_json.py --authorized --target https://example.com --output whatweb.json
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

DEFAULT_TIMEOUT = 300
DEFAULT_AGGRESSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_whatweb_json(stdout: str) -> list[dict[str, Any]]:
    """Parse whatweb JSON-lines output into a list of result objects."""
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            results.append({"_parse_error": True, "_raw": line})
            continue
        results.append(obj)
    return results


def flatten_plugins(plugins: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert whatweb plugin dict to a sorted list for readability."""
    flat: list[dict[str, Any]] = []
    for name, info in plugins.items():
        entry: dict[str, Any] = {"plugin": name}
        if isinstance(info, dict):
            entry.update(info)
        else:
            entry["value"] = info
        flat.append(entry)
    flat.sort(key=lambda x: x.get("plugin", ""))
    return flat


def build_summary(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract key fields from raw whatweb results into a digestible summary."""
    summary: list[dict[str, Any]] = []
    for entry in results:
        if entry.get("_parse_error"):
            summary.append(entry)
            continue
        plugins_flat = flatten_plugins(entry.get("plugins", {}))
        all_tech = [p["plugin"] for p in plugins_flat if not p.get("_parse_error")]
        summary.append(
            {
                "target": entry.get("target"),
                "http_status": entry.get("http_status"),
                "title": entry.get("title"),
                "ip": entry.get("ip"),
                "technologies": all_tech,
                "plugins_detailed": plugins_flat,
                "request_duration_ms": entry.get("request_duration_ms"),
            }
        )
    return summary


def build_command(args: argparse.Namespace) -> list[str]:
    command = [
        args.whatweb_binary,
        "--color=never",
        "--log-json",
        "-",
        "--no-errors",
    ]
    # Aggression level: 1 (passive) to 4 (heavy)
    if args.aggression:
        command.extend(["--aggression", str(args.aggression)])
    if args.max_redirects is not None:
        command.extend(["--max-redirects", str(args.max_redirects)])
    if args.user_agent:
        command.extend(["--user-agent", args.user_agent])
    if args.header:
        for header in args.header:
            command.extend(["--header", header])
    if args.plugin:
        for plugin in args.plugin:
            command.extend(["--plugin", plugin])
    if args.custom_plugin:
        for path in args.custom_plugin:
            command.extend(["--custom-plugin", path])
    if args.proxy:
        command.extend(["--proxy", args.proxy])
    if args.no_follow_redirect:
        command.append("--no-redirect")
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    # Targets come last
    command.extend(args.target)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run whatweb and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", required=True, action="append", help="Target URL(s). Repeat for multiple targets.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--aggression", type=int, choices=[1, 2, 3, 4], default=DEFAULT_AGGRESSION,
                        help="Aggression level: 1 (passive)-4 (heavy). Default: %(default)s")
    parser.add_argument("--max-redirects", type=int, default=10, help="Maximum redirects to follow. Default: %(default)s")
    parser.add_argument("--user-agent", help="Custom User-Agent string.")
    parser.add_argument("--header", action="append", default=[], help="Custom HTTP header (repeatable).")
    parser.add_argument("--plugin", action="append", default=[], help="Limit to specific plugin(s).")
    parser.add_argument("--custom-plugin", action="append", default=[], help="Path to custom plugin(s).")
    parser.add_argument("--no-follow-redirect", action="store_true", help="Do not follow redirects.")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080).")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw whatweb argument.")
    parser.add_argument("--whatweb-binary", default="whatweb", help="Path to whatweb binary.")
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

    if shutil.which(args.whatweb_binary) is None:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "binary_not_found",
                    "message": f"whatweb binary not found: {args.whatweb_binary}. Install with: brew install whatweb",
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
                "error": {"type": "timeout", "message": f"whatweb exceeded {args.timeout} seconds"},
                "command": exc.cmd,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 124

    raw_results = parse_whatweb_json(completed.stdout)
    summary = build_summary(raw_results)
    parse_errors = [r for r in raw_results if r.get("_parse_error")]

    payload = {
        "ok": completed.returncode == 0 and len(parse_errors) == 0,
        "tool": "whatweb",
        "started_at": started_at,
        "finished_at": utc_now(),
        "targets": args.target,
        "aggression": args.aggression,
        "command": command,
        "returncode": completed.returncode,
        "total_targets_scanned": len(args.target),
        "total_technologies_found": sum(len(h.get("technologies", [])) for h in summary),
        "hosts": summary,
        "stdout": completed.stdout if len(parse_errors) > 0 else "",
        "stderr": completed.stderr,
    }
    if parse_errors:
        payload["error"] = {"type": "json_parse_warning", "message": f"{len(parse_errors)} lines could not be parsed as JSON."}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
