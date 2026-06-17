#!/usr/bin/env python3
"""
masscan JSON wrapper for authorized high-speed port discovery.

masscan performs asynchronous stateless port scanning, orders of magnitude
faster than nmap for large ranges (/16+).  It requires root / sudo on macOS
to send raw packets.

Examples:
  # Single host, common web ports
  sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.10 -p 80,443,8080,8443

  # Full port range on a single host
  sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.10 -p 1-65535 --rate 5000

  # Sweep a /24 for port 443
  sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.0/24 -p 443 --rate 10000

  # Output to file
  sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.0/24 -p 80,443 -o masscan.json
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

DEFAULT_RATE = 2000
DEFAULT_WAIT = 10
DEFAULT_TIMEOUT = 3600

# Shared async utilities (--async-start / --async-status)
from _async_utils import add_async_args, async_start, async_status


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_masscan_json(stdout: str) -> list[dict[str, Any]]:
    """Parse masscan JSON-lines output into a list of result objects."""
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # masscan may emit status lines like "[rate] ..." to stderr,
            # but JSON parsing failures in stdout are worth keeping.
            results.append({"_parse_error": True, "_raw": line})
            continue
        # Only keep finished results (ignore banner/open/closed intermediate entries)
        if "ports" in obj:
            results.append(obj)
    return results


def summarize_hosts(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a compact host->ports summary from raw masscan results."""
    hosts: dict[str, dict[str, Any]] = {}
    for entry in results:
        ip = entry.get("ip", "unknown")
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "ports": [], "finished": entry.get("finished")}
        for port in entry.get("ports", []):
            hosts[ip]["ports"].append(
                {
                    "port": port.get("port"),
                    "proto": port.get("proto"),
                    "status": port.get("status"),
                    "service": port.get("service", {}),
                }
            )
    return list(hosts.values())


def build_command(args: argparse.Namespace) -> list[str]:
    command = [
        args.masscan_binary,
        args.target,
        "-p",
        args.ports,
        "--rate",
        str(args.rate),
        "--wait",
        str(args.wait),
        "-oJ",
        "-",  # JSON output to stdout
    ]
    if args.router_mac:
        command.extend(["--router-mac", args.router_mac])
    if args.adapter:
        command.extend(["--adapter", args.adapter])
    if args.source_ip:
        command.extend(["--source-ip", args.source_ip])
    if args.exclude:
        command.extend(["--exclude", args.exclude])
    if args.ttl is not None:
        command.extend(["--ttl", str(args.ttl)])
    for extra_arg in args.extra_arg:
        command.append(extra_arg)
    return command


def check_root() -> bool:
    """Return True if running as root (needed for raw socket / PF_PACKET)."""
    import os
    return os.geteuid() == 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run masscan and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", required=True, help="Target IP, range, or CIDR (e.g. 203.0.113.10, 203.0.113.0/24).")
    parser.add_argument("--ports", "-p", default="80,443,8080,8443", help="Port(s) to scan (e.g. 80,443 or 1-65535). Default: 80,443,8080,8443")
    parser.add_argument("--output", "-o", help="Optional normalized JSON output file.")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE, help=f"Packets per second. Default: {DEFAULT_RATE}")
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT, help=f"Seconds to wait after last reply. Default: {DEFAULT_WAIT}")
    parser.add_argument("--router-mac", help="Router MAC address (needed for some LAN scans).")
    parser.add_argument("--adapter", help="Network adapter to use.")
    parser.add_argument("--source-ip", help="Source IP for spoofed scans.")
    parser.add_argument("--exclude", help="IPs or ranges to exclude.")
    parser.add_argument("--ttl", type=int, help="Custom TTL value.")
    parser.add_argument("--extra-arg", action="append", default=[], help="Append one raw masscan argument.")
    parser.add_argument("--masscan-binary", default="masscan", help="Path to masscan binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime in seconds.")
    add_async_args(parser, "masscan")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if args.async_status:
        return async_status(args, started_at)

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

    if not check_root():
        emit(
            {
                "ok": False,
                "error": {
                    "type": "root_required",
                    "message": "masscan requires root privileges for raw socket access. Run with sudo.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 3

    if shutil.which(args.masscan_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"masscan binary not found: {args.masscan_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    if args.async_start:
        return async_start(args, argv, "masscan", started_at)

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
                "error": {"type": "timeout", "message": f"masscan exceeded {args.timeout} seconds"},
                "command": exc.cmd,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 124

    raw_results = parse_masscan_json(completed.stdout)
    hosts = summarize_hosts(raw_results)
    parse_error = any(r.get("_parse_error") for r in raw_results)

    total_open = sum(len(h["ports"]) for h in hosts)
    payload = {
        "ok": completed.returncode == 0 and not parse_error,
        "tool": "masscan",
        "started_at": started_at,
        "finished_at": utc_now(),
        "target": args.target,
        "ports_requested": args.ports,
        "rate": args.rate,
        "command": command,
        "returncode": completed.returncode,
        "total_open_ports": total_open,
        "hosts": hosts,
        "raw_count": len(raw_results),
        "stdout": completed.stdout if total_open == 0 else "",
        "stderr": completed.stderr,
    }
    if parse_error:
        payload["error"] = {"type": "json_parse_warning", "message": "Some lines could not be parsed as JSON — see raw results."}
    emit(payload, args.output)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
