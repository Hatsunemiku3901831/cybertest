#!/usr/bin/env python3
"""Rustscan fast port discovery plus nmap service confirmation."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 1800
OPEN_PORT_RE = re.compile(r"Open\s+[^:]+:(\d+)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_ports(stdout: str) -> list[int]:
    ports = {int(match.group(1)) for match in OPEN_PORT_RE.finditer(stdout)}
    if not ports:
        for line in stdout.splitlines():
            line = line.strip()
            if re.fullmatch(r"\d+(,\d+)*", line):
                ports.update(int(part) for part in line.split(",") if part)
    return sorted(ports)


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    if not xml_text.strip():
        return []
    root = ET.fromstring(xml_text)
    hosts: list[dict[str, Any]] = []
    for host in root.findall("host"):
        addresses = [addr.attrib for addr in host.findall("address")]
        ports: list[dict[str, Any]] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            ports.append(
                {
                    "protocol": port.attrib.get("protocol"),
                    "portid": port.attrib.get("portid"),
                    "state": state.attrib if state is not None else {},
                    "service": service.attrib if service is not None else {},
                }
            )
        hosts.append({"addresses": addresses, "ports": ports})
    return hosts


def run_command(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def build_rustscan_command(args: argparse.Namespace) -> list[str]:
    command = [
        args.rustscan_binary,
        "-a",
        args.target,
        "--batch-size",
        str(args.batch_size),
        "--timeout",
        str(args.connect_timeout),
        "--ulimit",
        str(args.ulimit),
    ]
    if args.ports:
        command.extend(["-p", args.ports])
    if args.range:
        command.extend(["-r", args.range])
    for extra_arg in args.rustscan_extra_arg:
        command.append(extra_arg)
    return command


def build_nmap_command(args: argparse.Namespace, ports: list[int]) -> list[str]:
    command = [args.nmap_binary, "-Pn", "-sV", "-oX", "-", "-p", ",".join(str(port) for port in ports), args.target]
    if args.scripts:
        command.extend(["--script", args.scripts])
    for extra_arg in args.nmap_extra_arg:
        command.append(extra_arg)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run rustscan then nmap and emit normalized JSON.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--target", required=True, help="Target host or IP.")
    parser.add_argument("--output", help="Optional normalized JSON output file.")
    parser.add_argument("--ports", help="Port list for rustscan, for example 80,443,8080.")
    parser.add_argument("--range", help="Port range for rustscan, for example 1-65535.")
    parser.add_argument("--batch-size", type=int, default=4500, help="Rustscan batch size.")
    parser.add_argument("--connect-timeout", type=int, default=1500, help="Rustscan per-connect timeout in ms.")
    parser.add_argument("--ulimit", type=int, default=5000, help="Rustscan ulimit.")
    parser.add_argument("--scripts", help="Optional nmap --script value for confirmation scan.")
    parser.add_argument("--rustscan-extra-arg", action="append", default=[], help="Append one raw rustscan argument.")
    parser.add_argument("--nmap-extra-arg", action="append", default=[], help="Append one raw nmap argument.")
    parser.add_argument("--rustscan-binary", default="rustscan", help="Path to rustscan binary.")
    parser.add_argument("--nmap-binary", default="nmap", help="Path to nmap binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime per phase in seconds.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    if not args.authorized:
        emit({"ok": False, "error": {"type": "authorization_required", "message": "Pass --authorized only after confirming scope."}, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 2
    for binary_name, binary_path in (("rustscan", args.rustscan_binary), ("nmap", args.nmap_binary)):
        if shutil.which(binary_path) is None:
            emit({"ok": False, "error": {"type": "binary_not_found", "message": f"{binary_name} binary not found: {binary_path}"}, "started_at": started_at, "finished_at": utc_now()}, args.output)
            return 127

    rustscan_command = build_rustscan_command(args)
    try:
        rustscan = run_command(rustscan_command, args.timeout)
    except subprocess.TimeoutExpired as exc:
        emit({"ok": False, "error": {"type": "timeout", "message": f"rustscan exceeded {args.timeout} seconds"}, "command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
        return 124

    ports = parse_ports(rustscan.stdout)
    nmap_command: list[str] | None = None
    nmap_result: subprocess.CompletedProcess[str] | None = None
    nmap_hosts: list[dict[str, Any]] = []
    nmap_parse_error = None
    if ports:
        nmap_command = build_nmap_command(args, ports)
        try:
            nmap_result = run_command(nmap_command, args.timeout)
            try:
                nmap_hosts = parse_nmap_xml(nmap_result.stdout)
            except ET.ParseError as exc:
                nmap_parse_error = str(exc)
        except subprocess.TimeoutExpired as exc:
            emit({"ok": False, "error": {"type": "timeout", "message": f"nmap exceeded {args.timeout} seconds"}, "rustscan_command": rustscan_command, "nmap_command": exc.cmd, "stdout": exc.stdout, "stderr": exc.stderr, "started_at": started_at, "finished_at": utc_now()}, args.output)
            return 124

    payload = {
        "ok": rustscan.returncode == 0 and (nmap_result is None or nmap_result.returncode == 0) and nmap_parse_error is None,
        "tool": "rustscan_nmap",
        "started_at": started_at,
        "finished_at": utc_now(),
        "target": args.target,
        "open_ports": ports,
        "rustscan": {"command": rustscan_command, "returncode": rustscan.returncode, "stdout": rustscan.stdout, "stderr": rustscan.stderr},
        "nmap": None if nmap_command is None else {"command": nmap_command, "returncode": nmap_result.returncode if nmap_result else None, "hosts": nmap_hosts, "stderr": nmap_result.stderr if nmap_result else ""},
    }
    if nmap_parse_error:
        payload["error"] = {"type": "nmap_xml_parse_error", "message": nmap_parse_error}
    emit(payload, args.output)
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
