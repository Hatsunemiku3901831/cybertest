#!/usr/bin/env python3
"""
Nmap JSON scanner for Codex-driven reconnaissance.

Example:
  python3 tool/nmap_json_scan.py --authorized --target 192.0.2.10 --profile default
  python3 tool/nmap_json_scan.py --authorized --target example.com --profile full --output scan.json
  python3 tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --profile discover
  python3 tool/nmap_json_scan.py --authorized --target 192.168.31.1 --profile lan-fast
  python3 tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --two-pass
  python3 tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --two-pass --async-start
  python3 tool/nmap_json_scan.py --async-status <task_id>

The script only wraps the local nmap binary. Use it only for targets where
you have explicit authorization.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


PROFILES: dict[str, list[str]] = {
    "discover": ["-sn"],
    "quick": ["-Pn", "-T3", "--top-ports", "100", "-sV", "--version-light"],
    "lan-fast": [
        "-Pn",
        "-T4",
        "--top-ports",
        "1000",
        "--open",
        "-sV",
        "--version-light",
        "--max-retries",
        "1",
        "--host-timeout",
        "90s",
        "--defeat-rst-ratelimit",
    ],
    "lan-deep": [
        "-Pn",
        "-T3",
        "--top-ports",
        "1000",
        "--open",
        "-sV",
        "--version-all",
        "--script",
        "default,safe",
        "--max-retries",
        "2",
        "--host-timeout",
        "180s",
    ],
    "risk-ports": [
        "-Pn",
        "-T4",
        "-p",
        "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,631,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,6379,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017",
        "--open",
        "--max-retries",
        "1",
        "--host-timeout",
        "60s",
        "--defeat-rst-ratelimit",
    ],
    "full-fast": [
        "-Pn",
        "-T4",
        "-p-",
        "--open",
        "--min-rate",
        "2000",
        "--max-retries",
        "1",
        "--host-timeout",
        "120s",
        "--defeat-rst-ratelimit",
    ],
    "default": [
        "-Pn",
        "-T3",
        "-sV",
        "--version-all",
        "-O",
        "--osscan-guess",
        "--traceroute",
        "--script",
        "default,safe",
    ],
    "full": [
        "-Pn",
        "-T3",
        "-p-",
        "-sV",
        "--version-all",
        "-O",
        "--osscan-guess",
        "--traceroute",
        "--script",
        "default,safe",
    ],
    "udp": ["-Pn", "-T3", "-sU", "--top-ports", "200", "-sV", "--script", "default,safe"],
    "udp-fast": ["-Pn", "-T4", "-sU", "--top-ports", "50", "--max-retries", "1", "--host-timeout", "90s"],
    "web": [
        "-Pn",
        "-T3",
        "-p",
        "80,81,88,443,591,8000,8008,8080,8081,8443,8888,9443",
        "-sV",
        "--version-all",
        "--script",
        "http-title,http-server-header,http-headers,http-methods,http-robots.txt,ssl-cert,ssl-enum-ciphers",
    ],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def text_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def attrs(element: ElementTree.Element | None) -> dict[str, str]:
    return dict(element.attrib) if element is not None else {}


def script_to_dict(script: ElementTree.Element) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": script.attrib.get("id"),
        "output": script.attrib.get("output"),
    }
    tables = []
    for table in script.findall("table"):
        entries = {}
        for elem in table.findall("elem"):
            key = elem.attrib.get("key") or "value"
            entries[key] = text_or_none(elem.text)
        nested = []
        for nested_table in table.findall("table"):
            nested_entries = {}
            for elem in nested_table.findall("elem"):
                key = elem.attrib.get("key") or "value"
                nested_entries[key] = text_or_none(elem.text)
            nested.append({"key": nested_table.attrib.get("key"), "entries": nested_entries})
        tables.append({"key": table.attrib.get("key"), "entries": entries, "tables": nested})
    if tables:
        result["tables"] = tables
    return result


def parse_port(port: ElementTree.Element) -> dict[str, Any]:
    state = port.find("state")
    service = port.find("service")
    scripts = [script_to_dict(script) for script in port.findall("script")]
    return {
        "protocol": port.attrib.get("protocol"),
        "port": int(port.attrib["portid"]) if port.attrib.get("portid", "").isdigit() else port.attrib.get("portid"),
        "state": attrs(state),
        "service": attrs(service),
        "scripts": scripts,
    }


def parse_os(host: ElementTree.Element) -> dict[str, Any]:
    os_elem = host.find("os")
    if os_elem is None:
        return {}
    return {
        "ports_used": [attrs(portused) for portused in os_elem.findall("portused")],
        "matches": [
            {
                "name": osmatch.attrib.get("name"),
                "accuracy": osmatch.attrib.get("accuracy"),
                "line": osmatch.attrib.get("line"),
                "classes": [attrs(osclass) for osclass in osmatch.findall("osclass")],
            }
            for osmatch in os_elem.findall("osmatch")
        ],
        "fingerprint": text_or_none(os_elem.findtext("osfingerprint")),
    }


def parse_trace(host: ElementTree.Element) -> dict[str, Any]:
    trace = host.find("trace")
    if trace is None:
        return {}
    return {
        "proto": trace.attrib.get("proto"),
        "port": trace.attrib.get("port"),
        "hops": [attrs(hop) for hop in trace.findall("hop")],
    }


def parse_host(host: ElementTree.Element) -> dict[str, Any]:
    ports = host.find("ports")
    extra_ports = []
    parsed_ports = []
    if ports is not None:
        extra_ports = [attrs(extra) for extra in ports.findall("extraports")]
        parsed_ports = [parse_port(port) for port in ports.findall("port")]

    return {
        "status": attrs(host.find("status")),
        "addresses": [attrs(address) for address in host.findall("address")],
        "hostnames": [attrs(hostname) for hostname in host.findall("./hostnames/hostname")],
        "uptime": attrs(host.find("uptime")),
        "distance": attrs(host.find("distance")),
        "tcpsequence": attrs(host.find("tcpsequence")),
        "ipidsequence": attrs(host.find("ipidsequence")),
        "tcptssequence": attrs(host.find("tcptssequence")),
        "ports": parsed_ports,
        "extra_ports": extra_ports,
        "os": parse_os(host),
        "trace": parse_trace(host),
        "host_scripts": [script_to_dict(script) for script in host.findall("./hostscript/script")],
        "times": attrs(host.find("times")),
    }


def parse_xml(xml_path: Path) -> dict[str, Any]:
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    runstats = root.find("runstats")
    hosts = [parse_host(host) for host in root.findall("host")]
    return {
        "scanner": root.attrib.get("scanner"),
        "args": root.attrib.get("args"),
        "start": root.attrib.get("start"),
        "startstr": root.attrib.get("startstr"),
        "version": root.attrib.get("version"),
        "xmloutputversion": root.attrib.get("xmloutputversion"),
        "scaninfo": [attrs(scaninfo) for scaninfo in root.findall("scaninfo")],
        "verbose": attrs(root.find("verbose")),
        "debugging": attrs(root.find("debugging")),
        "hosts": hosts,
        "runstats": {
            "finished": attrs(runstats.find("finished")) if runstats is not None else {},
            "hosts": attrs(runstats.find("hosts")) if runstats is not None else {},
        },
    }


def without_option_values(values: list[str], options: set[str]) -> list[str]:
    filtered = []
    skip_next = False
    for value in values:
        if skip_next:
            skip_next = False
            continue
        if value in options:
            skip_next = True
            continue
        filtered.append(value)
    return filtered


def build_nmap_args(args: argparse.Namespace, xml_path: Path) -> list[str]:
    profile_args = list(PROFILES[args.profile])
    if args.ports:
        profile_args = without_option_values(profile_args, {"-p", "--top-ports"})
    if args.top_ports:
        profile_args = without_option_values(profile_args, {"--top-ports"})
    if args.scripts:
        profile_args = without_option_values(profile_args, {"--script"})
    if args.min_rate:
        profile_args = without_option_values(profile_args, {"--min-rate"})
    if args.max_retries is not None:
        profile_args = without_option_values(profile_args, {"--max-retries"})
    if args.host_timeout:
        profile_args = without_option_values(profile_args, {"--host-timeout"})
    if args.max_rtt_timeout:
        profile_args = without_option_values(profile_args, {"--max-rtt-timeout"})
    if args.initial_rtt_timeout:
        profile_args = without_option_values(profile_args, {"--initial-rtt-timeout"})
    if args.stats_every:
        profile_args = without_option_values(profile_args, {"--stats-every"})

    nmap_args = [args.nmap_binary]
    nmap_args.extend(profile_args)

    if args.ports:
        nmap_args.extend(["-p", args.ports])
    if args.top_ports:
        nmap_args.extend(["--top-ports", str(args.top_ports)])
    if args.scripts:
        nmap_args.extend(["--script", args.scripts])
    if args.open_only and "--open" not in nmap_args:
        nmap_args.append("--open")
    if args.min_rate:
        nmap_args.extend(["--min-rate", str(args.min_rate)])
    if args.max_retries is not None:
        nmap_args.extend(["--max-retries", str(args.max_retries)])
    if args.host_timeout:
        nmap_args.extend(["--host-timeout", args.host_timeout])
    if args.max_rtt_timeout:
        nmap_args.extend(["--max-rtt-timeout", args.max_rtt_timeout])
    if args.initial_rtt_timeout:
        nmap_args.extend(["--initial-rtt-timeout", args.initial_rtt_timeout])
    if args.stats_every:
        nmap_args.extend(["--stats-every", args.stats_every])
    if args.defeat_rst_ratelimit and "--defeat-rst-ratelimit" not in nmap_args:
        nmap_args.append("--defeat-rst-ratelimit")
    if args.extra_nmap_arg:
        nmap_args.extend(args.extra_nmap_arg)

    nmap_args.extend(["-oX", str(xml_path)])
    nmap_args.extend(args.target)
    return nmap_args


def emit_json(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(json_safe(payload), ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(json_safe(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def default_async_dir() -> Path:
    return Path(tempfile.gettempdir()) / "codex-nmap-tasks"


def async_dir_from_args(args: argparse.Namespace) -> Path:
    return Path(args.async_dir).expanduser() if args.async_dir else default_async_dir()


def process_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def async_command(argv: list[str], result_path: Path) -> list[str]:
    command = [sys.executable, str(Path(__file__).resolve())]
    skip_next = False
    for value in argv:
        if skip_next:
            skip_next = False
            continue
        if value == "--async-start":
            continue
        if value in {"--async-status", "--async-dir", "--output"}:
            skip_next = True
            continue
        command.append(value)
    command.extend(["--output", str(result_path)])
    return command


def start_async_task(args: argparse.Namespace, argv: list[str], started_at: str) -> int:
    task_id = f"nmap-{uuid.uuid4().hex[:12]}"
    task_root = async_dir_from_args(args)
    task_dir = task_root / task_id
    task_dir.mkdir(parents=True, exist_ok=False)

    result_path = task_dir / "result.json"
    stdout_path = task_dir / "stdout.log"
    stderr_path = task_dir / "stderr.log"
    metadata_path = task_dir / "task.json"
    command = async_command(argv, result_path)

    stdout_file = stdout_path.open("w", encoding="utf-8")
    stderr_file = stderr_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
    finally:
        stdout_file.close()
        stderr_file.close()

    metadata = {
        "ok": True,
        "task_id": task_id,
        "pid": process.pid,
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "command": command,
        "task_dir": str(task_dir),
        "result_path": str(result_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    write_json(metadata_path, metadata)
    emit_json(metadata, args.output)
    return 0


def async_status(args: argparse.Namespace, started_at: str) -> int:
    task_root = async_dir_from_args(args)
    task_dir = task_root / args.async_status
    metadata_path = task_dir / "task.json"
    if not metadata_path.exists():
        emit_json(
            {
                "ok": False,
                "error": {
                    "type": "async_task_not_found",
                    "message": f"Async task not found: {args.async_status}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    metadata = read_json(metadata_path)
    result_path = Path(metadata["result_path"])
    stderr_path = Path(metadata["stderr_path"])
    pid = int(metadata["pid"])
    running = process_running(pid)
    result = read_json(result_path) if result_path.exists() else None

    if result is not None:
        status = "completed" if result.get("ok") else "failed"
    elif running:
        status = "running"
    else:
        status = "failed"

    metadata["status"] = status
    metadata["finished_at"] = result.get("finished_at") if result else (None if running else utc_now())
    write_json(metadata_path, metadata)

    payload = {
        "ok": status == "completed",
        "task_id": args.async_status,
        "status": status,
        "pid": pid,
        "running": running,
        "started_at": metadata.get("started_at"),
        "finished_at": metadata.get("finished_at"),
        "task_dir": metadata.get("task_dir"),
        "result_path": str(result_path),
        "stdout_path": metadata.get("stdout_path"),
        "stderr_path": str(stderr_path),
        "result": result,
    }
    if status == "failed" and result is None and stderr_path.exists():
        payload["stderr_tail"] = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]

    emit_json(payload, args.output)
    return 0 if status in {"completed", "running"} else 1


def up_targets(payload: dict[str, Any]) -> list[str]:
    targets = []
    seen = set()
    for host in payload.get("nmap", {}).get("hosts", []):
        if host.get("status", {}).get("state") != "up":
            continue
        addresses = host.get("addresses", [])
        preferred = next((addr for addr in addresses if addr.get("addrtype") == "ipv4"), None)
        if preferred is None:
            preferred = next((addr for addr in addresses if addr.get("addrtype") == "ipv6"), None)
        if preferred is None:
            continue
        target = preferred.get("addr")
        if target and target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def clone_args(args: argparse.Namespace, *, profile: str, targets: list[str]) -> argparse.Namespace:
    cloned = argparse.Namespace(**vars(args))
    cloned.profile = profile
    cloned.target = targets
    return cloned


def discovery_args(args: argparse.Namespace) -> argparse.Namespace:
    cloned = clone_args(args, profile=args.wide_profile, targets=args.target)
    cloned.ports = None
    cloned.top_ports = None
    cloned.scripts = None
    cloned.open_only = False
    cloned.min_rate = None
    cloned.max_retries = None
    cloned.host_timeout = None
    cloned.max_rtt_timeout = None
    cloned.initial_rtt_timeout = None
    cloned.defeat_rst_ratelimit = False
    cloned.extra_nmap_arg = []
    return cloned


def run_nmap_scan(args: argparse.Namespace, xml_path: Path, started_at: str) -> tuple[dict[str, Any], int]:
    nmap_args = build_nmap_args(args, xml_path)
    try:
        completed = subprocess.run(
            nmap_args,
            check=False,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            {
                "ok": False,
                "error": {
                    "type": "timeout",
                    "message": f"nmap exceeded timeout of {args.timeout} seconds",
                },
                "command": exc.cmd,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
                "started_at": started_at,
                "finished_at": utc_now(),
                "profile": args.profile,
                "targets": args.target,
            },
            124,
        )

    payload: dict[str, Any] = {
        "ok": completed.returncode == 0,
        "started_at": started_at,
        "finished_at": utc_now(),
        "profile": args.profile,
        "targets": args.target,
        "command": nmap_args,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }

    if xml_path.exists() and xml_path.stat().st_size > 0:
        try:
            payload["nmap"] = parse_xml(xml_path)
        except ElementTree.ParseError as exc:
            payload["ok"] = False
            payload["error"] = {
                "type": "xml_parse_error",
                "message": str(exc),
            }
    else:
        payload["ok"] = False
        payload["error"] = {
            "type": "missing_xml",
            "message": "nmap did not produce XML output",
        }

    return payload, completed.returncode if completed.returncode != 0 else 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run nmap and emit AI-friendly JSON for authorized reconnaissance."
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Required acknowledgement that all targets are in scope and authorized.",
    )
    parser.add_argument(
        "--target",
        action="append",
        help="Target host, CIDR, or hostname. Repeat for multiple authorized targets.",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="default",
        help="Scan profile. Use discover/lan-fast/risk-ports/full-fast for fast staged LAN work; default/full keep deeper legacy behavior.",
    )
    parser.add_argument("--ports", help="Override port list, for example 22,80,443 or 1-1000.")
    parser.add_argument("--top-ports", type=int, help="Override top port count.")
    parser.add_argument("--scripts", help="Override NSE script expression, for example default,safe,vuln.")
    parser.add_argument("--open-only", action="store_true", help="Add --open to suppress closed-port noise.")
    parser.add_argument("--min-rate", type=int, help="Override nmap --min-rate.")
    parser.add_argument("--max-retries", type=int, help="Override nmap --max-retries.")
    parser.add_argument("--host-timeout", help="Override nmap --host-timeout, for example 90s or 5m.")
    parser.add_argument("--max-rtt-timeout", help="Override nmap --max-rtt-timeout, for example 1000ms.")
    parser.add_argument("--initial-rtt-timeout", help="Override nmap --initial-rtt-timeout, for example 250ms.")
    parser.add_argument("--stats-every", help="Emit nmap progress lines at this interval, for example 15s.")
    parser.add_argument(
        "--two-pass",
        action="store_true",
        help="Run a high-performance discovery pass first, then scan only discovered live hosts.",
    )
    parser.add_argument(
        "--wide-profile",
        choices=sorted(PROFILES),
        default="discover",
        help="First-pass profile for --two-pass. Defaults to discover.",
    )
    parser.add_argument(
        "--deep-profile",
        choices=sorted(PROFILES),
        default="lan-deep",
        help="Second-pass profile for --two-pass. Defaults to lan-deep.",
    )
    parser.add_argument(
        "--defeat-rst-ratelimit",
        action="store_true",
        help="Add --defeat-rst-ratelimit when scan targets appear to rate-limit closed-port RSTs.",
    )
    parser.add_argument(
        "--extra-nmap-arg",
        action="append",
        default=[],
        help="Append one raw nmap argument. Repeat for multiple arguments.",
    )
    parser.add_argument("--nmap-binary", default="nmap", help="Path to nmap binary.")
    parser.add_argument("--output", help="Optional JSON output file path. JSON is also printed to stdout.")
    parser.add_argument("--timeout", type=int, default=1800, help="Maximum runtime in seconds.")
    parser.add_argument("--async-start", action="store_true", help="Start the scan in the background and return a task id.")
    parser.add_argument("--async-status", help="Read async task status and result by task id.")
    parser.add_argument(
        "--async-dir",
        help=f"Directory for async task state. Defaults to {default_async_dir()}.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if args.async_status:
        return async_status(args, started_at)

    if not args.target:
        emit_json(
            {
                "ok": False,
                "error": {
                    "type": "target_required",
                    "message": "Pass at least one --target unless using --async-status.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if not args.authorized:
        emit_json(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the target scope is explicitly authorized.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if shutil.which(args.nmap_binary) is None:
        emit_json(
            {
                "ok": False,
                "error": {
                    "type": "nmap_not_found",
                    "message": f"nmap binary not found: {args.nmap_binary}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    if args.async_start:
        return start_async_task(args, argv, started_at)

    with tempfile.TemporaryDirectory(prefix="nmap-json-scan-") as tmpdir:
        tmp_path = Path(tmpdir)
        if args.two_pass:
            first_started_at = utc_now()
            first_payload, first_code = run_nmap_scan(discovery_args(args), tmp_path / "wide.xml", first_started_at)
            discovered_targets = up_targets(first_payload)
            second_payload = None
            second_code = 0

            if first_payload.get("ok") and discovered_targets:
                second_args = clone_args(args, profile=args.deep_profile, targets=discovered_targets)
                second_started_at = utc_now()
                second_payload, second_code = run_nmap_scan(second_args, tmp_path / "deep.xml", second_started_at)

            payload = {
                "ok": first_payload.get("ok", False) and (second_payload is None or second_payload.get("ok", False)),
                "started_at": started_at,
                "finished_at": utc_now(),
                "mode": "two-pass",
                "targets": args.target,
                "wide_profile": args.wide_profile,
                "deep_profile": args.deep_profile,
                "discovered_targets": discovered_targets,
                "wide": first_payload,
                "deep": second_payload,
            }
            if first_payload.get("ok") and not discovered_targets:
                payload["note"] = "First pass found no live hosts; deep scan was skipped."

            emit_json(payload, args.output)
            if first_code != 0:
                return first_code
            return second_code

        payload, code = run_nmap_scan(args, tmp_path / "scan.xml", started_at)
        emit_json(payload, args.output)
        return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
