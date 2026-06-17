#!/usr/bin/env python3
"""
授权目标的源站/公网入口暴露验证工具。

本工具只做低影响探测：本地 DNS、可选 DNS-over-HTTPS、直连 IP
HTTP(S) 指纹，以及通过 curl --resolve 绑定 Host/SNI 的访问验证。
输出统一 JSON，便于后续报告区分“公网入口 IP”和“私有应用 upstream IP”。

示例:
  ./tool/origin_exposure_probe.py --authorized --hostname example.com
  ./tool/origin_exposure_probe.py --authorized --hostname api.example.com --ip 203.0.113.10
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


DEFAULT_TIMEOUT = 180
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_MAX_TIME = 12


def utc_now() -> str:
    """返回 ISO-8601 UTC 时间戳，用于可复现的证据元数据。"""
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    """把 JSON 结果输出到 stdout，并按需写入文件。"""
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_headers(text: str) -> dict[str, list[str]]:
    """解析 curl 响应头，同时保留重复 header。"""
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key:
            continue
        headers.setdefault(key, []).append(value.strip())
    return headers


def local_dns_lookup(hostname: str) -> dict[str, Any]:
    """通过本机解析器解析域名，并归一化地址列表。"""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"hostname": hostname, "ok": False, "error": str(exc), "addresses": []}

    addresses = sorted({info[4][0] for info in infos})
    return {"hostname": hostname, "ok": True, "addresses": addresses}


def run_curl(command: list[str], timeout: int) -> dict[str, Any]:
    """
    使用独立文件保存 curl 的响应头和正文。

    响应头和正文分离可以避免重定向或代理插入多个 HTTP 状态块时，
    依赖字符串切分造成误判。
    """
    with tempfile.TemporaryDirectory(prefix="origin-probe-") as tmpdir:
        header_path = Path(tmpdir) / "headers.txt"
        body_path = Path(tmpdir) / "body.bin"
        full_command = command + ["-D", str(header_path), "-o", str(body_path)]
        try:
            completed = subprocess.run(
                full_command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "ok": False,
                "classification": "timeout",
                "command": exc.cmd,
                "error": f"curl exceeded {timeout} seconds",
            }

        header_text = header_path.read_text(encoding="utf-8", errors="replace") if header_path.exists() else ""
        body = body_path.read_bytes() if body_path.exists() else b""

    status = None
    for line in header_text.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])

    headers = parse_headers(header_text)
    body_sample = body[:512].decode("utf-8", errors="replace")
    return {
        "ok": completed.returncode == 0,
        "classification": classify_http_result(completed.returncode, status, headers, body_sample),
        "command": full_command,
        "returncode": completed.returncode,
        "status": status,
        "headers": headers,
        "body_sample": body_sample,
        "stderr": completed.stderr,
    }


def classify_http_result(returncode: int, status: int | None, headers: dict[str, list[str]], body_sample: str) -> str:
    """给响应打保守分类标签，避免报告对原始响应过度解读。"""
    if returncode != 0:
        return "curl_error"
    if status is None:
        return "no_http_status"

    server = ",".join(headers.get("server", [])).lower()
    content_type = ",".join(headers.get("content-type", [])).lower()
    body_lower = body_sample.lower()

    if status == 200 and "text/html" in content_type and ("<!doctype html" in body_lower or "<html" in body_lower):
        return "html_200"
    if status == 404 and "nginx" in server:
        return "nginx_404"
    if 300 <= status < 400:
        return "redirect"
    if status in {401, 403}:
        return "protected"
    if status >= 500:
        return "server_error"
    return f"http_{status}"


def doh_lookup(curl_binary: str, doh_url: str, hostname: str, timeout: int) -> dict[str, Any]:
    """需要外部 DNS 对比时，用 curl 查询 DNS-over-HTTPS 端点。"""
    url = f"{doh_url}?name={quote(hostname)}&type=A"
    command = [curl_binary, "-fsS", "--max-time", str(timeout), "-H", "accept: application/dns-json", url]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout + 2)
    except subprocess.TimeoutExpired as exc:
        return {"hostname": hostname, "ok": False, "classification": "timeout", "command": exc.cmd}
    try:
        data = json.loads(completed.stdout) if completed.stdout else {}
    except json.JSONDecodeError as exc:
        return {
            "hostname": hostname,
            "ok": False,
            "classification": "json_parse_error",
            "command": command,
            "error": str(exc),
            "raw": completed.stdout,
        }
    answers = data.get("Answer") or []
    addresses = sorted({item.get("data") for item in answers if item.get("type") == 1 and item.get("data")})
    return {
        "hostname": hostname,
        "ok": completed.returncode == 0,
        "classification": "doh_answer" if addresses else "doh_no_a_record",
        "command": command,
        "returncode": completed.returncode,
        "addresses": addresses,
        "raw_status": data.get("Status"),
        "stderr": completed.stderr,
    }


def build_base_curl(args: argparse.Namespace, method: str, url: str) -> list[str]:
    """构造所有 HTTP 探测共用的低影响 curl 命令。"""
    return [
        args.curl_binary,
        "-k",
        "-sS",
        "-X",
        method,
        "--connect-timeout",
        str(args.connect_timeout),
        "--max-time",
        str(args.max_time),
        url,
    ]


def fixed_resolution_probes(args: argparse.Namespace) -> list[dict[str, Any]]:
    """对每个域名和候选 IP 组合执行 curl --resolve 绑定访问。"""
    results = []
    for hostname in args.hostname:
        for ip in args.ip:
            for scheme, port in (("https", 443), ("http", 80)):
                url = f"{scheme}://{hostname}/"
                command = build_base_curl(args, "HEAD", url)
                command[1:1] = ["--resolve", f"{hostname}:{port}:{ip}"]
                result = run_curl(command, args.timeout)
                result.update({"hostname": hostname, "ip": ip, "scheme": scheme, "probe": "fixed_host_sni"})
                results.append(result)
    return results


def direct_ip_probes(args: argparse.Namespace) -> list[dict[str, Any]]:
    """不带业务 Host 直连 IP，用于识别默认虚拟主机指纹。"""
    results = []
    for ip in args.ip:
        for scheme in ("https", "http"):
            command = build_base_curl(args, "HEAD", f"{scheme}://{ip}/")
            result = run_curl(command, args.timeout)
            result.update({"ip": ip, "scheme": scheme, "probe": "direct_ip_default_host"})
            results.append(result)
    return results


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect safe source-origin exposure evidence.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--hostname", action="append", default=[], help="Authorized hostname to inspect. Repeatable.")
    parser.add_argument("--ip", action="append", default=[], help="Candidate public entry/source IP. Repeatable.")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--skip-doh", action="store_true", help="Skip DNS-over-HTTPS comparison.")
    parser.add_argument("--doh-url", default="https://dns.google/resolve", help="DNS-over-HTTPS JSON endpoint.")
    parser.add_argument("--curl-binary", default="curl", help="Path to curl binary.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Maximum runtime per curl subprocess.")
    parser.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, help="curl connect timeout.")
    parser.add_argument("--max-time", type=int, default=DEFAULT_MAX_TIME, help="curl request max time.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {"type": "authorization_required", "message": "Pass --authorized after scope is confirmed."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2
    if not args.hostname and not args.ip:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_targets", "message": "Provide --hostname and/or --ip."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2
    if shutil.which(args.curl_binary) is None:
        emit(
            {
                "ok": False,
                "error": {"type": "binary_not_found", "message": f"curl binary not found: {args.curl_binary}"},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 127

    local_dns = [local_dns_lookup(hostname) for hostname in args.hostname]
    doh_dns = [] if args.skip_doh else [doh_lookup(args.curl_binary, args.doh_url, hostname, args.max_time) for hostname in args.hostname]
    fixed = fixed_resolution_probes(args) if args.hostname and args.ip else []
    direct = direct_ip_probes(args) if args.ip else []

    payload = {
        "ok": True,
        "tool": "origin_exposure_probe",
        "started_at": started_at,
        "finished_at": utc_now(),
        "hostnames": args.hostname,
        "ips": args.ip,
        "local_dns": local_dns,
        "doh_dns": doh_dns,
        "fixed_resolution_probes": fixed,
        "direct_ip_probes": direct,
        "notes": [
            "fixed_host_sni proves a supplied public IP can serve the named host when Host/SNI are bound",
            "direct_ip_default_host fingerprints the default virtual host and should not be called a private upstream IP",
        ],
    }
    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
