#!/usr/bin/env python3
"""
网关、nginx、Java JSON 错误和 SPA fallback 路由响应分类工具。

本工具不是 fuzz 工具。它只请求操作者明确给出的少量路径，并标记常见
误报模式：SPA fallback 200、nginx 404、Java JSON 错误、
service-discovery 503，以及应用层拒绝响应。

示例:
  ./tool/gateway_route_classifier.py --authorized --base-url https://api.example.com --path /app/tool/startup
  ./tool/gateway_route_classifier.py --authorized --base-url https://api.example.com --input paths.txt --resolve api.example.com:443:203.0.113.10
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin


DEFAULT_TIMEOUT = 180
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_MAX_TIME = 12


def utc_now() -> str:
    """返回 ISO-8601 UTC 时间戳，用于证据元数据。"""
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    """把归一化 JSON 输出到 stdout，并按需写入文件。"""
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def load_paths(args: argparse.Namespace) -> list[str]:
    """从可重复的 --path 参数和可选文件中加载路由路径。"""
    paths = list(args.path)
    if args.input:
        for line in Path(args.input).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                paths.append(line)
    return sorted(dict.fromkeys(paths))


def parse_headers(text: str) -> dict[str, list[str]]:
    """解析 curl 响应头，同时保留重复 header 值。"""
    headers: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if key:
            headers.setdefault(key, []).append(value.strip())
    return headers


def run_curl(command: list[str], timeout: int) -> dict[str, Any]:
    """执行 curl，并返回状态码、响应头和有长度限制的正文样本。"""
    with tempfile.TemporaryDirectory(prefix="gateway-classifier-") as tmpdir:
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
                "confidence": "high",
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
    body_sample = body[:2048].decode("utf-8", errors="replace")
    classification, confidence, reason = classify_response(completed.returncode, status, headers, body_sample)
    return {
        "ok": completed.returncode == 0,
        "classification": classification,
        "confidence": confidence,
        "reason": reason,
        "command": full_command,
        "returncode": completed.returncode,
        "status": status,
        "headers": headers,
        "body_sample": body_sample,
        "stderr": completed.stderr,
    }


def looks_like_json(text: str) -> bool:
    """在做网关/正文分类前，先用低成本方式判断正文是否像 JSON。"""
    stripped = text.lstrip()
    return stripped.startswith("{") or stripped.startswith("[")


def classify_response(
    returncode: int,
    status: int | None,
    headers: dict[str, list[str]],
    body_sample: str,
) -> tuple[str, str, str]:
    """
    分类常见网关路由响应。

    分类标签保持保守。例如 SPA fallback 200 虽然 HTTP 状态是 200，
    但明确标记为不能当作路由暴露命中。
    """
    if returncode != 0:
        return "curl_error", "high", "curl did not complete successfully"
    if status is None:
        return "no_http_status", "high", "curl returned no parseable HTTP status"

    header_blob = "\n".join(f"{k}: {','.join(v)}" for k, v in headers.items()).lower()
    content_type = ",".join(headers.get("content-type", [])).lower()
    server = ",".join(headers.get("server", [])).lower()
    body_lower = body_sample.lower()

    if status == 200 and "text/html" in content_type and re.search(r"<!doctype html|<div id=[\"']?(root|app)|<html", body_lower):
        return "spa_fallback_200", "high", "HTML app shell; do not treat as route exposure"
    if status == 404 and "nginx" in server:
        return "nginx_404", "high", "nginx-level 404"
    if status == 503 and re.search(r"service|discovery|load.?balancer|no available|upstream|instance", body_lower):
        return "gateway_service_discovery_503", "medium", "503 body suggests gateway/service-discovery handling"
    if looks_like_json(body_sample) and (status >= 400 or "application/json" in content_type):
        if re.search(r"timestamp|error|message|path|trace|status", body_lower):
            return "java_json_error", "medium", "JSON error shape commonly returned by Java/Spring gateways"
        return "json_response", "low", "JSON response without enough fields for a stronger label"
    if status == 200 and re.search(r"非法请求|illegal request|invalid request|bad request", body_lower):
        return "application_rejection_200", "medium", "application rejected the request despite HTTP 200"
    if "access-control-allow-origin" in header_blob and "access-control-allow-credentials" in header_blob:
        return "credentialed_cors_response", "medium", "response contains credentialed CORS headers"
    if status in {401, 403}:
        return "protected_route", "high", "route exists or is handled but requires authorization"
    if 300 <= status < 400:
        return "redirect", "medium", "route returned a redirect"
    if status >= 500:
        return "server_error", "low", "server error without a more specific gateway signature"
    return f"http_{status}", "low", "generic HTTP classification"


def build_command(args: argparse.Namespace, method: str, url: str) -> list[str]:
    """为单个路由构造有超时边界的 curl 请求。"""
    command = [
        args.curl_binary,
        "-k",
        "-sS",
        "-X",
        method,
        "--connect-timeout",
        str(args.connect_timeout),
        "--max-time",
        str(args.max_time),
    ]
    for resolve in args.resolve:
        command.extend(["--resolve", resolve])
    for header in args.header:
        command.extend(["-H", header])
    command.append(url)
    return command


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify explicit gateway route probes.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--base-url", action="append", default=[], help="Base URL, for example https://api.example.com.")
    parser.add_argument("--path", action="append", default=[], help="Route path to probe. Repeatable.")
    parser.add_argument("--input", help="File containing one route path per line.")
    parser.add_argument("--method", action="append", default=["GET"], help="HTTP method. Repeatable; default GET.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--resolve", action="append", default=[], help="curl --resolve value host:port:ip. Repeatable.")
    parser.add_argument("--output", help="Optional JSON output file.")
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
    if not args.base_url:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_base_url", "message": "Provide at least one --base-url."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2
    paths = load_paths(args)
    if not paths:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_paths", "message": "Provide --path or --input."},
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

    results = []
    for base_url in args.base_url:
        for path in paths:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            for method in args.method:
                result = run_curl(build_command(args, method.upper(), url), args.timeout)
                result.update({"base_url": base_url, "path": path, "method": method.upper(), "url": url})
                results.append(result)

    payload = {
        "ok": True,
        "tool": "gateway_route_classifier",
        "started_at": started_at,
        "finished_at": utc_now(),
        "base_urls": args.base_url,
        "paths": paths,
        "methods": [method.upper() for method in args.method],
        "results": results,
    }
    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
