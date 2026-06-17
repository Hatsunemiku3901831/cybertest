#!/usr/bin/env python3
"""
CORS + 公开上传信任边界风险链的安全证据收集工具。

本工具只执行三类低影响动作：
1. 对明确给出的 URL 做凭证化 CORS 预检；
2. 可选执行一次无害 multipart 上传；
3. 对直接提供或从上传响应中提取的公开预览 URL 做 header/正文样本检查。

它不会执行上传内容，也不会尝试 shell/RCE。JSON 输出会写入分类标签，
便于报告区分 shell-risk 前置条件和直接代码执行。

示例:
  ./tool/cors_upload_chain.py --authorized --cors-url https://api.example.com/upload --origin https://attacker.example
  ./tool/cors_upload_chain.py --authorized --upload-url https://api.example.com/upload --cookie 'sid=...' --preview-url https://cdn.example.com/a.html
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


DEFAULT_TIMEOUT = 240
DEFAULT_CONNECT_TIMEOUT = 5
DEFAULT_MAX_TIME = 20
DEFAULT_PROOF = "<!doctype html><title>codex harmless upload proof</title><p>harmless upload proof</p>\n"


def utc_now() -> str:
    """返回 ISO-8601 UTC 时间戳，用于证据元数据。"""
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    """把归一化 JSON 输出到 stdout，并按需写入文件。"""
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_headers(text: str) -> dict[str, list[str]]:
    """解析响应头，同时保留重复 header 值。"""
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
    """用独立文件保存 curl 响应头和正文，保证解析稳定。"""
    with tempfile.TemporaryDirectory(prefix="cors-upload-chain-") as tmpdir:
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
    body_text = body[:4096].decode("utf-8", errors="replace")
    return {
        "ok": completed.returncode == 0,
        "command": redact_command(full_command),
        "returncode": completed.returncode,
        "status": status,
        "headers": headers,
        "body_sample": body_text,
        "stderr": completed.stderr,
    }


def redact_command(command: list[str]) -> list[str]:
    """保存证据前，对明显携带凭据的 curl 参数做脱敏。"""
    redacted = []
    skip_value_for = {"-H", "--header", "-b", "--cookie"}
    redact_next = False
    for item in command:
        if redact_next:
            redacted.append(redact_header_or_cookie(item))
            redact_next = False
            continue
        redacted.append(item)
        if item in skip_value_for:
            redact_next = True
    return redacted


def redact_header_or_cookie(value: str) -> str:
    """从命令元数据中移除 token/cookie 明文。"""
    lower = value.lower()
    if lower.startswith("authorization:"):
        return "Authorization: <redacted>"
    if lower.startswith("cookie:"):
        return "Cookie: <redacted>"
    if "=" in value and ("sid" in lower or "token" in lower or "session" in lower):
        return "<redacted-cookie>"
    return value


def base_curl(args: argparse.Namespace, method: str, url: str) -> list[str]:
    """构造共用的、带超时边界的 curl 命令。"""
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
    if args.cookie:
        command.extend(["-H", f"Cookie: {args.cookie}"])
    if args.bearer:
        command.extend(["-H", f"Authorization: Bearer {args.bearer}"])
    for header in args.header:
        command.extend(["-H", header])
    command.append(url)
    return command


def cors_preflight(args: argparse.Namespace, url: str) -> dict[str, Any]:
    """使用任意 Origin 和指定请求方法发送 OPTIONS 预检。"""
    command = base_curl(args, "OPTIONS", url)
    command[-1:-1] = [
        "-H",
        f"Origin: {args.origin}",
        "-H",
        f"Access-Control-Request-Method: {args.request_method}",
        "-H",
        "Access-Control-Request-Headers: authorization,content-type",
    ]
    result = run_curl(command, args.timeout)
    result["classification"] = classify_cors(result.get("headers", {}), args.origin)
    result["url"] = url
    return result


def classify_cors(headers: dict[str, list[str]], origin: str) -> str:
    """分类 CORS 响应头，重点识别任意 Origin 凭证化信任。"""
    allow_origin_values = headers.get("access-control-allow-origin", [])
    allow_credentials = ",".join(headers.get("access-control-allow-credentials", [])).lower()
    allow_origin = ",".join(allow_origin_values)
    if origin in allow_origin_values and "true" in allow_credentials:
        return "arbitrary_origin_credentialed_cors"
    if "*" in allow_origin and "true" in allow_credentials:
        return "wildcard_with_credentials_header"
    if origin in allow_origin_values:
        return "origin_reflected_without_credentials"
    if allow_origin_values:
        return "cors_present_not_reflecting_origin"
    return "no_cors_headers"


def write_upload_payload(args: argparse.Namespace, tmpdir: Path) -> Path:
    """创建或复制用于 multipart 证明的无害上传文件。"""
    payload_path = tmpdir / args.filename
    if args.file:
        payload_path.write_bytes(Path(args.file).read_bytes())
    else:
        payload_path.write_text(args.file_content, encoding="utf-8")
    return payload_path


def upload_probe(args: argparse.Namespace) -> dict[str, Any] | None:
    """执行可选 multipart 上传，并只保留有长度边界的响应证据。"""
    if not args.upload_url:
        return None
    with tempfile.TemporaryDirectory(prefix="cors-upload-payload-") as tmpdir_name:
        payload_path = write_upload_payload(args, Path(tmpdir_name))
        command = base_curl(args, args.upload_method, args.upload_url)
        form_value = f"{args.field}=@{payload_path};filename={args.filename};type={args.content_type}"
        command[-1:-1] = ["-F", form_value]
        result = run_curl(command, args.timeout)
    result["classification"] = classify_upload_response(result)
    result["url"] = args.upload_url
    result["extracted_preview_urls"] = extract_urls(result.get("body_sample", ""))
    return result


def classify_upload_response(result: dict[str, Any]) -> str:
    """标记上传结果，但不暗示已经发生服务端执行。"""
    status = result.get("status")
    body = str(result.get("body_sample", "")).lower()
    if result.get("returncode") != 0:
        return "upload_curl_error"
    if status and 200 <= status < 300:
        if extract_urls(result.get("body_sample", "")):
            return "upload_accepted_with_public_url_candidate"
        return "upload_accepted_no_url_extracted"
    if status in {401, 403}:
        return "upload_requires_authorization"
    if status and status >= 400 and re.search(r"extension|suffix|type|mime|invalid|not allowed|禁止|格式", body):
        return "upload_rejected_by_validation"
    return f"upload_http_{status}"


def extract_urls(text: str) -> list[str]:
    """从 JSON 或文本响应中提取候选预览 URL。"""
    urls = re.findall(r"https?://[^\s\"'<>\\]+", text)
    return sorted(dict.fromkeys(urls))


def preview_probe(args: argparse.Namespace, url: str) -> dict[str, Any]:
    """获取公开预览的响应头/正文样本，并分类浏览器侧风险信号。"""
    command = base_curl(args, "GET", url)
    result = run_curl(command, args.timeout)
    result["classification"] = classify_preview(url, result)
    result["url"] = url
    return result


def classify_preview(url: str, result: dict[str, Any]) -> str:
    """分类公开对象行为，但不把危险后缀接收等同于代码执行。"""
    status = result.get("status")
    headers = result.get("headers", {})
    content_disposition = ",".join(headers.get("content-disposition", [])).lower()
    content_type = ",".join(headers.get("content-type", [])).lower()
    nosniff = ",".join(headers.get("x-content-type-options", [])).lower()
    dangerous_suffix = re.search(r"\.(jsp|jspx|php|asp|aspx|war|jar)(?:$|\?)", url.lower()) is not None

    if result.get("returncode") != 0:
        return "preview_curl_error"
    if status == 404:
        return "preview_not_found"
    if status and status >= 400:
        return f"preview_http_{status}"
    if dangerous_suffix and status == 200 and "attachment" not in content_disposition:
        return "dangerous_suffix_public_inline_no_execution_proven"
    if status == 200 and ("text/html" in content_type or "image/svg" in content_type) and "attachment" not in content_disposition:
        if "nosniff" in nosniff:
            return "active_content_public_inline_with_nosniff"
        return "active_content_public_inline"
    if status == 200 and "attachment" in content_disposition:
        return "public_attachment"
    return f"preview_http_{status}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect safe CORS/upload trust-boundary evidence.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--cors-url", action="append", default=[], help="URL to preflight. Repeatable.")
    parser.add_argument("--upload-url", help="Optional multipart upload URL.")
    parser.add_argument("--preview-url", action="append", default=[], help="Known public preview URL to probe. Repeatable.")
    parser.add_argument("--origin", default="https://codex.invalid", help="Origin header used for CORS checks.")
    parser.add_argument("--request-method", default="POST", help="Access-Control-Request-Method value.")
    parser.add_argument("--upload-method", default="POST", help="HTTP method for multipart upload.")
    parser.add_argument("--field", default="file", help="Multipart file field name.")
    parser.add_argument("--filename", default="codex-harmless-proof.html", help="Uploaded filename.")
    parser.add_argument("--content-type", default="text/html", help="Multipart file content type.")
    parser.add_argument("--file", help="Optional local harmless file to upload.")
    parser.add_argument("--file-content", default=DEFAULT_PROOF, help="Inline harmless upload content.")
    parser.add_argument("--cookie", help="Cookie header value. Redacted in output command metadata.")
    parser.add_argument("--bearer", help="Bearer token. Redacted in output command metadata.")
    parser.add_argument("--header", action="append", default=[], help="Additional header. Avoid passing secrets here.")
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
    if not args.cors_url and not args.upload_url and not args.preview_url:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_actions", "message": "Provide --cors-url, --upload-url, or --preview-url."},
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

    preflight_urls = list(args.cors_url)
    if args.upload_url and args.upload_url not in preflight_urls:
        preflight_urls.append(args.upload_url)

    cors_results = [cors_preflight(args, url) for url in preflight_urls]
    upload_result = upload_probe(args)
    extracted = upload_result.get("extracted_preview_urls", []) if upload_result else []
    preview_urls = sorted(dict.fromkeys(args.preview_url + extracted))
    preview_results = [preview_probe(args, url) for url in preview_urls]

    payload = {
        "ok": True,
        "tool": "cors_upload_chain",
        "started_at": started_at,
        "finished_at": utc_now(),
        "origin": args.origin,
        "cors_results": cors_results,
        "upload_result": upload_result,
        "preview_results": preview_results,
        "notes": [
            "dangerous_suffix_public_inline_no_execution_proven is a shell-risk precursor, not direct shell evidence",
            "active_content_public_inline indicates browser-rendered user content unless mitigated by attachment or policy headers",
        ],
    }
    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
