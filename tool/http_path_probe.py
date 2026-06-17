#!/usr/bin/env python3
"""
Authorized low-impact HTTP path/route probe.

This tool consolidates the former task-local safe_path_probe.py and
http_route_probe_nofollow.py helpers. It performs bounded GET/HEAD requests,
preserves redirect responses by default, and emits normalized JSON plus
optional header/body evidence files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin


DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 12
DEFAULT_MAX_BODY = 8192
DEFAULT_USER_AGENT = "codex-authorized-http-path-probe/1.0"

HIGH_SIGNAL_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "config-file": re.compile(rb"<configuration|connectionString", re.I),
    "password-keyword": re.compile(rb"password\s*[=:]", re.I),
    "private-key": re.compile(rb"BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY", re.I),
    "swagger-openapi": re.compile(rb"swagger|openapi", re.I),
    "directory-listing": re.compile(rb"Directory Listing|Index of /", re.I),
    "trace-info": re.compile(rb"Trace Information|ELMAH", re.I),
    "vcs-metadata": re.compile(rb"\.git|\.svn", re.I),
    "database-keyword": re.compile(rb"database|jdbc:|mongodb://|redis://", re.I),
    "backup-artifact": re.compile(rb"\.bak|backup|dump|phpinfo\(\)", re.I),
}

MARKER_PATTERNS: dict[str, bytes] = {
    "php-session": b"phpsessid=",
    "aspnet-session": b"asp.net_sessionid=",
    "admin-route": b"admin",
    "login-form": b"password",
    "upload": b"upload",
    "waf-block": b"waf",
    "iis-detail": b"iis",
    "spring-error": b"whitelabel error page",
    "nginx": b"nginx",
    "not-found": b"404",
}

INTERESTING_STATUSES = {200, 201, 202, 204, 206, 301, 302, 303, 307, 308, 401, 403}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, N802
        return None


@dataclass
class ProbeResult:
    url: str
    method: str
    status: int | None
    reason: str
    classification: str
    content_type: str
    content_length: str
    location: str
    set_cookie: str
    body_sha256: str
    header_path: str
    body_sample_path: str
    high_signal: list[str]
    markers: list[str]
    error: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_lines(path: str | None) -> list[str]:
    if not path:
        return []
    values: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            values.append(line)
    return values


def unique_ordered(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = value.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        result.append(clean)
    return result


def build_urls(args: argparse.Namespace) -> list[str]:
    direct_urls = list(args.url or []) + read_lines(args.urls)
    bases = list(args.base or []) + read_lines(args.bases)
    paths = list(args.path or []) + read_lines(args.paths)

    urls: list[str] = []
    urls.extend(direct_urls)
    for base in bases:
        normalized_base = base.rstrip("/") + "/"
        for path in paths:
            urls.append(urljoin(normalized_base, path.lstrip("/")))
    return unique_ordered(urls)


def safe_name(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", url)[:140].strip("_")
    return f"{slug}_{digest}" if slug else digest


def parse_header_lines(header_text: str) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for line in header_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key_lower = key.strip().lower()
        if key_lower:
            headers.setdefault(key_lower, []).append(value.strip())
    return headers


def first_header(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name.lower()) or []
    return values[0] if values else ""


def detect_high_signal(body: bytes, header_text: str) -> list[str]:
    haystack = body + b"\n" + header_text.encode("utf-8", errors="ignore")
    return [label for label, pattern in HIGH_SIGNAL_PATTERNS.items() if pattern.search(haystack)]


def detect_markers(body: bytes, header_text: str) -> list[str]:
    haystack = (body + b"\n" + header_text.encode("utf-8", errors="ignore")).lower()
    return [label for label, marker in MARKER_PATTERNS.items() if marker in haystack]


def classify_result(status: int | None, content_type: str, headers: dict[str, list[str]], body: bytes) -> str:
    if status is None:
        return "network_error"
    body_lower = body[:2048].lower()
    server = ",".join(headers.get("server", [])).lower()
    content_type_lower = content_type.lower()

    if 300 <= status < 400:
        return "redirect"
    if status in {401, 403}:
        return "protected"
    if status == 404:
        if "nginx" in server:
            return "nginx_404"
        return "not_found"
    if status == 200 and "text/html" in content_type_lower:
        if b"<!doctype html" in body_lower or b"<html" in body_lower:
            return "html_200"
    if status == 200 and ("json" in content_type_lower or body_lower[:1] in {b"{", b"["}):
        return "json_200"
    if status >= 500:
        return "server_error"
    return f"http_{status}"


def write_evidence(out_dir: Path | None, url: str, header_text: str, body: bytes) -> tuple[str, str]:
    if out_dir is None:
        return "", ""
    out_dir.mkdir(parents=True, exist_ok=True)
    name = safe_name(url)
    header_path = out_dir / f"{name}.headers"
    body_path = out_dir / f"{name}.body"
    header_path.write_text(header_text, encoding="utf-8")
    body_path.write_bytes(body)
    return str(header_path), str(body_path)


def build_headers(args: argparse.Namespace) -> dict[str, str]:
    headers = {"User-Agent": args.user_agent}
    if args.host:
        headers["Host"] = args.host
    if args.cookie:
        headers["Cookie"] = args.cookie
    for raw in args.header:
        if ":" not in raw:
            raise ValueError(f"invalid header, expected 'Name: value': {raw}")
        key, value = raw.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid header name: {raw}")
        headers[key] = value.strip()
    return headers


def build_opener(args: argparse.Namespace) -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    if not args.follow_redirects:
        handlers.append(NoRedirect)
    if args.insecure:
        context = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def probe(
    url: str,
    args: argparse.Namespace,
    headers: dict[str, str],
    opener: urllib.request.OpenerDirector,
    out_dir: Path | None,
) -> ProbeResult:
    request = urllib.request.Request(url, headers=headers, method=args.method)
    if args.data is not None:
        request.data = args.data.encode("utf-8")

    header_text = ""
    body = b""
    try:
        with opener.open(request, timeout=args.timeout) as resp:
            status = resp.status
            reason = resp.reason
            header_text = f"HTTP/{resp.version / 10:.1f} {status} {reason}\n" + str(resp.headers)
            if args.method != "HEAD":
                body = resp.read(args.max_body)
    except urllib.error.HTTPError as exc:
        status = exc.code
        reason = exc.reason
        header_text = f"HTTP error {status} {reason}\n" + str(exc.headers)
        if args.method != "HEAD":
            try:
                body = exc.read(args.max_body)
            except Exception:  # noqa: BLE001
                body = b""
    except Exception as exc:  # noqa: BLE001
        header_path, body_path = write_evidence(out_dir, url, "", b"")
        return ProbeResult(
            url=url,
            method=args.method,
            status=None,
            reason="",
            classification="network_error",
            content_type="",
            content_length="",
            location="",
            set_cookie="",
            body_sha256="",
            header_path=header_path,
            body_sample_path=body_path,
            high_signal=[],
            markers=[],
            error=repr(exc),
        )

    parsed_headers = parse_header_lines(header_text)
    content_type = first_header(parsed_headers, "content-type")
    header_path, body_path = write_evidence(out_dir, url, header_text, body)
    return ProbeResult(
        url=url,
        method=args.method,
        status=status,
        reason=reason,
        classification=classify_result(status, content_type, parsed_headers, body),
        content_type=content_type,
        content_length=first_header(parsed_headers, "content-length"),
        location=first_header(parsed_headers, "location"),
        set_cookie=first_header(parsed_headers, "set-cookie"),
        body_sha256=hashlib.sha256(body).hexdigest() if body else "",
        header_path=header_path,
        body_sample_path=body_path,
        high_signal=detect_high_signal(body, header_text),
        markers=detect_markers(body, header_text),
        error="",
    )


def is_interesting(item: dict[str, object]) -> bool:
    status = item.get("status")
    markers = item.get("markers") or []
    return (
        status in INTERESTING_STATUSES
        or bool(item.get("high_signal"))
        or (bool(markers) and markers != ["waf-block"])
    )


def emit(payload: dict[str, object], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Authorized bounded HTTP path/route probe.")
    parser.add_argument("--authorized", action="store_true", help="Required authorization acknowledgement.")
    parser.add_argument("--base", action="append", help="Base URL. Repeat for multiple bases.")
    parser.add_argument("--bases", help="File with base URLs.")
    parser.add_argument("--path", action="append", help="Path/route to probe. Repeat for multiple paths.")
    parser.add_argument("--paths", help="File with paths/routes.")
    parser.add_argument("--url", action="append", help="Full URL to probe. Repeat for multiple URLs.")
    parser.add_argument("--urls", help="File with full URLs.")
    parser.add_argument("--output", "--json", dest="output", help="Optional normalized JSON output file.")
    parser.add_argument("--out-dir", help="Optional directory for response header/body evidence.")
    parser.add_argument("--method", choices=["GET", "HEAD"], default="GET", help="HTTP method. Defaults to GET.")
    parser.add_argument("--data", help="Optional request body. Implies a urllib request body with the selected method.")
    parser.add_argument("--header", action="append", default=[], help="Header in 'Name: value' format.")
    parser.add_argument("--cookie", help="Cookie header value.")
    parser.add_argument("--host", help="Optional Host header override.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent value.")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects instead of preserving 30x.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout seconds.")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent worker count.")
    parser.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY, help="Maximum bytes read from each response.")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> str | None:
    if not args.authorized:
        return "pass --authorized only for in-scope targets"
    has_direct = bool(args.url or args.urls)
    has_matrix = bool(args.base or args.bases) and bool(args.path or args.paths)
    if not has_direct and not has_matrix:
        return "provide --url/--urls or both --base/--bases and --path/--paths"
    if args.data is not None and args.method == "HEAD":
        return "--data cannot be used with HEAD"
    if args.max_body < 0:
        return "--max-body must be >= 0"
    if args.workers < 1:
        return "--workers must be >= 1"
    return None


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    error = validate_args(args)
    if error:
        print(error, file=sys.stderr)
        return 2

    try:
        headers = build_headers(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    urls = build_urls(args)
    if not urls:
        print("no URLs to probe", file=sys.stderr)
        return 2

    started_at = utc_now()
    opener = build_opener(args)
    out_dir = Path(args.out_dir) if args.out_dir else None
    results: list[dict[str, object]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(probe, url, args, headers, opener, out_dir) for url in urls]
        for future in as_completed(futures):
            results.append(future.result().__dict__)

    results.sort(key=lambda item: str(item["url"]))
    interesting = [item for item in results if is_interesting(item)]
    payload: dict[str, object] = {
        "ok": True,
        "tool": "http_path_probe",
        "started_at": started_at,
        "finished_at": utc_now(),
        "count": len(results),
        "interesting_count": len(interesting),
        "options": {
            "method": args.method,
            "follow_redirects": args.follow_redirects,
            "host": args.host or "",
            "evidence_enabled": bool(args.out_dir),
            "max_body": args.max_body,
        },
        "interesting": interesting[:100],
        "results": results,
    }
    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
