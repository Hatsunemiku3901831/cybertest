#!/usr/bin/env python3
"""
FOFA API wrapper for authorized passive asset discovery.

Examples:
  ./tool/fofa_query.py --authorized --query 'domain="example.com"'
  ./tool/fofa_query.py --authorized --query 'cert="example.com"' --fields host,ip,port,protocol,title --size 200
  FOFA_KEY=... ./tool/fofa_query.py --authorized --query 'icon_hash="-247388890"' --output fofa.json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://fofa.info/api/v1/"
SEARCH_ENDPOINT = "search/all"
DEFAULT_FIELDS = "host,ip,port,protocol,title,domain,lastupdatetime"
DEFAULT_SIZE = 100
DEFAULT_TIMEOUT = 30
MAX_SIZE = 10000
DEFAULT_KEY_FILE = Path(__file__).with_name(".fofa_key")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def mask_secret(value: str | None) -> str | None:
    if not value:
        return value
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def load_secret_file(path: str | None) -> str | None:
    secret_path = Path(path) if path else DEFAULT_KEY_FILE
    if not secret_path.exists():
        return None
    return secret_path.read_text(encoding="utf-8").strip() or None


def build_query_url(args: argparse.Namespace, key: str) -> tuple[str, dict[str, str]]:
    query_text = args.query
    if args.qbase64:
        qbase64 = args.qbase64
    else:
        qbase64 = base64.b64encode(query_text.encode("utf-8")).decode("ascii")

    params: dict[str, str] = {
        "key": key,
        "qbase64": qbase64,
        "fields": args.fields,
        "page": str(args.page),
        "size": str(args.size),
        "full": "true" if args.full else "false",
        "r_type": "json",
    }
    if args.email:
        params["email"] = args.email

    base_url = args.base_url.rstrip("/")
    url = f"{base_url}/{SEARCH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    redacted = dict(params)
    redacted["key"] = mask_secret(key) or ""
    if "email" in redacted:
        redacted["email"] = mask_secret(args.email) or ""
    return url, redacted


def request_json(url: str, timeout: int, insecure: bool = False) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "codex-fofa-query/1.0"})
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return None, {
            "type": "http_error",
            "message": f"FOFA API returned HTTP {exc.code}",
            "status": exc.code,
            "body": body,
        }
    except urllib.error.URLError as exc:
        return None, {"type": "network_error", "message": str(exc.reason)}
    except TimeoutError:
        return None, {"type": "timeout", "message": f"FOFA API exceeded timeout"}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, {
            "type": "invalid_json",
            "message": f"FOFA API returned invalid JSON: {exc}",
            "status": status,
            "body": raw,
        }
    if not isinstance(data, dict):
        return None, {"type": "invalid_response", "message": "FOFA API response is not a JSON object."}
    return data, None


def normalize_results(fields: list[str], raw_results: Any) -> tuple[list[dict[str, Any]], list[Any]]:
    normalized: list[dict[str, Any]] = []
    unparsed: list[Any] = []
    if not isinstance(raw_results, list):
        return normalized, [raw_results]

    for item in raw_results:
        if isinstance(item, list):
            record = {field: item[index] if index < len(item) else None for index, field in enumerate(fields)}
            normalized.append(record)
        elif isinstance(item, dict):
            normalized.append(item)
        else:
            unparsed.append(item)
    return normalized, unparsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Query FOFA and emit normalized JSON for authorized asset discovery.")
    parser.add_argument("--authorized", action="store_true", help="Required acknowledgement of authorized scope.")
    parser.add_argument("--query", help="FOFA query syntax, for example: domain=\"example.com\".")
    parser.add_argument("--qbase64", help="Pre-encoded FOFA query. Use when the original query cannot be passed safely.")
    parser.add_argument("--fields", default=DEFAULT_FIELDS, help=f"Comma-separated return fields. Default: {DEFAULT_FIELDS}")
    parser.add_argument("--page", type=int, default=1, help="Result page number.")
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE, help=f"Results per page, max {MAX_SIZE}.")
    parser.add_argument("--full", action="store_true", help="Request full historical data when the account permits it.")
    parser.add_argument(
        "--key",
        help="FOFA API key. Defaults to FOFA_KEY environment variable, then tool/.fofa_key.",
    )
    parser.add_argument("--key-file", help="Optional file containing the FOFA API key.")
    parser.add_argument("--email", help="Optional FOFA account email. Defaults to FOFA_EMAIL environment variable.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"FOFA API base URL. Default: {DEFAULT_BASE_URL}")
    parser.add_argument("--output", help="Optional JSON output file.")
    parser.add_argument("--include-raw", action="store_true", help="Include the raw FOFA JSON response in output.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for the FOFA API request.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    key = args.key or os.environ.get("FOFA_KEY") or load_secret_file(args.key_file)
    args.email = args.email or os.environ.get("FOFA_EMAIL")

    if not args.authorized:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "authorization_required",
                    "message": "Pass --authorized only after confirming the query is limited to in-scope targets.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if not key:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "missing_api_key",
                    "message": "Provide --key, set FOFA_KEY, or create tool/.fofa_key.",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if not args.query and not args.qbase64:
        emit(
            {
                "ok": False,
                "error": {"type": "missing_query", "message": "Provide --query or --qbase64."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if args.page < 1:
        emit(
            {
                "ok": False,
                "error": {"type": "invalid_page", "message": "--page must be >= 1."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    if args.size < 1 or args.size > MAX_SIZE:
        emit(
            {
                "ok": False,
                "error": {"type": "invalid_size", "message": f"--size must be between 1 and {MAX_SIZE}."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    fields = [field.strip() for field in args.fields.split(",") if field.strip()]
    if not fields:
        emit(
            {
                "ok": False,
                "error": {"type": "invalid_fields", "message": "--fields must contain at least one field."},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    url, redacted_params = build_query_url(args, key)
    data, error = request_json(url, args.timeout, insecure=args.insecure)
    if error:
        emit(
            {
                "ok": False,
                "tool": "fofa",
                "error": error,
                "request": {
                    "base_url": args.base_url.rstrip("/"),
                    "endpoint": SEARCH_ENDPOINT,
                    "params": redacted_params,
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 1

    assert data is not None
    if data.get("error"):
        emit(
            {
                "ok": False,
                "tool": "fofa",
                "error": {
                    "type": "api_error",
                    "message": data.get("errmsg") or data.get("message") or "FOFA API returned error=true.",
                },
                "request": {
                    "base_url": args.base_url.rstrip("/"),
                    "endpoint": SEARCH_ENDPOINT,
                    "params": redacted_params,
                },
                "started_at": started_at,
                "finished_at": utc_now(),
                "raw": data if args.include_raw else None,
            },
            args.output,
        )
        return 1

    results, unparsed = normalize_results(fields, data.get("results", []))
    payload: dict[str, Any] = {
        "ok": True,
        "tool": "fofa",
        "started_at": started_at,
        "finished_at": utc_now(),
        "query": args.query,
        "qbase64": args.qbase64
        or base64.b64encode((args.query or "").encode("utf-8")).decode("ascii"),
        "fields": fields,
        "page": data.get("page", args.page),
        "size": data.get("size", len(results)),
        "mode": data.get("mode"),
        "request": {
            "base_url": args.base_url.rstrip("/"),
            "endpoint": SEARCH_ENDPOINT,
            "params": redacted_params,
        },
        "results": results,
        "unparsed_results": unparsed,
        "note": "FOFA results are passive index data and should be revalidated with live probes before conclusions.",
    }
    if args.include_raw:
        payload["raw"] = data

    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
