#!/usr/bin/env python3
"""
Sploitus exploit/tool search wrapper for Codex.

It searches the public Sploitus API and emits either an AI-friendly Markdown
summary or structured JSON for downstream processing.

Examples:
  ./tool/sploitus.py --query "apache struts" --type exploits
  ./tool/sploitus.py --query "nuclei" --type tools --format json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


SPLOITUS_API_URL = "https://sploitus.com/search"
SPLOITUS_DEFAULT_SORT = "default"
DEFAULT_SPLOITUS_LIMIT = 10
MAX_SPLOITUS_LIMIT = 25
DEFAULT_SPLOITUS_TYPE = "exploits"
SPLOITUS_REQUEST_TIMEOUT = 30

MAX_SOURCE_SIZE = 50 * 1024
MAX_TOTAL_RESULT_SIZE = 80 * 1024
TRUNCATION_MSG_BUFFER = 500


@dataclass
class SploitusAction:
    query: str
    exploit_type: str = DEFAULT_SPLOITUS_TYPE
    sort: str = SPLOITUS_DEFAULT_SORT
    max_results: int = DEFAULT_SPLOITUS_LIMIT
    title: bool = False
    offset: int = 0


def normalize_action(args: argparse.Namespace) -> SploitusAction:
    exploit_type = (args.type or DEFAULT_SPLOITUS_TYPE).strip().lower()
    sort = (args.sort or SPLOITUS_DEFAULT_SORT).strip().lower()
    limit = args.max_results
    if limit < 1 or limit > MAX_SPLOITUS_LIMIT:
        limit = DEFAULT_SPLOITUS_LIMIT
    return SploitusAction(
        query=args.query,
        exploit_type=exploit_type,
        sort=sort,
        max_results=limit,
        title=args.title,
        offset=args.offset,
    )


def build_headers(query: str) -> dict[str, str]:
    referer = f"https://sploitus.com/?query={urllib.parse.quote(query)}"
    return {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json",
        "Origin": "https://sploitus.com",
        "Referer": referer,
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        ),
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "DNT": "1",
    }


def search_sploitus(action: SploitusAction, timeout: int) -> dict[str, Any]:
    request_body = {
        "query": action.query,
        "type": action.exploit_type,
        "sort": action.sort,
        "title": action.title,
        "offset": action.offset,
    }
    body = json.dumps(request_body).encode("utf-8")
    request = urllib.request.Request(
        SPLOITUS_API_URL,
        data=body,
        headers=build_headers(action.query),
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw_body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        if exc.code in {499, 422}:
            raise RuntimeError(
                f"Sploitus API rate limit exceeded (HTTP {exc.code}), please try again later"
            ) from exc
        raise RuntimeError(f"Sploitus API returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"request to Sploitus failed: {exc.reason}") from exc

    if status != 200:
        raise RuntimeError(f"Sploitus API returned HTTP {status}")

    try:
        parsed = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"failed to decode Sploitus response: {exc}") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("failed to decode Sploitus response: top-level response is not an object")
    parsed.setdefault("exploits", [])
    parsed.setdefault("exploits_total", len(parsed["exploits"]))
    return parsed


def append_limited(parts: list[str], item: str, current_size: int) -> tuple[bool, int]:
    if current_size + len(item) > MAX_TOTAL_RESULT_SIZE - TRUNCATION_MSG_BUFFER:
        return False, current_size
    parts.append(item)
    return True, current_size + len(item)


def format_sploitus_results(query: str, exploit_type: str, limit: int, response: dict[str, Any]) -> str:
    parts = [
        "# Sploitus Search Results\n\n",
        f"**Query:** `{query}`  \n",
        f"**Type:** {exploit_type}  \n",
        f"**Total matches on Sploitus:** {response.get('exploits_total', 0)}\n\n",
        "---\n\n",
    ]

    if limit < 1:
        limit = DEFAULT_SPLOITUS_LIMIT

    results = response.get("exploits", [])
    if not isinstance(results, list):
        results = []
    results = results[:limit]

    if not results:
        if exploit_type.lower() == "tools":
            parts.append("No security tools were found for the given query.\n")
        else:
            parts.append("No exploits were found for the given query.\n")
        return "".join(parts)

    current_size = len("".join(parts))
    actual_shown = 0
    truncated_by_size = False

    if exploit_type.lower() == "tools":
        header = f"## Security Tools (showing up to {len(results)})\n\n"
        parts.append(header)
        current_size += len(header)

        for index, item in enumerate(results, start=1):
            item_parts = [f"### {index}. {item.get('title', '')}\n\n"]
            if item.get("href"):
                item_parts.append(f"**URL:** {item['href']}  \n")
            if item.get("download"):
                item_parts.append(f"**Download:** {item['download']}  \n")
            if item.get("type"):
                item_parts.append(f"**Source Type:** {item['type']}  \n")
            if item.get("id"):
                item_parts.append(f"**ID:** {item['id']}  \n")
            item_parts.append("\n---\n\n")

            ok, current_size = append_limited(parts, "".join(item_parts), current_size)
            if not ok:
                truncated_by_size = True
                break
            actual_shown += 1
    else:
        header = f"## Exploits (showing up to {len(results)})\n\n"
        parts.append(header)
        current_size += len(header)

        for index, item in enumerate(results, start=1):
            item_parts = [f"### {index}. {item.get('title', '')}\n\n"]
            if item.get("href"):
                item_parts.append(f"**URL:** {item['href']}  \n")
            score = item.get("score")
            if isinstance(score, (int, float)) and score > 0:
                item_parts.append(f"**CVSS Score:** {score:.1f}  \n")
            if item.get("type"):
                item_parts.append(f"**Type:** {item['type']}  \n")
            if item.get("published"):
                item_parts.append(f"**Published:** {item['published']}  \n")
            if item.get("id"):
                item_parts.append(f"**ID:** {item['id']}  \n")
            if item.get("language"):
                item_parts.append(f"**Language:** {item['language']}  \n")
            if item.get("source"):
                source_preview = str(item["source"])
                if len(source_preview) > MAX_SOURCE_SIZE:
                    source_preview = (
                        source_preview[:MAX_SOURCE_SIZE]
                        + "\n... [source truncated, exceeded 50 KB limit]"
                    )
                item_parts.append(f"\n**Source Preview:**\n```\n{source_preview}\n```\n")
            item_parts.append("\n---\n\n")

            ok, current_size = append_limited(parts, "".join(item_parts), current_size)
            if not ok:
                truncated_by_size = True
                break
            actual_shown += 1

    if truncated_by_size:
        parts.append(
            "\n\n"
            f"**Note:** Results truncated after {actual_shown} items due to "
            f"{MAX_TOTAL_RESULT_SIZE} bytes size limit. Total shown: "
            f"{actual_shown} of {len(results)} available.\n"
        )

    return "".join(parts)


def emit_json(action: SploitusAction, response: dict[str, Any], markdown: str) -> str:
    results = response.get("exploits", [])
    if not isinstance(results, list):
        results = []
    return json.dumps(
        {
            "ok": True,
            "query": action.query,
            "type": action.exploit_type,
            "sort": action.sort,
            "limit": action.max_results,
            "total": response.get("exploits_total", len(results)),
            "results": results[: action.max_results],
            "markdown": markdown,
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search Sploitus for exploit or security-tool references."
    )
    parser.add_argument("--query", required=True, help="Search query, for example a product, CVE, or service.")
    parser.add_argument(
        "--type",
        choices=["exploits", "tools"],
        default=DEFAULT_SPLOITUS_TYPE,
        help="Sploitus search type.",
    )
    parser.add_argument("--sort", default=SPLOITUS_DEFAULT_SORT, help="Sploitus sort order.")
    parser.add_argument(
        "--max-results",
        type=int,
        default=DEFAULT_SPLOITUS_LIMIT,
        help=f"Maximum displayed results, clamped to 1-{MAX_SPLOITUS_LIMIT}.",
    )
    parser.add_argument("--title", action="store_true", help="Ask Sploitus to search only titles.")
    parser.add_argument("--offset", type=int, default=0, help="Sploitus result offset.")
    parser.add_argument("--timeout", type=int, default=SPLOITUS_REQUEST_TIMEOUT, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format.",
    )
    parser.add_argument("--output", help="Optional file path. Output is also printed to stdout.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    action = normalize_action(args)

    try:
        response = search_sploitus(action, args.timeout)
        markdown = format_sploitus_results(
            action.query,
            action.exploit_type,
            action.max_results,
            response,
        )
        output = emit_json(action, response, markdown) if args.format == "json" else markdown
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(output)
                output_file.write("\n")
        print(output)
        return 0
    except Exception as exc:
        message = f"failed to search in Sploitus: {exc}"
        if args.format == "json":
            print(
                json.dumps(
                    {
                        "ok": False,
                        "query": action.query,
                        "type": action.exploit_type,
                        "sort": action.sort,
                        "limit": action.max_results,
                        "error": str(exc),
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(message)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
