#!/usr/bin/env python3
"""Extract likely API/resource endpoint strings from saved xgym JS bundles."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
import re


KEYWORDS = (
    "api",
    "appraisal",
    "base",
    "exam",
    "login",
    "logout",
    "user",
    "upload",
    "captcha",
    "dict",
    "resource",
    "identity",
    "student",
    "monitor",
    "answer",
    "submit",
    "addr",
    "attachment",
    "oss",
    "video",
    "play",
)

ALLOWED_HTTP_HINTS = ("panyu", "pyhome", "zhiyingwl", "192.168")

HTTP_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
REL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_-])"
    r"((?:base|api|appraisal|attachment)/[A-Za-z0-9_./{}:?=&%-]+)"
)
CLEAN_PATH_RE = re.compile(r"[A-Za-z0-9_./{}:?=&%#-]+")


def decode_js_string(quote: str, body: str) -> str:
    if quote == '"':
        try:
            return json.loads(f'"{body}"')
        except json.JSONDecodeError:
            return body
    return body.replace(r"\'", "'").replace(r"\\", "\\")


def iter_js_strings(text: str):
    """Yield JavaScript string literal bodies using a linear scan."""
    idx = 0
    length = len(text)
    while idx < length:
        quote = text[idx]
        if quote not in ("'", '"'):
            idx += 1
            continue
        idx += 1
        start = idx
        escaped = False
        chunks = []
        while idx < length:
            char = text[idx]
            if escaped:
                chunks.append("\\" + char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                yield quote, "".join(chunks) if chunks else text[start:idx]
                idx += 1
                break
            else:
                chunks.append(char)
            idx += 1
        else:
            return


def interesting(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in KEYWORDS)


def add_candidate(found: dict[str, set[str]], source: Path, candidate: str) -> None:
    candidate = candidate.strip().rstrip(".,;")
    if len(candidate) < 4 or len(candidate) > 220 or not interesting(candidate):
        return
    if candidate.startswith("//") or candidate.startswith("/*#") or any(c in candidate for c in "\"' \n\t"):
        return
    if candidate.startswith(("http://", "https://")) and not any(hint in candidate for hint in ALLOWED_HTTP_HINTS):
        return
    if candidate.startswith(("../", "./", "/var/")):
        return
    found[candidate].add(source.name)


def extract(paths: list[Path]) -> list[dict[str, object]]:
    found: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for quote, body in iter_js_strings(text):
            value = decode_js_string(quote, body)
            for url in HTTP_RE.findall(value):
                add_candidate(found, path, url)
            for rel in REL_RE.findall(value):
                add_candidate(found, path, rel)
            if "/" in value and CLEAN_PATH_RE.fullmatch(value):
                add_candidate(found, path, value)
        for rel in REL_RE.findall(text):
            add_candidate(found, path, rel)

    rows = []
    for endpoint, sources in found.items():
        rows.append({"endpoint": endpoint, "sources": sorted(sources)})
    rows.sort(key=lambda row: (row["endpoint"].startswith("http"), row["endpoint"]))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    rows = extract(args.paths)
    payload = {"count": len(rows), "endpoints": rows}
    rendered = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
