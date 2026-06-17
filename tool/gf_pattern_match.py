#!/usr/bin/env python3
"""
gf-patterns URL pattern-match wrapper — native Python implementation.

Applies Gf-Patterns (14 regex-based URL classifiers) against a URL list and
outputs a normalized JSON report with per-pattern matches and a P0–P3 priority
ranking.  No external ``gf`` binary required — patterns are read directly from
``~/.gf/*.json``.

Examples:
  # Match all 14 patterns against a katana URL dump
  ./tool/gf_pattern_match.py --input katana_urls.txt --output gf-results.json

  # Run a single high-signal pattern
  ./tool/gf_pattern_match.py --input urls.txt --pattern sqli

  # Read from stdin, write JSON to stdout
  cat urls.txt | ./tool/gf_pattern_match.py

  # Only P0 + P1 patterns
  ./tool/gf_pattern_match.py --input urls.txt --min-priority P1

  # Custom patterns directory
  ./tool/gf_pattern_match.py --input urls.txt --patterns-dir /custom/gf-patterns
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Priority map — drives the automated P0–P3 ranking.
# ---------------------------------------------------------------------------
PRIORITY_MAP: dict[str, dict[str, Any]] = {
    "sqli":             {"priority": "P0", "label": "SQL 注入候选",              "weight": 95},
    "rce":              {"priority": "P0", "label": "远程命令/代码执行候选",      "weight": 95},
    "ssti":             {"priority": "P0", "label": "服务端模板注入候选",         "weight": 90},
    "ssrf":             {"priority": "P1", "label": "SSRF 候选",                 "weight": 75},
    "lfi":              {"priority": "P1", "label": "本地文件包含/路径遍历候选",   "weight": 75},
    "idor":             {"priority": "P1", "label": "IDOR/越权候选",             "weight": 70},
    "redirect":         {"priority": "P1", "label": "开放重定向候选",             "weight": 65},
    "xss":              {"priority": "P2", "label": "XSS 候选",                  "weight": 50},
    "debug_logic":      {"priority": "P2", "label": "调试逻辑/管理功能候选",       "weight": 45},
    "img-traversal":    {"priority": "P2", "label": "图片路径遍历候选",           "weight": 40},
    "interestingparams":{"priority": "P3", "label": "敏感参数名候选",             "weight": 20},
    "interestingsubs":  {"priority": "P3", "label": "敏感子路径候选",             "weight": 15},
    "interestingEXT":   {"priority": "P3", "label": "敏感文件扩展名候选",          "weight": 10},
    "jsvar":            {"priority": "P3", "label": "JS 变量提取候选",            "weight": 5},
}

DEFAULT_PATTERNS_DIR = Path.home() / ".gf"
PRIORITY_ORDER = ["P0", "P1", "P2", "P3"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any], output: str | None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(data + "\n", encoding="utf-8")
    print(data)


def parse_gf_flags(flag_str: str) -> int:
    """Convert ``gf``-style flags (``-iE``, ``-HanroE``) to ``re`` bitmask.

    Only ``-i`` (case-insensitive) is mapped; ``-E``/``-H``/``-a``/``-n``/
    ``-r``/``-o`` are grep flags with no Python ``re`` equivalent.
    """
    mask = 0
    for ch in flag_str.replace("-", ""):
        if ch == "i":
            mask |= re.IGNORECASE
    return mask


def load_pattern_file(name: str, path: Path) -> dict[str, Any]:
    """Load a single ``.gf/*.json`` pattern file.

    Returns a dict with metadata, raw patterns, and pre-compiled regex list.
    On failure the dict carries an ``"error"`` key.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"name": name, "error": f"failed to load {path}: {exc}"}

    flag_str = raw.get("flags", "")
    regex_flags = parse_gf_flags(flag_str)
    raw_patterns: list[str] = [
        s for s in raw.get("patterns", []) if isinstance(s, str) and s.strip()
    ]

    compiled: list[re.Pattern[str]] = []
    skipped: list[str] = []
    for rp in raw_patterns:
        try:
            compiled.append(re.compile(rp, regex_flags))
        except re.error as exc:
            skipped.append(f"{rp}: {exc}")

    info = PRIORITY_MAP.get(name, {"priority": "P3", "label": name, "weight": 0})

    return {
        "name": name,
        "priority": info["priority"],
        "label": info["label"],
        "weight": info["weight"],
        "raw_pattern_count": len(raw_patterns),
        "compiled_pattern_count": len(compiled),
        "compiled": compiled,
        "skipped_patterns": skipped,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Gf-Patterns URL pattern-match — native Python wrapper."
    )
    p.add_argument(
        "--input", "-i",
        help="URL list file (one URL per line).  Reads from stdin if omitted.",
    )
    p.add_argument(
        "--output", "-o",
        help="Optional normalized JSON output file.",
    )
    p.add_argument(
        "--pattern",
        choices=list(PRIORITY_MAP.keys()),
        help="Run a single named pattern instead of all 14.",
    )
    p.add_argument(
        "--patterns-dir",
        default=str(DEFAULT_PATTERNS_DIR),
        help=f"Directory containing .json gf pattern definitions "
             f"(default: {DEFAULT_PATTERNS_DIR}).",
    )
    p.add_argument(
        "--min-priority",
        choices=PRIORITY_ORDER,
        default="P3",
        help="Only include patterns at or above this priority level "
             "(default: P3 = all).",
    )
    p.add_argument(
        "--dedup-per-pattern",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Deduplicate matched URLs within each pattern (default: on).",
    )
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()

    # --- validate patterns directory ------------------------------------------
    patterns_dir = Path(args.patterns_dir).expanduser()
    if not patterns_dir.is_dir():
        emit(
            {
                "ok": False,
                "error": {
                    "type": "patterns_dir_not_found",
                    "message": f"Patterns directory not found: {patterns_dir}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    # --- enumerate pattern names ----------------------------------------------
    if args.pattern:
        pattern_names = [args.pattern]
    else:
        pattern_names = sorted(
            p.stem
            for p in patterns_dir.glob("*.json")
            if p.stem in PRIORITY_MAP
        )

    if not pattern_names:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "no_patterns_found",
                    "message": f"No recognised gf patterns found in {patterns_dir}",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    min_prio_idx = PRIORITY_ORDER.index(args.min_priority)

    # --- load & filter patterns -----------------------------------------------
    patterns: list[dict[str, Any]] = []
    load_errors: list[dict[str, Any]] = []

    for name in pattern_names:
        path = patterns_dir / f"{name}.json"
        if not path.is_file():
            load_errors.append({"name": name, "error": f"file not found: {path}"})
            continue
        loaded = load_pattern_file(name, path)
        if "error" in loaded:
            load_errors.append(loaded)
            continue
        if PRIORITY_ORDER.index(loaded["priority"]) > min_prio_idx:
            continue
        patterns.append(loaded)

    if not patterns and load_errors:
        emit(
            {
                "ok": False,
                "error": {"type": "all_patterns_failed", "failures": load_errors},
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 3

    # --- read URLs ------------------------------------------------------------
    if args.input:
        try:
            urls = [
                line.strip()
                for line in Path(args.input).read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            emit(
                {
                    "ok": False,
                    "error": {"type": "input_read_error", "message": str(exc)},
                    "started_at": started_at,
                    "finished_at": utc_now(),
                },
                args.output,
            )
            return 2
    else:
        urls = [line.strip() for line in sys.stdin if line.strip()]

    if not urls:
        emit(
            {
                "ok": False,
                "error": {
                    "type": "no_urls",
                    "message": "No URLs provided (empty input).",
                },
                "started_at": started_at,
                "finished_at": utc_now(),
            },
            args.output,
        )
        return 2

    # --- match URLs against each loaded pattern -------------------------------
    match_data: list[dict[str, Any]] = []
    total_matches = 0

    for pat in patterns:
        compiled: list[re.Pattern[str]] = pat.pop("compiled")

        matched_urls: list[str] = []
        seen: set[str] = set()
        for url in urls:
            for cre in compiled:
                if cre.search(url):
                    if args.dedup_per_pattern:
                        if url in seen:
                            continue
                        seen.add(url)
                    matched_urls.append(url)
                    break  # one match per URL per pattern is sufficient

        skipped = pat.pop("skipped_patterns", [])
        entry: dict[str, Any] = {
            **pat,
            "skipped_pattern_count": len(skipped),
            "matched_url_count": len(matched_urls),
            "matched_urls": matched_urls,
        }
        if skipped:
            entry["skipped_patterns"] = skipped
        match_data.append(entry)
        total_matches += len(matched_urls)

    # --- sort: priority descending, then match count descending ---------------
    match_data.sort(
        key=lambda d: (PRIORITY_ORDER.index(d["priority"]), -d["matched_url_count"])
    )

    # --- priority summary -----------------------------------------------------
    summary: list[dict[str, Any]] = []
    for prio in PRIORITY_ORDER:
        group = [d for d in match_data if d["priority"] == prio]
        if not group:
            continue
        summary.append(
            {
                "priority": prio,
                "pattern_count": len(group),
                "total_matched_urls": sum(d["matched_url_count"] for d in group),
                "patterns": [d["name"] for d in group],
            }
        )

    # --- top candidates (P0 + P1 with hits) ----------------------------------
    top_candidates: list[dict[str, Any]] = []
    for d in match_data:
        if d["priority"] in ("P0", "P1") and d["matched_urls"]:
            top_candidates.append(
                {
                    "priority": d["priority"],
                    "pattern": d["name"],
                    "label": d["label"],
                    "sample_urls": d["matched_urls"][:5],
                }
            )

    # --- emit -----------------------------------------------------------------
    payload: dict[str, Any] = {
        "ok": True,
        "tool": "gf_pattern_match",
        "started_at": started_at,
        "finished_at": utc_now(),
        "input": {
            "source": args.input or "<stdin>",
            "total_urls": len(urls),
        },
        "patterns_dir": str(patterns_dir),
        "patterns_loaded": len(match_data),
        "total_matched_urls": total_matches,
        "priority_summary": summary,
        "top_candidates": top_candidates,
        "patterns": match_data,
    }
    if load_errors:
        payload["load_errors"] = load_errors

    emit(payload, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
