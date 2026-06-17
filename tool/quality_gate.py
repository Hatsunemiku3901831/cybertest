#!/usr/bin/env python3
"""
Quality gate for cybertest scan pipeline runs.

Checks whether required reconnaissance phases completed, skipped,
or failed, and emits JSON plus an optional Markdown report.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MODE_REQUIREMENTS: dict[str, list[str]] = {
    "quick": ["subfinder", "dnsx", "httpx", "katana", "gf", "nuclei"],
    "full": ["subfinder", "dnsx", "httpx", "tlsx", "naabu", "nmap", "katana", "history", "gf", "nuclei", "ffuf"],
    "deep": [
        "subfinder",
        "dnsx",
        "httpx",
        "tlsx",
        "naabu",
        "nmap",
        "katana",
        "history",
        "gf",
        "nuclei",
        "ffuf",
    ],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# 质量门禁",
        "",
        f"- 模式：`{payload.get('mode')}`",
        f"- 状态：`{payload.get('status')}`",
        f"- 结论：{payload.get('conclusion')}",
        "",
        "| 阶段 | 状态 | 说明 | 证据 |",
        "|---|---|---|---|",
    ]
    for item in payload.get("checks", []):
        lines.append(
            f"| `{item['phase']}` | `{item['status']}` | {item.get('message', '')} | `{item.get('output_file', '')}` |"
        )
    lines.append("")
    if payload.get("blocking_gaps"):
        lines.append("## 阻塞项")
        lines.append("")
        for item in payload["blocking_gaps"]:
            lines.append(f"- `{item['phase']}`：{item.get('message', '')}")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate scan pipeline quality gate.")
    parser.add_argument("--pipeline-dir", required=True, help="Pipeline output directory containing pipeline_state.json.")
    parser.add_argument("--mode", choices=["quick", "full", "deep"], help="Override scan mode.")
    parser.add_argument("--output", help="Optional JSON output path.")
    parser.add_argument("--markdown-output", help="Optional Markdown output path.")
    parser.add_argument("--strict", action="store_true", help="Treat skipped required phases as FAIL instead of WARN.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    pipeline_dir = Path(args.pipeline_dir)
    state_path = pipeline_dir / "pipeline_state.json"
    state = read_json(state_path)
    mode = args.mode or state.get("mode", "full")
    required = MODE_REQUIREMENTS.get(mode, MODE_REQUIREMENTS["full"])
    phase_outputs = state.get("phase_outputs", {})

    checks: list[dict[str, Any]] = []
    blocking: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for phase in required:
        details = phase_outputs.get(phase)
        if not details:
            item = {
                "phase": phase,
                "status": "FAIL",
                "message": "required phase was not executed",
                "output_file": "",
            }
            checks.append(item)
            blocking.append(item)
            continue
        if details.get("ok"):
            item = {
                "phase": phase,
                "status": "PASS",
                "message": details.get("summary", "completed"),
                "output_file": details.get("output_file", ""),
            }
            checks.append(item)
            continue
        skipped = bool(details.get("skipped"))
        status = "FAIL" if args.strict or not skipped else "WARN"
        item = {
            "phase": phase,
            "status": status,
            "message": details.get("error", "phase did not complete"),
            "output_file": details.get("output_file", ""),
        }
        checks.append(item)
        if status == "FAIL":
            blocking.append(item)
        else:
            warnings.append(item)

    status = "PASS"
    conclusion = "Required reconnaissance phases completed."
    if blocking:
        status = "FAIL"
        conclusion = "Required reconnaissance phases are missing or failed; do not claim all directions are exhausted."
    elif warnings:
        status = "WARN"
        conclusion = "Core flow ran with skipped phases; document gaps before claiming coverage."

    payload = {
        "ok": status != "FAIL",
        "tool": "quality_gate",
        "started_at": started_at,
        "finished_at": utc_now(),
        "pipeline_dir": str(pipeline_dir),
        "state_file": str(state_path),
        "mode": mode,
        "status": status,
        "conclusion": conclusion,
        "checks": checks,
        "blocking_gaps": blocking,
        "warnings": warnings,
    }

    if args.output:
        write_json(Path(args.output), payload)
    if args.markdown_output:
        write_markdown(Path(args.markdown_output), payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
