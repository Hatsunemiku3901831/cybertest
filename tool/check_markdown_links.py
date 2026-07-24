#!/usr/bin/env python3
"""Check repository-local Markdown links without network access."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import unquote, urlsplit


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOTS = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "CLAUDE.md",
    REPO_ROOT / "agent" / "AGENT.md",
    REPO_ROOT / "agent" / "capabilities",
    REPO_ROOT / "agent" / "cases",
    REPO_ROOT / "agent" / "memory",
    REPO_ROOT / "agent" / "policies",
    REPO_ROOT / "agent" / "references",
    REPO_ROOT / "agent" / "skills",
    REPO_ROOT / "agent" / "tactics",
    REPO_ROOT / "require",
)
IGNORED_PARTS = {
    ".git",
    ".idea",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "tasks",
}
LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)\n]+)\)")
SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
LINE_SUFFIX_PATTERN = re.compile(r":\d+(?::\d+)?$")


class MarkdownLinkError(ValueError):
    """Raised for invalid scan input."""


def _iter_markdown(paths: Iterable[Path]) -> list[Path]:
    discovered: set[Path] = set()
    for root in paths:
        if not root.exists():
            raise MarkdownLinkError(f"scan path is missing: {root.name}")
        candidates = [root] if root.is_file() else root.rglob("*.md")
        for path in candidates:
            if not path.is_file() or path.suffix.lower() != ".md":
                continue
            if any(part in IGNORED_PARTS for part in path.parts):
                continue
            discovered.add(path.resolve())
    return sorted(discovered)


def _display_path(path: Path, repo_root: Path = REPO_ROOT) -> str:
    try:
        return path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def _link_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith("<"):
        closing = target.find(">")
        return target[1:closing] if closing >= 0 else target[1:]
    return target.split(maxsplit=1)[0]


def _local_path(target: str) -> str | None:
    if not target or target.startswith("#") or SCHEME_PATTERN.match(target):
        return None
    parsed = urlsplit(target)
    path = unquote(parsed.path)
    if not path:
        return None
    return LINE_SUFFIX_PATTERN.sub("", path)


def check_paths(
    paths: Iterable[Path],
    *,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    files = _iter_markdown(paths)
    checked_links = 0
    external_links = 0
    broken: list[dict[str, Any]] = []
    for document in files:
        text = document.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in LINK_PATTERN.finditer(line):
                target = _link_target(match.group(1))
                relative = _local_path(target)
                if relative is None:
                    external_links += 1
                    continue
                checked_links += 1
                candidate = Path(relative)
                if candidate.is_absolute():
                    exists = False
                    reason = "absolute_local_link"
                else:
                    exists = (document.parent / candidate).resolve().exists()
                    reason = "missing_target"
                if not exists:
                    broken.append(
                        {
                            "path": _display_path(document, repo_root),
                            "line": line_number,
                            "target": target,
                            "reason": reason,
                        }
                    )
    return {
        "schema_version": "1.0",
        "ok": not broken,
        "scanned_file_count": len(files),
        "checked_local_link_count": checked_links,
        "ignored_external_or_anchor_count": external_links,
        "broken_link_count": len(broken),
        "broken_links": broken,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="离线检查 Cybertest Markdown 相对链接目标是否存在。",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="待检查的 Markdown 文件或目录；省略时检查项目文档。",
    )
    parser.add_argument("--output", type=Path, help="可选 JSON 输出路径。")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只输出检查结果，不写 --output。",
    )
    parser.add_argument(
        "--fail-on-broken",
        action="store_true",
        help="存在失效相对链接时返回退出码 1。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = check_paths(args.paths or DEFAULT_ROOTS)
        if args.dry_run:
            report["dry_run"] = True
            if args.output:
                report["would_write"] = args.output.name
        rendered = json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        if args.output and not args.dry_run:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        sys.stdout.write(rendered)
        if report["broken_link_count"] and args.fail_on_broken:
            return 1
        return 0
    except (MarkdownLinkError, OSError, ValueError) as exc:
        sys.stderr.write(
            json.dumps(
                {"ok": False, "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
