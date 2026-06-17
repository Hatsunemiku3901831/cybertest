#!/usr/bin/env python3
"""Build a single Markdown context bundle for another LLM."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_MAX_FILE_BYTES = 200_000
DEFAULT_DOCS = [
    "AGENTS.md",
    "agent/AGENT.md",
    "agent/skills/handoff-docs.md",
]
TEXT_SUFFIXES = {
    ".bash",
    ".conf",
    ".css",
    ".csv",
    ".go",
    ".graphql",
    ".html",
    ".http",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".md",
    ".py",
    ".sh",
    ".sql",
    ".svg",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_git(args: list[str]) -> str:
    try:
        completed = subprocess.run(["git", *args], check=False, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"[git command failed: {exc}]"
    output = (completed.stdout or "") + (completed.stderr or "")
    return output.strip() or "[empty]"


def has_git_repo() -> bool:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in sample


def fence_for(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    aliases = {"py": "python", "sh": "bash", "yml": "yaml", "md": "markdown", "txt": "text"}
    return aliases.get(suffix, suffix or "text")


def latest_task_dir(root: Path) -> Path:
    tasks_dir = root / "tasks"
    candidates = [path for path in tasks_dir.glob("20[0-9][0-9]-*") if path.is_dir()]
    if not candidates:
        raise SystemExit("No task directory found. Use --task-dir explicitly.")
    return sorted(candidates, key=lambda item: item.name)[-1]


def relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def build_tree(base: Path, root: Path, output_path: Path | None) -> list[str]:
    lines: list[str] = []
    for path in sorted(base.rglob("*")):
        if output_path and path.resolve() == output_path.resolve():
            continue
        rel = path.relative_to(base)
        depth = len(rel.parts) - 1
        prefix = "  " * depth + "- "
        label = rel.name + ("/" if path.is_dir() else "")
        size = "" if path.is_dir() else f" ({path.stat().st_size} bytes)"
        lines.append(f"{prefix}{label}{size}")
    if not lines:
        lines.append("[empty task directory]")
    return lines


def append_text_file(sections: list[str], path: Path, root: Path, max_file_bytes: int, full: bool) -> None:
    rel = relative(path, root)
    stat = path.stat()
    digest = sha256_file(path)
    sections.append(f"## File: {rel}")
    sections.append("")
    sections.append(f"- Size: {stat.st_size} bytes")
    sections.append(f"- SHA256: `{digest}`")
    if not is_text_file(path):
        sections.append("- Content: binary or non-text file, not embedded.")
        sections.append("")
        return
    data = path.read_bytes()
    truncated = False
    if not full and len(data) > max_file_bytes:
        data = data[:max_file_bytes]
        truncated = True
    text = data.decode("utf-8", errors="replace")
    if truncated:
        sections.append(f"- Content: truncated to first {max_file_bytes} bytes. Use --full to embed full text.")
    sections.append("")
    sections.append(f"```{fence_for(path)}")
    sections.append(text.rstrip())
    sections.append("```")
    sections.append("")


def collect_files(task_dir: Path, extra_files: list[str], root: Path, output_path: Path) -> list[Path]:
    paths: list[Path] = []
    for item in DEFAULT_DOCS + extra_files:
        path = (root / item).resolve()
        if path.exists() and path.is_file():
            paths.append(path)
    for path in sorted(task_dir.rglob("*")):
        if path.is_file() and path.resolve() != output_path.resolve():
            paths.append(path.resolve())
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export one Markdown file containing task context for another LLM.")
    parser.add_argument("--task-dir", help="Task archive directory. Defaults to latest tasks/20xx-* directory.")
    parser.add_argument("--output", help="Output Markdown file. Defaults to <task-dir>/outputs/llm-context-bundle.md.")
    parser.add_argument("--include", action="append", default=[], help="Extra repo-relative file to embed. Repeat as needed.")
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES, help="Per-file text embed limit.")
    parser.add_argument("--full", action="store_true", help="Embed full text files instead of truncating large files.")
    parser.add_argument("--no-git", action="store_true", help="Skip git status and recent commit metadata.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path.cwd().resolve()
    task_dir = (root / args.task_dir).resolve() if args.task_dir else latest_task_dir(root).resolve()
    if not task_dir.exists() or not task_dir.is_dir():
        print(f"Task directory not found: {task_dir}", file=sys.stderr)
        return 2
    output_path = Path(args.output).resolve() if args.output else task_dir / "outputs" / "llm-context-bundle.md"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sections: list[str] = [
        "# LLM Task Context Bundle",
        "",
        "用途：复制本文件全文给其它大模型，让它在不读取本地仓库的情况下理解当前任务。",
        "",
        "## Bundle Metadata",
        "",
        f"- Generated at UTC: `{utc_now()}`",
        f"- Repository root: `{root}`",
        f"- Task directory: `{relative(task_dir, root)}`",
        f"- Output file: `{relative(output_path, root)}`",
        "",
        "## Instructions For Receiving LLM",
        "",
        "- 先阅读项目规则和任务目录文件，再给出结论。",
        "- 区分事实、推断、未确认线索和需要追加授权的动作。",
        "- 安全测试内容仅限授权范围；不要建议破坏性操作或越界探测。",
        "- 如文件内容被截断，应基于已给内容分析，并明确缺口。",
        "",
        "## Task Directory Tree",
        "",
        "```text",
        *build_tree(task_dir, root, output_path),
        "```",
        "",
    ]

    if not args.no_git and has_git_repo():
        sections.extend(
            [
                "## Git Context",
                "",
                "### Status",
                "",
                "```text",
                run_git(["status", "--short"]),
                "```",
                "",
                "### Recent Commits",
                "",
                "```text",
                run_git(["log", "--oneline", "-5"]),
                "```",
                "",
            ]
        )
    elif not args.no_git:
        sections.extend(["## Git Context", "", "未检测到 git 仓库元数据，已跳过 git status 和 recent commits。", ""])

    sections.extend(["## Embedded Files", ""])
    for path in collect_files(task_dir, args.include, root, output_path):
        append_text_file(sections, path, root, args.max_file_bytes, args.full)

    output_path.write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")
    print(str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
