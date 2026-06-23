#!/usr/bin/env python3
"""Split the 2026-05-19 pentest task archive into per-target copies.

This script is intentionally one-off: it preserves the original task folder,
copies target-related files into tasks/rongshu/<target>/ with the same relative
layout, and rewrites known multi-target Markdown ledgers into target-scoped
versions at the same relative paths.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "tasks" / "2026-05-19-1540-xskj-pentest"
DEST = REPO / "tasks" / "rongshu"


@dataclass(frozen=True)
class Target:
    key: str
    dirname: str
    unit: str
    system: str
    url: str
    aliases: tuple[str, ...]
    evidence_terms: tuple[str, ...]


TARGETS: tuple[Target, ...] = (
    Target(
        key="pyps",
        dirname="01-广州市番禺区财政投资评审管理系统",
        unit="广州市番禺区财政局",
        system="广州市番禺区财政投资评审管理系统",
        url="https://pyps.work:8089/pycp/",
        aliases=(
            "pyps",
            "pycp",
            "pyps.work",
            "www.pyps.work",
            "218.20.201.58",
            "pageoffice",
            "poserver",
            "loginseal",
            "adminseal",
            "sealimage",
            "poseal",
            "ueditor-tomcat",
            "财政投资评审",
            "番禺区财政投资评审",
        ),
        evidence_terms=(
            "01-pyps",
            "pyps-",
            "pyps_",
            "pyps.work",
            "www.pyps.work",
            "pycp",
            "pageoffice",
            "poserver",
            "loginseal",
            "adminseal",
            "sealimage",
            "sealsetup",
            "posetup",
            "webbuilder",
        ),
    ),
    Target(
        key="seeyon",
        dirname="02-办公协同系统",
        unit="广州市番禺信息技术投资发展有限公司",
        system="办公协同系统",
        url="http://183.6.42.97:8090/seeyon/main.do",
        aliases=(
            "seeyon",
            "183.6.42.97",
            "致远",
            "协同办公",
            "办公协同",
            "a8+",
            "v8.1sp2",
            "v8_1sp2",
            "adddate",
        ),
        evidence_terms=(
            "02-seeyon",
            "seeyon",
            "zhiyuan",
            "adddate",
            "a8",
            "183.6.42.97",
        ),
    ),
    Target(
        key="pyitid",
        dirname="03-广州市番禺信息技术投资发展有限公司官网",
        unit="广州市番禺信息技术投资发展有限公司",
        system="官网",
        url="http://www.pyitid.com/",
        aliases=(
            "pyitid",
            "www.pyitid.com",
            "www.pyitid.cn",
            "mail.pyitid.com",
            "pyxt.aiorange.cn",
            "pyxt",
            "aiorange",
            "120.78.143.173",
            "coremail",
            "信投官网",
            "番禺信息技术投资发展有限公司官网",
        ),
        evidence_terms=(
            "03-pyitid",
            "pyitid",
            "coremail",
            "pyxt",
            "aiorange",
            "ip120",
            "nmap-120",
            "120.78.143.173",
        ),
    ),
    Target(
        key="pypfjt",
        dirname="04-广州市番禺区番发集团有限公司官网",
        unit="广州市番禺区番发集团有限公司",
        system="官网",
        url="http://www.pypfjt.com/",
        aliases=(
            "pypfjt",
            "www.pypfjt.com",
            "番发",
            "番发集团",
            "yoyoli",
            "114.80.208.28",
            "lhs123",
            "www.lhs123.cn",
            "baomogarden",
            "www.baomogarden.net",
            "panyuhotel",
            "pypanan",
            "lxhd001",
            "lxhd",
            "pypfly",
            "thinkphp",
            "thinkcmf",
            "wordpress",
            "metinfo",
        ),
        evidence_terms=(
            "04-pypfjt",
            "pypfjt",
            "pypfjt.com",
            "pypfly",
            "yoyoli",
            "lhs",
            "lhs123",
            "baomogarden",
            "panyuhotel",
            "pypanan",
            "lxhd001",
            "lxhd",
            "114.80.208.28",
            "thinkphp",
            "thinkcmf",
            "wordpress",
        ),
    ),
    Target(
        key="park",
        dirname="05-番禺工业园经济总部智慧园区管理平台",
        unit="广州市番禺新投资有限公司",
        system="番禺工业园经济总部智慧园区管理平台",
        url="https://119.130.61.58/",
        aliases=(
            "119.130.61.58",
            "park",
            "feparks",
            "jfinal",
            "attachid",
            "oss/uploadprevfilelocal",
            "智慧园区",
            "工业园",
            "番禺新投资",
            "广州市番盈新投资有限公司",
            "wx.yyzcyy.cn",
        ),
        evidence_terms=(
            "05-park",
            "park",
            "119.130.61.58",
            "feparks",
            "attachid",
            "oss-upload",
            "uploadprevfile",
            "jfinal",
        ),
    ),
    Target(
        key="water",
        dirname="06-广州市番禺水务投资集团有限公司官网",
        unit="广州市番禺水务投资集团有限公司",
        system="官网",
        url="http://panyuwater.cn/",
        aliases=(
            "panyuwater",
            "panyuwater.cn",
            "106.55.55.25",
            "水务",
            "番禺水务",
            "asp.net 2.0",
        ),
        evidence_terms=(
            "06-water",
            "water",
            "panyuwater",
            "106.55.55.25",
        ),
    ),
    Target(
        key="lsy",
        dirname="07-番粮粮食云",
        unit="珠江粮油公司及其下属公司",
        system="番粮粮食云",
        url="https://lsy.pylscb.com/#/",
        aliases=(
            "lsy",
            "lsy.pylscb.com",
            "pylscb",
            "139.159.234.199",
            "番粮",
            "粮食云",
            "rabbitmq",
            "stomp",
            "artemis",
            "video-platform",
            "dahua",
            "camera",
            "摄像头",
            "cloud-data-center",
            "cloud-business",
            "wrzs",
            "znlk",
            "datastocksync",
            "stock sync",
            "粮油",
        ),
        evidence_terms=(
            "07-lsy",
            "lsy",
            "pylscb",
            "rabbitmq",
            "stomp",
            "artemis",
            "video-platform",
            "dahua",
            "camera",
            "cloud-data-center",
            "cloud-business",
            "wrzs",
            "znlk",
            "datastock",
            "storehouse",
            "weigh",
        ),
    ),
)

TARGET_BY_KEY = {target.key: target for target in TARGETS}
COMMON_TOP_DIRS = ("inputs", "outputs", "evidence", "notes", "temporarytool")
GLOBAL_COPY = {
    Path("inputs/authorization.md"),
    Path("inputs/authorization.pdf"),
    Path("evidence/authorization.pdf.png"),
}
GLOBAL_PREFIXES = (
    Path("evidence/auth-pages"),
    Path("evidence/rendered-auth"),
)
SPECIAL_REL_TARGETS: dict[Path, tuple[str, ...]] = {
    Path("inputs/asp-cms-sensitive-paths.txt"): ("pyitid", "water"),
    Path("inputs/editor-upload-probe-paths.txt"): ("pyitid", "water"),
    Path("outputs/nuclei-exposure-files-high.json"): tuple(target.key for target in TARGETS),
    Path("temporarytool/extract_pdf_page_images.py"): tuple(target.key for target in TARGETS),
    Path("temporarytool/render_pdf_pages.swift"): tuple(target.key for target in TARGETS),
    Path("temporarytool/http_route_probe_nofollow.py"): tuple(target.key for target in TARGETS),
    Path("temporarytool/safe_path_probe.py"): tuple(target.key for target in TARGETS),
    Path("temporarytool/socket_service_probe.py"): tuple(target.key for target in TARGETS),
    Path("temporarytool/sqlmap_targeted.py"): tuple(target.key for target in TARGETS),
}
SPLIT_MARKDOWN = {
    Path("outputs/vulnerability-archive.md"),
    Path("outputs/asset-inventory-detailed.md"),
    Path("outputs/agent-handoff-pentest-status.md"),
    Path("outputs/llm-context-bundle.md"),
    Path("inputs/previous-recon-summary.md"),
    Path("inputs/previous-targets.md"),
    Path("inputs/scope.md"),
    Path("retrospective.md"),
}
SKIP_NAMES = {".DS_Store"}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, text: str, dry_run: bool) -> None:
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def copy_file(src: Path, dst: Path, dry_run: bool) -> None:
    if dry_run:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def target_dir(target: Target) -> Path:
    return DEST / target.dirname


def normalized_for_match(value: str) -> str:
    return value.lower().replace("\\", "/")


def sample_file_text(path: Path, limit: int = 131_072) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace").lower()


def match_target_in_text(text: str, target: Target) -> bool:
    needle = normalized_for_match(text)
    return any(term.lower() in needle for term in target.aliases)


def classify_by_string(value: str, strong_only: bool = False) -> set[str]:
    normalized = normalized_for_match(value)
    keys: set[str] = set()
    for target in TARGETS:
        terms = target.evidence_terms if strong_only else target.evidence_terms + target.aliases
        if any(term.lower() in normalized for term in terms):
            keys.add(target.key)
    return keys


def classify_file(path: Path) -> set[str]:
    rel = path.relative_to(SOURCE)
    rel_str = rel.as_posix()
    keys = classify_by_string(rel_str, strong_only=True)
    if keys:
        return keys

    sample = sample_file_text(path)
    if not sample:
        return set()
    return {
        target.key
        for target in TARGETS
        if any(term.lower() in sample for term in target.aliases)
    }


def split_h2_sections(text: str) -> tuple[str, list[tuple[str, str]]]:
    pattern = re.compile(r"(?m)^## .*$")
    matches = list(pattern.finditer(text))
    if not matches:
        return text, []
    intro = text[: matches[0].start()].rstrip() + "\n"
    sections: list[tuple[str, str]] = []
    for idx, match in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        chunk = text[match.start() : end].strip() + "\n"
        heading = match.group(0)
        sections.append((heading, chunk))
    return intro, sections


def split_h3_chunks(section: str) -> tuple[str, list[tuple[str, str]]]:
    pattern = re.compile(r"(?m)^### .*$")
    matches = list(pattern.finditer(section))
    if not matches:
        return section, []
    prefix = section[: matches[0].start()].rstrip() + "\n"
    chunks: list[tuple[str, str]] = []
    for idx, match in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(section)
        chunk = section[match.start() : end].strip() + "\n"
        chunks.append((match.group(0), chunk))
    return prefix, chunks


def target_note(target: Target, source_rel: Path) -> str:
    return (
        f"\n> 本文件从 `tasks/2026-05-19-1540-xskj-pentest/{source_rel.as_posix()}` "
        f"按目标 `{target.system}` 拆分生成；原始文件保留在原任务目录。\n\n"
    )


def classify_markdown_chunk(chunk: str) -> set[str]:
    return {
        target.key
        for target in TARGETS
        if any(term.lower() in chunk.lower() for term in target.aliases + target.evidence_terms)
    }


def filter_table_or_paragraph_section(section: str, target: Target) -> str:
    lines = section.splitlines()
    if not lines:
        return ""

    kept: list[str] = [lines[0]]
    table_header: list[str] = []
    paragraph: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if not paragraph:
            return
        block = "\n".join(paragraph)
        if match_target_in_text(block, target):
            if kept and kept[-1] != "":
                kept.append("")
            kept.extend(paragraph)
        paragraph = []

    for line in lines[1:]:
        stripped = line.strip()
        if stripped.startswith("|"):
            flush_paragraph()
            if re.match(r"^\|\s*-", stripped) or not table_header:
                table_header.append(line)
                if len(table_header) <= 2:
                    kept.append(line)
                continue
            if match_target_in_text(line, target):
                kept.append(line)
            continue

        if stripped == "":
            flush_paragraph()
            if kept and kept[-1] != "":
                kept.append("")
            continue

        paragraph.append(line)

    flush_paragraph()
    text = "\n".join(kept).rstrip() + "\n"
    return text if match_target_in_text(text, target) or len(kept) > 1 else ""


def split_generic_markdown(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    intro, sections = split_h2_sections(text)
    output = [intro.rstrip(), target_note(target, rel)]

    for _, section in sections:
        prefix, h3_chunks = split_h3_chunks(section)
        if h3_chunks:
            section_parts: list[str] = []
            filtered_prefix = filter_table_or_paragraph_section(prefix, target)
            if filtered_prefix.strip():
                section_parts.append(filtered_prefix.rstrip())
            for _, chunk in h3_chunks:
                if match_target_in_text(chunk, target):
                    section_parts.append(chunk.rstrip())
            if section_parts:
                output.append("\n\n".join(section_parts))
            continue

        filtered = filter_table_or_paragraph_section(section, target)
        if filtered.strip():
            output.append(filtered.rstrip())

    if len(output) <= 2:
        output.append("未在原文件中检出该目标的专属段落。\n")
    return "\n\n".join(part.rstrip() for part in output if part is not None).rstrip() + "\n"


def split_vulnerability_archive(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    intro, sections = split_h2_sections(text)
    output = [intro.rstrip(), target_note(target, rel)]

    for heading, section in sections:
        if heading == "## 维护规则":
            output.append(section.rstrip())
            continue
        if heading == "## 风险总览":
            filtered = filter_table_or_paragraph_section(section, target)
            if filtered.strip():
                output.append(filtered.rstrip())
            continue
        if heading.startswith(("## VULN-", "## RISK-")):
            if match_target_in_text(section, target):
                output.append(section.rstrip())
            continue
        if heading == "## 已测未确认或已降级方向":
            filtered = filter_table_or_paragraph_section(section, target)
            if filtered.strip():
                output.append(filtered.rstrip())

    if len(output) <= 2:
        output.append("未在漏洞总账中检出该目标的专属风险段落。\n")
    return "\n\n".join(output).rstrip() + "\n"


def split_asset_inventory(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    intro, sections = split_h2_sections(text)
    output = [intro.rstrip(), target_note(target, rel)]
    h3_target = {
        "### 3.1": "pyps",
        "### 3.2": "seeyon",
        "### 3.3": "pyitid",
        "### 3.4": "pypfjt",
        "### 3.5": "park",
        "### 3.6": "water",
        "### 3.7": "lsy",
    }

    for heading, section in sections:
        if heading.startswith(("## 1.", "## 2.")):
            filtered = filter_table_or_paragraph_section(section, target)
            if filtered.strip():
                output.append(filtered.rstrip())
            continue

        if heading.startswith("## 3."):
            prefix, h3_chunks = split_h3_chunks(section)
            parts = [prefix.rstrip()] if prefix.strip() else []
            for h3_heading, chunk in h3_chunks:
                owner = next((key for prefix_key, key in h3_target.items() if h3_heading.startswith(prefix_key)), None)
                if owner == target.key:
                    parts.append(chunk.rstrip())
            if len(parts) > 1:
                output.append("\n\n".join(parts))
            continue

        if heading.startswith("## 7."):
            if target.key == "pypfjt":
                output.append(section.rstrip())
            continue

        filtered = filter_table_or_paragraph_section(section, target)
        if filtered.strip():
            output.append(filtered.rstrip())

    if len(output) <= 2:
        output.append("未在资产文档中检出该目标的专属资产段落。\n")
    return "\n\n".join(output).rstrip() + "\n"


def split_previous_recon(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    intro, sections = split_h2_sections(text)
    output = [intro.rstrip(), target_note(target, rel)]
    h2_target = {
        "## 1.": "pyps",
        "## 3.": "pypfjt",
        "## 4.": "park",
        "## 5.": "water",
        "## 6.": "lsy",
    }

    for heading, section in sections:
        owner = next((key for prefix_key, key in h2_target.items() if heading.startswith(prefix_key)), None)
        if owner:
            if owner == target.key:
                output.append(section.rstrip())
            continue

        if heading.startswith("## 2."):
            prefix, h3_chunks = split_h3_chunks(section)
            parts = [prefix.rstrip()] if prefix.strip() else []
            for h3_heading, chunk in h3_chunks:
                if target.key == "seeyon" and "OA" in h3_heading:
                    parts.append(chunk.rstrip())
                if target.key == "pyitid" and "官网" in h3_heading:
                    parts.append(chunk.rstrip())
            if len(parts) > 1:
                output.append("\n\n".join(parts))
            continue

        filtered = filter_table_or_paragraph_section(section, target)
        if filtered.strip():
            output.append(filtered.rstrip())

    if len(output) <= 2:
        output.append("未在前期信息收集摘要中检出该目标的专属段落。\n")
    return "\n\n".join(output).rstrip() + "\n"


def split_scope(target: Target) -> str:
    return f"""# Scope

Authorization source: `inputs/authorization.md`

Window: 2026-05-18 00:00 to 2026-05-24 23:59.

Authorized tester/source IP: 120.236.117.181. This is the tester-side address and is excluded from target scanning.

In-scope internet system for this archive:

1. `{target.url}`
   - 单位：{target.unit}
   - 系统名称：{target.system}

Associated public assets are included only when the original task evidence or reports explicitly tied them to this target.

Constraints from authorization:

- No denial-of-service attacks.
- No system restart or shutdown.
- No adding, modifying, or deleting system files/data unless separately approved.
- Sensitive files/data may be accessed only to the minimum extent needed to prove impact.

Operational level recorded in the original task:

- Enhanced active validation, template scanning, endpoint enumeration, and safe vulnerability probes.
- Avoid destructive payloads, credential attacks, data modification, and bulk sensitive data access.
"""


def split_previous_targets(target: Target) -> str:
    return f"""# Targets

1. {target.system}
   - {target.url}
   - 单位：{target.unit}

## Operating Boundaries

- Scope is limited to the asset above and directly linked public pages or associated assets proven in the original archive.
- This file was split from `tasks/2026-05-19-1540-xskj-pentest/inputs/previous-targets.md`.
- Original archive files are preserved in place.
"""


def split_llm_context_bundle(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    marker = "\n## File: "
    if marker not in text:
        return split_generic_markdown(src, target)

    pre, embedded = text.split(marker, 1)
    pieces = [pre.rstrip(), target_note(target, rel).rstrip(), "## Embedded Files"]
    for raw_section in embedded.split(marker):
        section = "## File: " + raw_section
        first_line = section.splitlines()[0]
        file_path = first_line.replace("## File: ", "", 1).strip()
        file_keys = classify_by_string(file_path, strong_only=True)
        if target.key in file_keys or (not file_keys and match_target_in_text(section[:200_000], target)):
            pieces.append(section.rstrip())
    if len(pieces) == 3:
        pieces.append("未在原 LLM 上下文包中检出该目标的专属嵌入文件。")
    return "\n\n".join(pieces).rstrip() + "\n"


def split_markdown_file(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    if rel == Path("outputs/vulnerability-archive.md"):
        return split_vulnerability_archive(src, target)
    if rel == Path("outputs/asset-inventory-detailed.md"):
        return split_asset_inventory(src, target)
    if rel == Path("inputs/previous-recon-summary.md"):
        return split_previous_recon(src, target)
    if rel == Path("inputs/scope.md"):
        return split_scope(target)
    if rel == Path("inputs/previous-targets.md"):
        return split_previous_targets(target)
    if rel == Path("outputs/llm-context-bundle.md"):
        return split_llm_context_bundle(src, target)
    return split_generic_markdown(src, target)


def split_text_lines(src: Path, target: Target) -> str:
    rel = src.relative_to(SOURCE)
    text = read_text(src)
    kept = [line for line in text.splitlines() if match_target_in_text(line, target)]
    if not kept:
        return ""
    header = f"# Split from `{rel.as_posix()}` for `{target.system}`\n\n"
    return header + "\n".join(kept).rstrip() + "\n"


def should_skip(path: Path) -> bool:
    return any(part in SKIP_NAMES for part in path.parts)


def ensure_skeleton(dry_run: bool) -> None:
    if dry_run:
        return
    DEST.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        base = target_dir(target)
        base.mkdir(parents=True, exist_ok=True)
        for dirname in COMMON_TOP_DIRS:
            (base / dirname).mkdir(exist_ok=True)


def clean_destination(dry_run: bool) -> None:
    if dry_run or not DEST.exists():
        return
    for target in TARGETS:
        path = target_dir(target)
        if path.exists():
            shutil.rmtree(path)
    summary = DEST / "_split-summary.md"
    if summary.exists():
        summary.unlink()


def process_file(src: Path, dry_run: bool, stats: dict[str, dict[str, int]], unclassified: list[Path]) -> None:
    rel = src.relative_to(SOURCE)
    if should_skip(rel):
        return

    if rel in GLOBAL_COPY or any(rel.is_relative_to(prefix) for prefix in GLOBAL_PREFIXES):
        for target in TARGETS:
            copy_file(src, target_dir(target) / rel, dry_run)
            stats[target.key]["copied"] += 1
        return

    if rel in SPECIAL_REL_TARGETS:
        for key in SPECIAL_REL_TARGETS[rel]:
            target = TARGET_BY_KEY[key]
            copy_file(src, target_dir(target) / rel, dry_run)
            stats[key]["copied"] += 1
        return

    if rel in SPLIT_MARKDOWN:
        for target in TARGETS:
            content = split_markdown_file(src, target)
            write_text(target_dir(target) / rel, content, dry_run)
            stats[target.key]["split_docs"] += 1
        return

    keys = classify_file(src)
    if not keys:
        unclassified.append(rel)
        return

    if src.suffix.lower() in {".md", ".txt"} and len(keys) > 1:
        for key in keys:
            target = TARGET_BY_KEY[key]
            content = split_generic_markdown(src, target) if src.suffix.lower() == ".md" else split_text_lines(src, target)
            if content.strip():
                write_text(target_dir(target) / rel, content, dry_run)
                stats[key]["split_docs"] += 1
        return

    for key in keys:
        target = TARGET_BY_KEY[key]
        copy_file(src, target_dir(target) / rel, dry_run)
        stats[key]["copied"] += 1


def build_summary(stats: dict[str, dict[str, int]], unclassified: list[Path], dry_run: bool) -> str:
    lines = [
        "# Rongshu Split Summary",
        "",
        f"Source: `{SOURCE.relative_to(REPO).as_posix()}`",
        f"Destination: `{DEST.relative_to(REPO).as_posix()}`",
        f"Mode: {'dry-run' if dry_run else 'copy'}",
        "",
        "| Target | Directory | Copied files | Split/generated docs |",
        "| --- | --- | ---: | ---: |",
    ]
    for target in TARGETS:
        item = stats[target.key]
        label = f"{target.unit} / {target.system}"
        lines.append(
            f"| {label} | `{target.dirname}` | {item['copied']} | {item['split_docs']} |"
        )
    lines.extend(["", "## Unclassified Files", ""])
    if unclassified:
        lines.extend(f"- `{path.as_posix()}`" for path in sorted(unclassified))
    else:
        lines.append("- None")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="classify without writing files")
    parser.add_argument("--clean", action="store_true", help="remove generated target directories before writing")
    args = parser.parse_args()

    if not SOURCE.is_dir():
        raise SystemExit(f"source task directory not found: {SOURCE}")

    if args.clean:
        clean_destination(args.dry_run)
    ensure_skeleton(args.dry_run)
    stats = {target.key: {"copied": 0, "split_docs": 0} for target in TARGETS}
    unclassified: list[Path] = []

    for root, dirs, files in os.walk(SOURCE):
        dirs.sort()
        files.sort()
        for filename in files:
            process_file(Path(root) / filename, args.dry_run, stats, unclassified)

    summary = build_summary(stats, unclassified, args.dry_run)
    write_text(DEST / "_split-summary.md", summary, args.dry_run)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
