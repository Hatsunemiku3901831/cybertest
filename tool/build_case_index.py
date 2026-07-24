#!/usr/bin/env python3
"""Build the deterministic Cybertest anonymized case index.

The JSON index is the machine-readable source of truth.  The Markdown index is
always derived from the same in-memory representation and is never parsed back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tool.cybertest_core.schema_validation import (  # noqa: E402
    load_json_document,
    validate_instance,
)


DIMENSIONS = (
    "scene",
    "target_type",
    "technology",
    "business_object",
    "operation_type",
    "trust_boundary",
    "observed_signal",
    "root_cause_family",
    "evidence_mode",
    "required_material",
    "matched_tactics",
)


class CaseIndexError(ValueError):
    """Raised when a case cannot enter the reusable index."""


def canonical_json(document: Any) -> str:
    """Return stable, human-readable JSON with exactly one trailing newline."""

    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.name


def _relative_repo_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise CaseIndexError(
            f"case file is outside repository root: {path.name}"
        ) from exc


def _source_path(repo_root: Path, relative_path: str) -> Path:
    candidate = (repo_root / relative_path).resolve()
    try:
        candidate.relative_to(repo_root.resolve())
    except ValueError as exc:
        raise CaseIndexError(
            f"source path escapes repository root: {relative_path}"
        ) from exc
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_identity(source: dict[str, Any]) -> dict[str, str]:
    """Return the stable provenance identity, excluding mutable content hash."""

    return {
        "source_alias": source["source_alias"],
        "relative_path": Path(source["relative_path"]).as_posix(),
    }


def _ensure_unique_ids(
    items: Iterable[Any],
    *,
    field: str,
    case_id: str,
) -> None:
    identifiers = [
        item.get("id")
        for item in items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if len(identifiers) != len(set(identifiers)):
        raise CaseIndexError(f"{case_id}: duplicate id in {field}")


def validate_case(
    document: dict[str, Any],
    schema: dict[str, Any],
    *,
    label: str,
    repo_root: Path,
    verify_sources: bool,
) -> None:
    """Apply schema, provenance, and deterministic indexing checks."""

    errors = validate_instance(document, schema)
    if errors:
        rendered = "; ".join(errors)
        raise CaseIndexError(f"{label}: schema validation failed: {rendered}")

    case_id = document["id"]
    _ensure_unique_ids(
        document["effective_paths"],
        field="effective_paths",
        case_id=case_id,
    )
    _ensure_unique_ids(
        document["ineffective_paths"],
        field="ineffective_paths",
        case_id=case_id,
    )
    _ensure_unique_ids(
        document["request_matrix"],
        field="request_matrix",
        case_id=case_id,
    )

    source_identity_keys = [
        (
            source["source_alias"],
            Path(source["relative_path"]).as_posix(),
        )
        for source in document["sources"]
    ]
    if len(source_identity_keys) != len(set(source_identity_keys)):
        raise CaseIndexError(f"{case_id}: duplicate identity in sources")

    for source in document["sources"]:
        relative_path = source["relative_path"]
        if ".." in Path(relative_path).parts:
            raise CaseIndexError(
                f"{case_id}: source path must not contain '..': {relative_path}"
            )
        if not verify_sources:
            continue
        source_path = _source_path(repo_root, relative_path)
        if not source_path.is_file():
            raise CaseIndexError(
                f"{case_id}: source file is missing: {relative_path}"
            )
        actual = _sha256_file(source_path)
        if actual != source["sha256"]:
            raise CaseIndexError(
                f"{case_id}: source hash mismatch: {relative_path}"
            )


def discover_case_paths(cases_dir: Path) -> list[Path]:
    """Return case JSON files in a stable order, excluding generated indexes."""

    if not cases_dir.is_dir():
        raise CaseIndexError(f"case directory is missing: {cases_dir.name}")
    return sorted(
        path
        for path in cases_dir.rglob("*.json")
        if path.name != "index.json" and not path.name.startswith(".")
    )


def collect_cases(
    cases_dir: Path,
    schema_path: Path,
    *,
    repo_root: Path,
    verify_sources: bool = False,
) -> list[tuple[Path, dict[str, Any]]]:
    """Load and validate every source case."""

    schema = load_json_document(schema_path)
    records: list[tuple[Path, dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for path in discover_case_paths(cases_dir):
        document = load_json_document(path)
        if not isinstance(document, dict):
            raise CaseIndexError(f"{path.name}: case document must be an object")
        validate_case(
            document,
            schema,
            label=_display_path(path, repo_root),
            repo_root=repo_root,
            verify_sources=verify_sources,
        )
        case_id = document["id"]
        if case_id in seen_ids:
            raise CaseIndexError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        records.append((path, document))

    if not records:
        raise CaseIndexError("no case documents found")
    return records


def _dimension_values(document: dict[str, Any], dimension: str) -> list[str]:
    value = document[dimension]
    if isinstance(value, list):
        return sorted(value)
    return [value]


def build_index(
    records: Sequence[tuple[Path, dict[str, Any]]],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    """Build a stable multi-dimensional index."""

    case_entries: list[dict[str, Any]] = []
    dimension_map: dict[str, dict[str, list[str]]] = {
        dimension: {} for dimension in DIMENSIONS
    }

    for path, document in sorted(records, key=lambda item: item[1]["id"]):
        entry: dict[str, Any] = {
            "id": document["id"],
            "title": document["title"],
            "summary": document["summary"],
            "relative_path": _relative_repo_path(path, repo_root),
            "source_hashes": sorted(
                {source["sha256"] for source in document["sources"]}
            ),
            "source_identities": sorted(
                (_source_identity(source) for source in document["sources"]),
                key=lambda identity: (
                    identity["source_alias"],
                    identity["relative_path"],
                ),
            ),
            "anonymization_status": document["anonymization_check"]["status"],
            "evidence_contract": {
                "effective_path_count": len(document["effective_paths"]),
                "ineffective_path_count": len(document["ineffective_paths"]),
                "request_variant_count": len(document["request_matrix"]),
                "false_positive_filter_count": len(
                    document["false_positive_filters"]
                ),
                "evidence_invariant_count": len(document["evidence_invariants"]),
                "stop_condition_count": len(document["stop_conditions"]),
                "rollback_required": document["rollback"]["required"],
            },
        }
        for dimension in DIMENSIONS:
            entry[dimension] = document[dimension]
            for value in _dimension_values(document, dimension):
                dimension_map[dimension].setdefault(value, []).append(document["id"])
        case_entries.append(entry)

    normalized_dimensions = {
        dimension: {
            value: sorted(case_ids)
            for value, case_ids in sorted(values.items())
        }
        for dimension, values in dimension_map.items()
    }
    fingerprint_input = json.dumps(
        case_entries,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "schema_version": "1.0",
        "case_schema_version": "1.0",
        "case_count": len(case_entries),
        "content_sha256": hashlib.sha256(fingerprint_input).hexdigest(),
        "dimensions": normalized_dimensions,
        "cases": case_entries,
    }


def _markdown_cell(value: Any) -> str:
    if isinstance(value, list):
        rendered = ", ".join(str(item) for item in value)
    else:
        rendered = str(value)
    return rendered.replace("|", "\\|").replace("\n", " ")


def render_markdown(index: dict[str, Any]) -> str:
    """Render a deterministic human-readable view from ``index.json`` data."""

    lines = [
        "# Case Index",
        "",
        "> 由 `tool/build_case_index.py` 从结构化 case 确定性生成；"
        "`index.json` 是机器可读事实源。",
        "",
        f"- case 数量：{index['case_count']}",
        f"- 内容指纹：`{index['content_sha256']}`",
        "",
        "## Cases",
        "",
        "| ID | 标题 | 场景 | 根因家族 | 信任边界 | Tactic | 文件 |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in index["cases"]:
        lines.append(
            "| {id} | {title} | {scene} | {root} | {trust} | {tactics} | [{path}]({link}) |".format(
                id=_markdown_cell(case["id"]),
                title=_markdown_cell(case["title"]),
                scene=_markdown_cell(case["scene"]),
                root=_markdown_cell(case["root_cause_family"]),
                trust=_markdown_cell(case["trust_boundary"]),
                tactics=_markdown_cell(case["matched_tactics"]),
                path=_markdown_cell(case["relative_path"]),
                link=_markdown_cell(
                    Path(case["relative_path"]).relative_to("agent/cases").as_posix()
                ),
            )
        )

    lines.extend(["", "## 多维检索", ""])
    for dimension in DIMENSIONS:
        lines.extend(
            [
                f"### `{dimension}`",
                "",
                "| 值 | Case |",
                "|---|---|",
            ]
        )
        for value, case_ids in index["dimensions"][dimension].items():
            links = ", ".join(f"`{case_id}`" for case_id in case_ids)
            lines.append(f"| {_markdown_cell(value)} | {links} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="生成或校验 Cybertest 匿名 case 的 JSON/Markdown 多维索引。",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=REPO_ROOT / "agent" / "cases",
        help="case JSON 所在目录。",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=REPO_ROOT / "agent" / "schemas" / "case.schema.json",
        help="case JSON Schema。",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="用于解析来源和生成相对路径的仓库根目录。",
    )
    parser.add_argument("--output-json", type=Path, help="JSON 索引输出路径。")
    parser.add_argument("--output-md", type=Path, help="Markdown 索引输出路径。")
    parser.add_argument(
        "--verify-sources",
        action="store_true",
        help="校验每个来源相对路径和 SHA-256。",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="只检查已生成索引是否最新，不写文件。",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="只把拟生成的 JSON 输出到 stdout，不写文件。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    cases_dir = args.cases_dir
    output_json = args.output_json or cases_dir / "index.json"
    output_md = args.output_md or cases_dir / "index.md"

    try:
        records = collect_cases(
            cases_dir,
            args.schema,
            repo_root=args.repo_root,
            verify_sources=args.verify_sources,
        )
        index = build_index(records, repo_root=args.repo_root)
        json_text = canonical_json(index)
        markdown_text = render_markdown(index)

        if args.dry_run:
            sys.stdout.write(json_text)
            return 0

        if args.check:
            stale = []
            if not output_json.is_file() or output_json.read_text(
                encoding="utf-8"
            ) != json_text:
                stale.append(output_json.name)
            if not output_md.is_file() or output_md.read_text(
                encoding="utf-8"
            ) != markdown_text:
                stale.append(output_md.name)
            report = {
                "ok": not stale,
                "case_count": index["case_count"],
                "content_sha256": index["content_sha256"],
                "stale_outputs": stale,
            }
            sys.stdout.write(canonical_json(report))
            return 0 if not stale else 1

        _write_text(output_json, json_text)
        _write_text(output_md, markdown_text)
        sys.stdout.write(
            canonical_json(
                {
                    "ok": True,
                    "case_count": index["case_count"],
                    "content_sha256": index["content_sha256"],
                    "outputs": [output_json.name, output_md.name],
                }
            )
        )
        return 0
    except (CaseIndexError, OSError, ValueError) as exc:
        sys.stderr.write(canonical_json({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
