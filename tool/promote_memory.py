#!/usr/bin/env python3
"""Generate auditable memory-promotion recommendations from a case index.

This tool deliberately writes recommendation JSON only.  It never creates or
modifies a stable skill, Agent rule, tactic, or memory document.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SELECTION_RULE = (
    "按分组字段聚合同一匿名 case index；只根据独立 case、稳定来源身份、"
    "场景、技术和证据契约完整性提出晋升建议；来源 hash 仅用于溯源，"
    "不自动写入稳定 skill。"
)
GROUP_FIELDS = (
    "matched_tactics",
    "root_cause_family",
    "scene",
)


class PromotionError(ValueError):
    """Raised when the case index cannot support an auditable recommendation."""


def canonical_json(document: Any) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _as_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _contract_complete(case: dict[str, Any]) -> bool:
    contract = case.get("evidence_contract", {})
    return (
        case.get("anonymization_status") == "passed"
        and contract.get("effective_path_count", 0) >= 1
        and contract.get("ineffective_path_count", 0) >= 1
        and contract.get("request_variant_count", 0) >= 3
        and contract.get("false_positive_filter_count", 0) >= 1
        and contract.get("evidence_invariant_count", 0) >= 1
        and contract.get("stop_condition_count", 0) >= 1
    )


def _source_identity_set(case: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    identities = case.get("source_identities")
    if not isinstance(identities, list) or not identities:
        raise PromotionError(
            f"{case.get('id', '<unknown>')}: missing source identities"
        )

    normalized: list[tuple[str, str]] = []
    for identity in identities:
        if not isinstance(identity, dict):
            raise PromotionError(
                f"{case.get('id', '<unknown>')}: invalid source identity"
            )
        source_alias = identity.get("source_alias")
        relative_path = identity.get("relative_path")
        if not isinstance(source_alias, str) or not source_alias:
            raise PromotionError(
                f"{case.get('id', '<unknown>')}: invalid source alias"
            )
        if not isinstance(relative_path, str) or not relative_path:
            raise PromotionError(
                f"{case.get('id', '<unknown>')}: invalid source relative path"
            )
        normalized.append((source_alias, Path(relative_path).as_posix()))
    return tuple(sorted(set(normalized)))


def _recommended_stage(
    *,
    case_count: int,
    independent_source_count: int,
    scene_count: int,
    technology_count: int,
    all_contracts_complete: bool,
    minimum_cases: int,
) -> tuple[str, list[str]]:
    blockers: list[str] = []
    if case_count < minimum_cases:
        blockers.append(f"独立 case 少于 {minimum_cases} 个")
        return "draft_pattern", blockers
    if independent_source_count < 2:
        blockers.append("独立 case 的稳定来源身份集合少于 2 组")
        return "draft_pattern", blockers
    if not all_contracts_complete:
        blockers.append("至少一个 case 的负控、不变量或停止条件不完整")
        return "draft_pattern", blockers
    if case_count < 3 or scene_count < 2:
        blockers.append("尚未跨至少 2 个场景积累 3 个独立 case")
        return "active_pattern", blockers
    if case_count < 5 or technology_count < 2:
        blockers.append("尚未跨至少 2 个技术栈积累 5 个独立 case")
        return "tactic_candidate", blockers
    return "skill_review", blockers


def build_recommendations(
    index: dict[str, Any],
    *,
    source_index_sha256: str | None = None,
    group_by: str = "matched_tactics",
    minimum_cases: int = 2,
    selection_rule: str = DEFAULT_SELECTION_RULE,
) -> dict[str, Any]:
    """Return deterministic recommendations; never mutate ``index``."""

    if index.get("schema_version") != "1.0":
        raise PromotionError("unsupported case index schema_version")
    cases = index.get("cases")
    if not isinstance(cases, list) or not cases:
        raise PromotionError("case index has no cases")
    if group_by not in GROUP_FIELDS:
        raise PromotionError(f"unsupported group field: {group_by}")
    if minimum_cases < 2:
        raise PromotionError("minimum_cases must be at least 2")

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        if not isinstance(case, dict) or not case.get("id"):
            raise PromotionError("case index contains an invalid case entry")
        for value in _as_values(case.get(group_by, [])):
            if value:
                groups[value].append(case)
    if not groups:
        raise PromotionError(f"no values found for group field: {group_by}")

    recommendations = []
    for group_key, grouped_cases in sorted(groups.items()):
        case_ids = sorted({case["id"] for case in grouped_cases})
        source_hashes = sorted(
            {
                source_hash
                for case in grouped_cases
                for source_hash in case.get("source_hashes", [])
            }
        )
        source_identity_sets = [
            _source_identity_set(case)
            for case in grouped_cases
        ]
        source_identities = sorted(
            {
                identity
                for identity_set in source_identity_sets
                for identity in identity_set
            }
        )
        independent_source_sets = {
            identity_set
            for identity_set in source_identity_sets
        }
        scenes = sorted(
            {
                value
                for case in grouped_cases
                for value in _as_values(case.get("scene", []))
            }
        )
        technologies = sorted(
            {
                value
                for case in grouped_cases
                for value in _as_values(case.get("technology", []))
            }
        )
        trust_boundaries = sorted(
            {
                value
                for case in grouped_cases
                for value in _as_values(case.get("trust_boundary", []))
            }
        )
        complete = all(_contract_complete(case) for case in grouped_cases)
        stage, blockers = _recommended_stage(
            case_count=len(case_ids),
            independent_source_count=len(independent_source_sets),
            scene_count=len(scenes),
            technology_count=len(technologies),
            all_contracts_complete=complete,
            minimum_cases=minimum_cases,
        )
        stable_seed = json.dumps(
            {
                "group_by": group_by,
                "group_key": group_key,
                "case_ids": case_ids,
                "stage": stage,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        recommendations.append(
            {
                "recommendation_id": (
                    "PROMOTION-" + hashlib.sha256(stable_seed).hexdigest()[:16]
                ),
                "group_by": group_by,
                "group_key": group_key,
                "case_ids": case_ids,
                "source_hashes": source_hashes,
                "source_identities": [
                    {
                        "source_alias": source_alias,
                        "relative_path": relative_path,
                    }
                    for source_alias, relative_path in source_identities
                ],
                "independence_basis": "source_identity",
                "independent_source_set_count": len(independent_source_sets),
                "scenes": scenes,
                "technologies": technologies,
                "trust_boundaries": trust_boundaries,
                "evidence_contract_complete": complete,
                "recommended_stage": stage,
                "blockers": blockers,
                "requires_human_approval": True,
                "writes_stable_skill": False,
                "promotion_boundary": (
                    "只有跨独立任务、清晰前置、负控、不变量、停止规则和误报边界"
                    "均稳定时，才由人工评审决定是否修改正式 skill。"
                ),
            }
        )

    return {
        "schema_version": "1.0",
        "source_index_sha256": source_index_sha256
        or index.get("content_sha256"),
        "selection_rule": selection_rule,
        "group_by": group_by,
        "minimum_cases": minimum_cases,
        "recommendation_count": len(recommendations),
        "automatic_skill_writes": 0,
        "recommendations": recommendations,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _under_skills(path: Path) -> bool:
    skills_dir = (REPO_ROOT / "agent" / "skills").resolve()
    try:
        path.resolve().relative_to(skills_dir)
        return True
    except ValueError:
        return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从匿名 case index 生成可审计的 memory 晋升建议；不会写稳定 skill。",
    )
    parser.add_argument(
        "--case-index",
        type=Path,
        default=REPO_ROOT / "agent" / "cases" / "index.json",
        help="build_case_index.py 生成的 JSON 事实源。",
    )
    parser.add_argument(
        "--group-by",
        choices=GROUP_FIELDS,
        default="matched_tactics",
        help="建议聚合维度。",
    )
    parser.add_argument(
        "--minimum-cases",
        type=int,
        default=2,
        help="从 draft pattern 晋升所需的最少独立 case 数。",
    )
    parser.add_argument(
        "--selection-rule",
        default=DEFAULT_SELECTION_RULE,
        help="写入建议记录的选择规则。",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="可选建议 JSON 输出路径；禁止写入 agent/skills。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只输出建议，不写 --output。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.output and args.output.suffix.lower() != ".json":
            raise PromotionError("promotion output must use a .json suffix")
        if args.output and _under_skills(args.output):
            raise PromotionError("promotion output must not be written under agent/skills")
        index = json.loads(args.case_index.read_text(encoding="utf-8"))
        recommendations = build_recommendations(
            index,
            source_index_sha256=_sha256_file(args.case_index),
            group_by=args.group_by,
            minimum_cases=args.minimum_cases,
            selection_rule=args.selection_rule,
        )
        if args.dry_run:
            recommendations["dry_run"] = True
            if args.output:
                recommendations["would_write"] = args.output.name
        rendered = canonical_json(recommendations)
        if args.output and not args.dry_run:
            _write_text(args.output, rendered)
        sys.stdout.write(rendered)
        return 0
    except (PromotionError, OSError, json.JSONDecodeError, ValueError) as exc:
        sys.stderr.write(canonical_json({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
