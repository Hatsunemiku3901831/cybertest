"""Deterministic tactic loading and attention-aware route ranking."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .schema_validation import assert_valid, load_json_document


ROUTE_VERSION = "1.0"
DEFAULT_TOP_K = 3
MIN_MATCH_SCORE = 25

WEIGHTS = {
    "observed_signals": 30,
    "control_gap": 25,
    "business_object": 8,
    "operation_type": 7,
    "trust_boundary": 15,
    "evidence_stage": 5,
    "capability": 5,
    "historical_validation": 5,
}

VALIDATION_LEVELS = {
    "readonly": 0,
    "log_confirmation": 0,
    "empty_body": 1,
    "fake_object": 2,
    "test_object": 3,
    "authorized_side_effect": 4,
}

REJECTING_NEGATIVE_OUTCOMES = {
    "core_hypothesis_rejected",
    "false_positive",
    "negative",
    "same_shape",
}


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_tactics_root(root: str | Path | None) -> Path:
    if root is None:
        return _repository_root() / "agent" / "tactics"
    supplied = Path(root)
    nested = supplied / "agent" / "tactics"
    return nested if nested.is_dir() else supplied


def load_tactics(root: str | Path | None = None) -> list[dict[str, Any]]:
    """Load and schema-check tactics from the JSON-compatible YAML registry."""

    tactics_root = _resolve_tactics_root(root)
    index_path = tactics_root / "index.yaml"
    index = load_json_document(index_path)
    if not isinstance(index, dict) or not isinstance(index.get("tactics"), list):
        raise ValueError(f"invalid tactic registry: {index_path}")

    schema = load_json_document(_repository_root() / "agent" / "schemas" / "tactic.schema.json")
    tactics: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in index["tactics"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError(f"invalid tactic registry entry in {index_path}: {entry!r}")
        tactic_path = tactics_root / entry["path"]
        tactic = load_json_document(tactic_path)
        if not isinstance(tactic, dict):
            raise ValueError(f"tactic must be an object: {tactic_path}")
        assert_valid(tactic, schema, str(tactic_path))
        tactic_id = str(tactic["id"])
        if tactic_id != entry.get("id"):
            raise ValueError(
                f"registry id {entry.get('id')!r} does not match {tactic_id!r}"
            )
        if tactic_id in seen_ids:
            raise ValueError(f"duplicate tactic id: {tactic_id}")
        seen_ids.add(tactic_id)
        tactics.append(tactic)
    return sorted(tactics, key=lambda item: item["id"])


def _string_set(values: Any) -> set[str]:
    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    for value in values:
        if isinstance(value, str):
            result.add(value)
        elif isinstance(value, dict):
            identifier = value.get("id") or value.get("capability")
            if isinstance(identifier, str):
                result.add(identifier)
    return result


def _overlap(left: Any, right: Any) -> set[str]:
    return _string_set(left) & _string_set(right)


def _excluded_route_ids(context: dict[str, Any]) -> set[str]:
    excluded = _string_set(context.get("excluded_routes", []))
    for result in context.get("negative_control_results", []):
        if not isinstance(result, dict):
            continue
        if result.get("outcome") in REJECTING_NEGATIVE_OUTCOMES:
            tactic_id = result.get("tactic_id")
            if isinstance(tactic_id, str):
                excluded.add(tactic_id)
    return excluded


def _requirement_ids(requirements: Any) -> set[str]:
    return _string_set(requirements if isinstance(requirements, list) else [])


def _available_capability_ids(values: Any) -> set[str]:
    """Normalize legacy ids and healthy v2 capability-state records."""

    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    v2_state_fields = {
        "installed",
        "configured",
        "reachable",
        "healthy",
        "permitted",
        "material_ready",
    }
    for value in values:
        if isinstance(value, str):
            result.add(value)
            continue
        if not isinstance(value, dict):
            continue
        capability_id = value.get("capability") or value.get("id")
        if not isinstance(capability_id, str):
            continue
        is_v2 = (
            value.get("source_compatibility") in {"v2", "detector_v2"}
            or bool(v2_state_fields & value.keys())
        )
        if is_v2:
            if (
                value.get("available") is True
                and value.get("healthy") is True
                and value.get("health") == "ok"
            ):
                result.add(capability_id)
        elif value.get("available") is True:
            result.add(capability_id)
    return result


def _material_gate(
    tactic: dict[str, Any], available: set[str]
) -> tuple[list[dict[str, str]], list[str]]:
    missing: list[dict[str, str]] = []
    notes: list[str] = []
    for requirement in tactic.get("material_requirements", []):
        if isinstance(requirement, str):
            item = {"id": requirement, "description": requirement, "required": True}
        elif isinstance(requirement, dict):
            item = requirement
        else:
            continue
        material_id = item.get("id")
        if not isinstance(material_id, str) or not item.get("required", True):
            continue
        if material_id not in available:
            missing.append(
                {
                    "id": material_id,
                    "description": str(item.get("description", material_id)),
                }
            )
    return missing, notes


def _capability_gate(
    tactic: dict[str, Any], available: set[str]
) -> tuple[list[str], list[str], list[str]]:
    selected: list[str] = []
    missing: list[str] = []
    notes: list[str] = []
    for requirement in tactic.get("required_capabilities", []):
        if isinstance(requirement, str):
            capability_id = requirement
            required = True
            fallbacks: list[str] = []
        elif isinstance(requirement, dict):
            capability_id = requirement.get("id")
            required = requirement.get("required", True)
            raw_fallbacks = requirement.get("fallbacks", [])
            if isinstance(raw_fallbacks, str):
                fallbacks = [raw_fallbacks]
            else:
                fallbacks = [item for item in raw_fallbacks if isinstance(item, str)]
        else:
            continue
        if not isinstance(capability_id, str):
            continue
        if capability_id in available:
            selected.append(capability_id)
            continue
        fallback = next((item for item in fallbacks if item in available), None)
        if fallback:
            selected.append(fallback)
            notes.append(f"capability_fallback:{capability_id}->{fallback}")
        elif required:
            missing.append(capability_id)
    return selected, missing, notes


def _policy_gate(
    tactic: dict[str, Any], policy: dict[str, Any]
) -> tuple[list[str], list[str]]:
    conflicts: list[str] = []
    notes: list[str] = []
    tactic_id = tactic["id"]
    if tactic_id in _string_set(policy.get("denied_tactics", [])):
        conflicts.append("tactic_denied")

    trigger_operations = _string_set(tactic.get("triggers", {}).get("operation_types", []))
    denied_operations = _string_set(policy.get("denied_operation_types", []))
    if trigger_operations & denied_operations:
        conflicts.append("operation_denied")

    allowed_operations = _string_set(policy.get("allowed_operation_types", []))
    if allowed_operations and trigger_operations and not trigger_operations & allowed_operations:
        conflicts.append("operation_not_allowed")

    maximum = policy.get("max_safe_validation_level")
    tactic_level = tactic.get("safe_validation_level", "readonly")
    if isinstance(maximum, str) and maximum in VALIDATION_LEVELS:
        if VALIDATION_LEVELS.get(str(tactic_level), 99) > VALIDATION_LEVELS[maximum]:
            conflicts.append("validation_level_exceeds_policy")
    return conflicts, notes


def _hard_gate(
    tactic: dict[str, Any],
    context: dict[str, Any],
    policy: dict[str, Any],
    excluded_ids: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    details: dict[str, Any] = {
        "notes": [],
        "selected_capabilities": [],
        "missing_capabilities": [],
        "missing_materials": [],
    }
    tactic_id = tactic["id"]
    triggers = tactic.get("triggers", {})

    if tactic.get("status") == "deprecated":
        gates.append({"code": "deprecated", "detail": "tactic is deprecated"})
    if tactic_id in excluded_ids:
        outcome = "negative_control_rejected" if any(
            isinstance(item, dict)
            and item.get("tactic_id") == tactic_id
            and item.get("outcome") in REJECTING_NEGATIVE_OUTCOMES
            for item in context.get("negative_control_results", [])
        ) else "excluded_route"
        gates.append({"code": outcome, "detail": "route was previously excluded"})

    for field, code in (
        ("target_types", "incompatible_target_type"),
        ("technologies", "incompatible_technology"),
    ):
        expected = _string_set(triggers.get(field, []))
        observed = _string_set(context.get(field, []))
        if expected and observed and not expected & observed:
            gates.append({"code": code, "detail": f"no overlap for {field}"})

    contradiction = _overlap(
        tactic.get("exclusion_signals", []), context.get("observed_signals", [])
    )
    if contradiction:
        gates.append(
            {
                "code": "evidence_contradiction",
                "detail": f"contradicting signals: {','.join(sorted(contradiction))}",
            }
        )

    policy_conflicts, policy_notes = _policy_gate(tactic, policy)
    details["notes"].extend(policy_notes)
    for conflict in policy_conflicts:
        gates.append({"code": "policy_conflict", "detail": conflict})

    available_materials = _string_set(context.get("available_materials", []))
    missing_materials, material_notes = _material_gate(tactic, available_materials)
    details["notes"].extend(material_notes)
    details["missing_materials"] = missing_materials
    if missing_materials:
        gates.append(
            {
                "code": "material_missing",
                "detail": ",".join(item["id"] for item in missing_materials),
            }
        )

    available_capabilities = _available_capability_ids(
        context.get("available_capabilities", [])
    )
    selected, missing_capabilities, capability_notes = _capability_gate(
        tactic, available_capabilities
    )
    details["selected_capabilities"] = selected
    details["missing_capabilities"] = missing_capabilities
    details["notes"].extend(capability_notes)
    if missing_capabilities:
        gates.append(
            {
                "code": "capability_missing",
                "detail": ",".join(sorted(missing_capabilities)),
            }
        )
    return gates, details


def _proportional_score(expected: Any, observed: Any, weight: int) -> int:
    expected_values = _string_set(expected)
    if not expected_values:
        return 0
    matches = expected_values & _string_set(observed)
    if not matches:
        return 0
    return max(1, round(weight * len(matches) / len(expected_values)))


def _score_tactic(
    tactic: dict[str, Any],
    context: dict[str, Any],
    gate_details: dict[str, Any],
) -> tuple[int, list[str]]:
    triggers = tactic.get("triggers", {})
    reasons: list[str] = []
    score = 0

    signal_score = _proportional_score(
        triggers.get("observed_signals", []),
        context.get("observed_signals", []),
        WEIGHTS["observed_signals"],
    )
    if signal_score:
        score += signal_score
        reasons.append(f"observed_signals:+{signal_score}")

    tactic_gaps = tactic.get("control_gap", {}).get("suspected_missing_controls", [])
    context_gaps = context.get("suspected_control_gaps", [])
    gap_score = _proportional_score(
        tactic_gaps, context_gaps, WEIGHTS["control_gap"]
    )
    if not gap_score:
        tactic_category = tactic.get("control_gap", {}).get("category")
        if tactic_category and tactic_category == context.get("category"):
            gap_score = WEIGHTS["control_gap"] // 2
    if gap_score:
        score += gap_score
        reasons.append(f"control_gap:+{gap_score}")

    for context_field, trigger_field, weight_key in (
        ("business_objects", "business_objects", "business_object"),
        ("operation_types", "operation_types", "operation_type"),
        ("trust_boundaries", "trust_boundaries", "trust_boundary"),
    ):
        if _overlap(context.get(context_field, []), triggers.get(trigger_field, [])):
            value = WEIGHTS[weight_key]
            score += value
            reasons.append(f"{weight_key}:+{value}")

    evidence_stages = _string_set(triggers.get("evidence_stages", []))
    if context.get("evidence_stage") in evidence_stages:
        value = WEIGHTS["evidence_stage"]
        score += value
        reasons.append(f"evidence_stage:+{value}")

    requirements = _requirement_ids(tactic.get("required_capabilities", []))
    if not requirements or gate_details.get("selected_capabilities"):
        value = WEIGHTS["capability"]
        score += value
        reasons.append(f"capability:+{value}")

    history_count = tactic.get("historical_validation_count", 0)
    if isinstance(history_count, int) and history_count > 0:
        value = WEIGHTS["historical_validation"]
        score += value
        reasons.append(f"historical_validation:+{value}")

    return min(100, score), reasons


def _is_semantically_relevant(
    tactic: dict[str, Any], context: dict[str, Any]
) -> bool:
    """Distinguish an actionable blocked route from unrelated gated tactics."""

    return _has_semantic_anchor(tactic, context)


def _has_semantic_anchor(
    tactic: dict[str, Any],
    context: dict[str, Any],
) -> bool:
    """Require tactic-specific evidence before generic dimensions can rank."""

    triggers = tactic.get("triggers", {})
    control_gap = tactic.get("control_gap", {})
    signal_matches = _overlap(
        triggers.get("observed_signals", []),
        context.get("observed_signals", []),
    )
    gap_matches = _overlap(
        control_gap.get("suspected_missing_controls", []),
        context.get("suspected_control_gaps", []),
    )
    return bool(gap_matches or len(signal_matches) >= 2)


def _validation_contract(
    tactic: dict[str, Any], gate_details: dict[str, Any]
) -> dict[str, Any]:
    request_matrix = copy.deepcopy(tactic.get("request_matrix", []))
    capability_fallback = any(
        isinstance(note, str) and note.startswith("capability_fallback:")
        for note in gate_details.get("notes", [])
    )
    return {
        "tactic_id": tactic["id"],
        "request_matrix": request_matrix,
        "expected_observations": copy.deepcopy(tactic.get("expected_observations", [])),
        "negative_controls": [
            item["id"]
            for item in request_matrix
            if isinstance(item, dict)
            and item.get("role") == "negative_control"
            and isinstance(item.get("id"), str)
        ],
        "false_positive_filters": copy.deepcopy(
            tactic.get("false_positive_filters", [])
        ),
        "evidence_invariants": copy.deepcopy(tactic.get("evidence_invariants", [])),
        "safe_validation_level": tactic.get("safe_validation_level", "readonly"),
        "execution_mode": (
            "capability_fallback" if capability_fallback else "primary"
        ),
        "rollback": copy.deepcopy(tactic.get("rollback", {})),
    }


def _decision_id(
    context: dict[str, Any],
    policy: dict[str, Any],
    matched: list[dict[str, Any]],
) -> str:
    canonical = json.dumps(
        {
            "context": context,
            "policy": policy,
            "matched": [
                {"id": item["id"], "score": item["score"]} for item in matched
            ],
            "route_version": ROUTE_VERSION,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "RD-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()


def _fallback_for(gate_codes: Counter[str]) -> tuple[str, dict[str, str]]:
    if gate_codes["policy_conflict"]:
        return (
            "policy_conflict",
            {
                "kind": "policy_conflict",
                "reason": "all relevant tactics conflict with the active policy",
                "next_action": "shrink the validation plan to the permitted policy boundary",
            },
        )
    if gate_codes["capability_missing"]:
        return (
            "blocked_need_capability",
            {
                "kind": "capability_missing",
                "reason": "required capability and registered fallback are unavailable",
                "next_action": "record the missing capability or use a registered static fallback",
            },
        )
    if gate_codes["material_missing"]:
        return (
            "blocked_need_material",
            {
                "kind": "material_missing",
                "reason": "required controlled material is unavailable",
                "next_action": "record the material requirement and the first resumable action",
            },
        )
    return (
        "route_gap",
        {
            "kind": "no_tactic_match",
            "reason": "no tactic passed the gates and minimum match score",
            "next_action": "use the generic control-gap workflow and record a route_gap",
        },
    )


def rank_tactics(
    context: dict[str, Any],
    tactics: Iterable[dict[str, Any]] | None = None,
    top_k: int = DEFAULT_TOP_K,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank tactics and return a stable, explainable RouteDecision."""

    if not isinstance(context, dict):
        raise TypeError("context must be a dictionary")
    if top_k < 1:
        raise ValueError("top_k must be at least 1")
    top_k = min(top_k, DEFAULT_TOP_K)

    tactic_list = load_tactics() if tactics is None else list(tactics)
    tactic_list = sorted(tactic_list, key=lambda item: str(item.get("id", "")))
    active_policy = copy.deepcopy(policy or context.get("policy") or {})
    excluded_ids = _excluded_route_ids(context)
    eligible: list[dict[str, Any]] = []
    blocked_routes: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    gate_codes: Counter[str] = Counter()

    for tactic in tactic_list:
        if not isinstance(tactic, dict) or not tactic.get("id"):
            continue
        gates, details = _hard_gate(tactic, context, active_policy, excluded_ids)
        if gates:
            structural_codes = {
                "deprecated",
                "excluded_route",
                "negative_control_rejected",
                "incompatible_target_type",
                "incompatible_technology",
                "evidence_contradiction",
            }
            codes = {item["code"] for item in gates}
            if not codes & structural_codes and _is_semantically_relevant(tactic, context):
                gate_codes.update(codes)
                score, match_reasons = _score_tactic(tactic, context, details)
                if score >= MIN_MATCH_SCORE:
                    blocked_routes.append(
                        {
                            "tactic": tactic,
                            "score": score,
                            "match_reasons": match_reasons,
                            "gate_details": details,
                            "gate_codes": codes,
                        }
                    )
            trace.append(
                {
                    "event": "tactic_evaluated",
                    "tactic_id": tactic["id"],
                    "outcome": "excluded",
                    "reasons": gates,
                }
            )
            continue

        if not _has_semantic_anchor(tactic, context):
            trace.append(
                {
                    "event": "tactic_evaluated",
                    "tactic_id": tactic["id"],
                    "outcome": "insufficient_semantic_anchor",
                    "score": 0,
                    "reasons": [
                        "requires one matching control gap or two tactic-specific signals"
                    ],
                }
            )
            continue

        score, match_reasons = _score_tactic(tactic, context, details)
        if score < MIN_MATCH_SCORE:
            trace.append(
                {
                    "event": "tactic_evaluated",
                    "tactic_id": tactic["id"],
                    "outcome": "insufficient_match",
                    "score": score,
                    "reasons": match_reasons,
                }
            )
            continue
        eligible.append(
            {
                "tactic": tactic,
                "score": score,
                "match_reasons": match_reasons,
                "gate_details": details,
            }
        )
        trace.append(
            {
                "event": "tactic_evaluated",
                "tactic_id": tactic["id"],
                "outcome": "eligible",
                "score": score,
                "reasons": match_reasons,
                "fallbacks": details.get("notes", []),
            }
        )

    eligible.sort(key=lambda item: (-item["score"], item["tactic"]["id"]))
    blocked_routes.sort(
        key=lambda item: (-item["score"], item["tactic"]["id"])
    )
    selected = eligible[:top_k]
    matched: list[dict[str, Any]] = []
    for index, item in enumerate(selected):
        tactic = item["tactic"]
        matched.append(
            {
                "id": tactic["id"],
                "title": tactic["title"],
                "score": item["score"],
                "match_reasons": item["match_reasons"],
                "contradictions": [],
                "load_mode": "full" if index == 0 else "summary",
            }
        )

    deferred = [
        {
            "id": item["tactic"]["id"],
            "title": item["tactic"]["title"],
            "score": item["score"],
            "reason": "outside_top_k",
        }
        for item in eligible[top_k:]
    ]

    if not selected:
        blocked_primary = blocked_routes[0] if blocked_routes else None
        primary_gate_codes = (
            Counter(blocked_primary["gate_codes"])
            if blocked_primary is not None
            else gate_codes
        )
        route_status, fallback = _fallback_for(primary_gate_codes)
        resumable = (
            blocked_primary is not None
            and route_status
            in {"blocked_need_material", "blocked_need_capability"}
        )
        resume_tactic_id = (
            str(blocked_primary["tactic"]["id"]) if resumable else None
        )
        material_requirements: list[dict[str, Any]] = []
        required_capabilities: list[str] = []
        validation_contract: dict[str, Any] = {}
        stop_conditions: list[str] = []
        do_not_overclaim = (
            "No vulnerability conclusion may be drawn from a route gap."
        )
        reroute_triggers: list[str] = []
        supporting_skills: list[str] = []
        decision_match: list[dict[str, Any]] = []
        if blocked_primary is not None:
            blocked_tactic = blocked_primary["tactic"]
            blocked_details = blocked_primary["gate_details"]
            available_materials = _string_set(
                context.get("available_materials", [])
            )
            for requirement in blocked_tactic.get("material_requirements", []):
                if not isinstance(requirement, dict):
                    continue
                item = copy.deepcopy(requirement)
                item["available"] = item.get("id") in available_materials
                material_requirements.append(item)
            required_capabilities = sorted(
                set(blocked_details.get("selected_capabilities", []))
                | set(blocked_details.get("missing_capabilities", []))
            )
            if resumable:
                validation_contract = _validation_contract(
                    blocked_tactic, blocked_details
                )
                stop_conditions = copy.deepcopy(
                    blocked_tactic.get("stop_conditions", [])
                )
                do_not_overclaim = blocked_tactic.get(
                    "do_not_overclaim", do_not_overclaim
                )
                reroute_triggers = copy.deepcopy(
                    blocked_tactic.get("reroute_triggers", [])
                )
                supporting_skills = [
                    item
                    for item in blocked_tactic.get("supporting_skills", [])
                    if isinstance(item, str)
                ][:2]
                fallback["resume_tactic_id"] = resume_tactic_id
                fallback["next_action"] = blocked_tactic[
                    "next_discriminating_action"
                ]
                fallback["missing_materials"] = [
                    item["id"]
                    for item in material_requirements
                    if not item.get("available")
                ]
                fallback["missing_capabilities"] = list(
                    blocked_details.get("missing_capabilities", [])
                )
                decision_match = [
                    {
                        "id": blocked_tactic["id"],
                        "score": blocked_primary["score"],
                    }
                ]
        decision = {
            "route_version": ROUTE_VERSION,
            "decision_id": "",
            "route_status": route_status,
            "phase": str(context.get("phase", "validation")),
            "primary_skill": "agent/skills/hunt-routing.md",
            "supporting_skills": supporting_skills,
            "matched_tactics": [],
            "deferred_tactics": deferred,
            "required_capabilities": required_capabilities,
            "material_requirements": material_requirements,
            "next_discriminating_action": fallback["next_action"],
            "validation_contract": validation_contract,
            "stop_conditions": stop_conditions,
            "do_not_overclaim": do_not_overclaim,
            "reroute_triggers": reroute_triggers,
            "resume_tactic_id": resume_tactic_id,
            "fallback": fallback,
            "trace": trace
            + [
                {
                    "event": "route_fallback",
                    "outcome": route_status,
                    "reasons": [fallback],
                }
            ],
        }
        decision["decision_id"] = _decision_id(
            context, active_policy, decision_match
        )
        return decision

    primary = selected[0]
    tactic = primary["tactic"]
    details = primary["gate_details"]
    fallback_notes = details.get("notes", [])
    fallback = None
    route_status = "matched"
    if fallback_notes:
        route_status = "matched_with_fallback"
        fallback = {
            "kind": "registered_fallback",
            "reason": ";".join(fallback_notes),
            "next_action": tactic["next_discriminating_action"],
        }

    material_requirements = []
    available_materials = _string_set(context.get("available_materials", []))
    for requirement in tactic.get("material_requirements", []):
        if isinstance(requirement, dict):
            item = copy.deepcopy(requirement)
            item["available"] = item.get("id") in available_materials
            material_requirements.append(item)

    supporting_skills = [
        item for item in tactic.get("supporting_skills", []) if isinstance(item, str)
    ][:2]
    decision = {
        "route_version": ROUTE_VERSION,
        "decision_id": "",
        "route_status": route_status,
        "phase": str(context.get("phase", "validation")),
        "primary_skill": "agent/skills/hunt-routing.md",
        "supporting_skills": supporting_skills,
        "matched_tactics": matched,
        "deferred_tactics": deferred,
        "required_capabilities": details.get("selected_capabilities", []),
        "material_requirements": material_requirements,
        "next_discriminating_action": tactic["next_discriminating_action"],
        "validation_contract": _validation_contract(tactic, details),
        "stop_conditions": copy.deepcopy(tactic.get("stop_conditions", [])),
        "do_not_overclaim": tactic.get("do_not_overclaim", ""),
        "reroute_triggers": copy.deepcopy(tactic.get("reroute_triggers", [])),
        "resume_tactic_id": None,
        "fallback": fallback,
        "trace": trace
        + [
            {
                "event": "route_selected",
                "tactic_id": tactic["id"],
                "outcome": route_status,
                "score": primary["score"],
            }
        ],
    }
    decision["decision_id"] = _decision_id(context, active_policy, matched)
    return decision
