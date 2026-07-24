"""Pure normalization for optional dynamic pipeline plans."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any


V2_CAPABILITY_FIELDS = {
    "installed",
    "configured",
    "reachable",
    "healthy",
    "permitted",
    "material_ready",
}
CAPABILITY_STATE_FIELDS = (
    "installed",
    "configured",
    "reachable",
    "healthy",
    "permitted",
    "material_ready",
)


def available_capability_ids(payload: Mapping[str, Any]) -> set[str]:
    available: set[str] = set()
    records = payload.get("capabilities", [])
    if not isinstance(records, list):
        return available
    report_version = payload.get("schema_version")
    for item in records:
        if not isinstance(item, dict) or item.get("available") is not True:
            continue
        capability_id = item.get("capability") or item.get("id")
        if not isinstance(capability_id, str):
            continue
        is_v2 = (
            report_version == "2.0"
            or item.get("source_compatibility") in {"v2", "detector_v2"}
            or bool(V2_CAPABILITY_FIELDS & item.keys())
        )
        if is_v2 and not (
            item.get("healthy") is True and item.get("health") == "ok"
        ):
            continue
        available.add(capability_id)
    return available


def available_material_ids(payload: Mapping[str, Any]) -> set[str]:
    raw = payload.get("available_materials", payload.get("materials", []))
    available: set[str] = set()
    if isinstance(raw, dict):
        available.update(
            str(key) for key, value in raw.items() if value is True
        )
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                available.add(item)
            elif (
                isinstance(item, dict)
                and item.get("available") is True
                and isinstance(item.get("id"), str)
            ):
                available.add(item["id"])
    return available


def capability_state_for(
    payload: Mapping[str, Any],
    capability_id: str,
    *,
    material_ready: bool,
) -> dict[str, Any]:
    """Return a conservative plan state for one detected capability.

    Pipeline planning never grants policy permission. Even a healthy runtime
    capability therefore remains unavailable until an explicit task plan is
    completed and approved.
    """

    record = next(
        (
            item
            for item in payload.get("capabilities", [])
            if isinstance(item, dict)
            and (item.get("capability") or item.get("id")) == capability_id
        ),
        None,
    )
    state = {field: False for field in CAPABILITY_STATE_FIELDS}
    state["material_ready"] = material_ready
    health = "unavailable"
    if isinstance(record, dict):
        is_v2 = (
            payload.get("schema_version") == "2.0"
            or item_is_v2(record)
        )
        if is_v2:
            for field in ("installed", "configured", "reachable", "healthy"):
                state[field] = record.get(field) is True
            requested_health = record.get("health")
            if isinstance(requested_health, str):
                health = requested_health
        elif record.get("available") is True:
            for field in ("installed", "configured", "reachable", "healthy"):
                state[field] = True
            health = "ok"
    return {
        **state,
        "available": False,
        "health": health,
    }


def item_is_v2(record: Mapping[str, Any]) -> bool:
    return (
        record.get("source_compatibility") in {"v2", "detector_v2"}
        or bool(V2_CAPABILITY_FIELDS & record.keys())
    )


def build_dynamic_plan_draft(
    *,
    phase_id: str,
    route_binding: Mapping[str, Any],
    capability_id: str,
    capability_payload: Mapping[str, Any],
    required_materials: list[str],
    missing_materials: list[str],
    safe_validation_level: str,
    operation: str,
) -> dict[str, Any]:
    """Build a schema-valid but non-executable task plan draft."""

    identity = {
        "phase_id": phase_id,
        "candidate_id": route_binding["candidate_id"],
        "tactic_id": route_binding["tactic_id"],
        "route_decision_id": route_binding["route_decision_id"],
        "capability_id": capability_id,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16].upper()
    evidence_id = f"EV-DRAFT-{digest}"
    material_ready = not missing_materials
    return {
        "schema_version": "1.0",
        "plan_status": "draft",
        "plan_id": f"DVP-{digest}",
        "candidate_id": str(route_binding["candidate_id"]),
        "candidate_file": "outputs/bounty-candidates.json",
        "tactic_id": str(route_binding["tactic_id"]),
        "route_decision_id": str(route_binding["route_decision_id"]),
        "route_status": str(route_binding["route_status"]),
        "resume_requirements_satisfied": bool(
            route_binding.get("resumed_requirements")
        ),
        "provider_capability": capability_id,
        "capability_state": capability_state_for(
            capability_payload,
            capability_id,
            material_ready=material_ready,
        ),
        "material_ready": material_ready,
        "missing_materials": sorted(missing_materials),
        "policy": {
            "permitted": False,
            "safe_validation_level": safe_validation_level,
        },
        "controlled_test_object": False,
        "actions": [
            {
                "action_id": f"ACTION-{digest}",
                "evidence_id": evidence_id,
                "operation": operation,
                "control_variant": "candidate-probe",
                "request_id": None,
                "auth_context": None,
                "browser_context": None,
                "parameters": {
                    "required_materials": sorted(required_materials),
                },
                "invariants_checked": [
                    "candidate-tactic-route-binding",
                ],
                "rollback_status": "not-required",
                "evidence_refs": [
                    f"evidence/envelopes/{evidence_id}.json",
                ],
                "state_change": False,
            }
        ],
        "stop_conditions": [
            "stop after one minimal observation",
            "stop when scope, policy, capability or materials change",
        ],
        "rollback_plan": {
            "required": False,
            "steps": [],
        },
    }


def dynamic_route_bindings(
    payloads: Iterable[Mapping[str, Any]],
    available_capabilities: set[str],
    available_materials: set[str],
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for payload in payloads:
        observations = payload.get("observations", {})
        if not isinstance(observations, dict):
            continue
        matches = observations.get("matches", [])
        if not isinstance(matches, list):
            continue
        for match in matches:
            if not isinstance(match, dict):
                continue
            candidate_id = match.get("candidate_id")
            route_decision_id = match.get("route_decision_id")
            route_status = match.get("route_status")
            tactic_id: Any = None
            if route_status in {"matched", "matched_with_fallback"}:
                matched_tactics = match.get("matched_tactics", [])
                if isinstance(matched_tactics, list) and matched_tactics:
                    primary = matched_tactics[0]
                    if isinstance(primary, dict):
                        tactic_id = primary.get("id")
            elif route_status in {
                "blocked_need_material",
                "blocked_need_capability",
            }:
                tactic_id = match.get("resume_tactic_id")
            if not all(
                isinstance(value, str) and value.strip()
                for value in (
                    candidate_id,
                    tactic_id,
                    route_decision_id,
                    route_status,
                )
            ):
                continue
            binding: dict[str, Any] = {
                "candidate_id": candidate_id.strip(),
                "tactic_id": tactic_id.strip(),
                "route_decision_id": route_decision_id.strip(),
                "route_status": route_status.strip(),
            }
            if route_status == "blocked_need_material":
                missing_materials = {
                    item
                    for item in match.get("missing_materials", [])
                    if isinstance(item, str) and item
                }
                if (
                    not missing_materials
                    or not missing_materials.issubset(available_materials)
                ):
                    continue
                binding["resumed_requirements"] = {
                    "materials": sorted(missing_materials),
                    "capabilities": [],
                }
            elif route_status == "blocked_need_capability":
                missing_capabilities = {
                    item
                    for item in match.get("missing_capabilities", [])
                    if isinstance(item, str) and item
                }
                if (
                    not missing_capabilities
                    or not missing_capabilities.issubset(
                        available_capabilities
                    )
                ):
                    continue
                binding["resumed_requirements"] = {
                    "materials": [],
                    "capabilities": sorted(missing_capabilities),
                }
            bindings.append(binding)
    return sorted(
        bindings,
        key=lambda item: (
            item["candidate_id"],
            item["tactic_id"],
            item["route_decision_id"],
            item["route_status"],
        ),
    )
