#!/usr/bin/env python3
"""Plan or explicitly execute one bound Cybertest dynamic validation."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Mapping

try:
    from cybertest_core.adapters import (
        ADAPTER_TYPES,
        CLIHttpAdapter,
        JsonCommandTransport,
    )
    from cybertest_core.adapters.base import (
        DynamicAdapter,
        action_requires_state_change,
        validation_level_allows_state_change,
    )
    from cybertest_core.schema_validation import (
        SchemaValidationError,
        assert_valid,
        load_json_document,
    )
except ModuleNotFoundError:  # Imported as ``tool.run_dynamic_validation``.
    from tool.cybertest_core.adapters import (
        ADAPTER_TYPES,
        CLIHttpAdapter,
        JsonCommandTransport,
    )
    from tool.cybertest_core.adapters.base import (
        DynamicAdapter,
        action_requires_state_change,
        validation_level_allows_state_change,
    )
    from tool.cybertest_core.schema_validation import (
        SchemaValidationError,
        assert_valid,
        load_json_document,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
PLAN_SCHEMA = (
    REPO_ROOT / "agent" / "schemas" / "dynamic-validation-plan.schema.json"
)


class DynamicValidationError(ValueError):
    """Raised when execution cannot safely bind to task state."""


def _execution_state_requirements(capability_id: Any) -> tuple[str, ...]:
    if capability_id == "cli.http":
        return ("installed", "healthy", "permitted", "material_ready")
    return (
        "installed",
        "configured",
        "reachable",
        "healthy",
        "permitted",
        "material_ready",
    )


def canonical_json(document: Any) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _write_json_atomic(path: Path, document: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(canonical_json(document), encoding="utf-8")
    temporary.chmod(mode)
    temporary.replace(path)


def _task_path(task_dir: Path, reference: str) -> Path:
    if not isinstance(reference, str) or not reference:
        raise DynamicValidationError("task-relative path is required")
    relative = Path(reference)
    if relative.is_absolute() or ".." in relative.parts:
        raise DynamicValidationError("task-relative path is required")
    resolved = (task_dir / relative).resolve()
    try:
        resolved.relative_to(task_dir.resolve())
    except ValueError as exc:
        raise DynamicValidationError("task-relative path escapes task directory") from exc
    return resolved


def load_plan(path: Path) -> dict[str, Any]:
    document = load_json_document(path)
    plan = document
    if isinstance(document, dict):
        observations = document.get("observations")
        if isinstance(observations, dict) and isinstance(
            observations.get("dynamic_validation_plan"),
            dict,
        ):
            plan = observations["dynamic_validation_plan"]
    schema = load_json_document(PLAN_SCHEMA)
    assert_valid(plan, schema, "dynamic validation plan")
    if not isinstance(plan, dict):
        raise DynamicValidationError("dynamic validation plan must be an object")
    return plan


def _capability_state_errors(plan: Mapping[str, Any]) -> list[str]:
    state = plan["capability_state"]
    errors: list[str] = []
    requirements = set(
        _execution_state_requirements(plan.get("provider_capability"))
    )
    if state.get("configured") is True and state.get("installed") is not True:
        errors.append("capability configured=true requires installed=true")
    if state.get("reachable") is True and state.get("installed") is not True:
        errors.append("capability reachable=true requires installed=true")
    if (
        state.get("reachable") is True
        and "configured" in requirements
        and state.get("configured") is not True
    ):
        errors.append("capability reachable=true requires configured=true")
    if state.get("healthy") is True and state.get("installed") is not True:
        errors.append("capability healthy=true requires installed=true")
    if (
        state.get("healthy") is True
        and "reachable" in requirements
        and state.get("reachable") is not True
    ):
        errors.append("capability healthy=true requires reachable=true")

    health = state.get("health")
    if health == "ok" and not all(
        state.get(field) is True
        for field in requirements
        if field not in {"permitted", "material_ready"}
    ):
        errors.append(
            "capability health=ok is missing required health prerequisites"
        )
    if health != "ok" and state.get("healthy") is True:
        errors.append("capability healthy=true requires health=ok")

    expected_available = all(
        state.get(field) is True for field in requirements
    )
    if state.get("available") is not expected_available:
        errors.append("capability available does not match its derived state")
    if state.get("permitted") is not plan["policy"].get("permitted"):
        errors.append("capability permitted state does not match active policy")
    if state.get("material_ready") is not plan.get("material_ready"):
        errors.append(
            "capability material_ready state does not match plan materials"
        )
    return errors


def assess_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return deterministic execution gates without changing task state."""

    state = plan["capability_state"]
    missing_materials = list(plan["missing_materials"])
    errors: list[str] = []
    status = "ready_for_explicit_execution"

    state_errors = _capability_state_errors(plan)
    if plan.get("plan_status", "ready") != "ready":
        status = "blocked_need_plan_completion"
        errors.append("dynamic plan draft must be completed before execution")
    elif state_errors:
        status = "invalid_plan"
        errors.extend(state_errors)
    elif plan["route_status"].startswith("blocked_") and (
        plan.get("resume_requirements_satisfied") is not True
    ):
        status = "blocked_need_route"
        errors.append("blocked route has not satisfied resume requirements")
    elif (
        plan["policy"].get("permitted") is not True
        or state.get("permitted") is not True
    ):
        status = "policy_conflict"
        errors.append("active policy does not permit provider execution")
    elif (
        plan.get("material_ready") is not True
        or state.get("material_ready") is not True
        or missing_materials
        or plan.get("controlled_test_object") is not True
    ):
        status = "blocked_need_material"
        errors.append("controlled materials or test object are not ready")
    elif (
        state.get("available") is not True
        or state.get("healthy") is not True
        or state.get("health") != "ok"
    ):
        status = "blocked_need_capability"
        errors.append("provider capability is not healthy and available")

    actions = plan["actions"]
    expected_envelope_refs = {
        f"evidence/envelopes/{action['evidence_id']}.json"
        for action in actions
    }
    actual_envelope_refs = {
        reference
        for action in actions
        for reference in action["evidence_refs"]
        if reference.startswith("evidence/envelopes/")
    }
    if expected_envelope_refs != actual_envelope_refs:
        status = "invalid_plan"
        errors.append("every action must bind its exact envelope reference")

    derived_state_changes = [
        action for action in actions if action_requires_state_change(action)
    ]
    undeclared_state_changes = [
        action
        for action in derived_state_changes
        if action.get("state_change") is not True
    ]
    if undeclared_state_changes:
        status = "invalid_plan"
        errors.append(
            "write-capable operations must declare state_change=true: "
            + ",".join(
                str(action.get("action_id"))
                for action in undeclared_state_changes
            )
        )

    state_changes = [
        action
        for action in actions
        if action.get("state_change") is True
        or action_requires_state_change(action)
    ]
    if state_changes:
        if not validation_level_allows_state_change(
            plan["policy"].get("safe_validation_level")
        ):
            status = "policy_conflict"
            errors.append(
                "active safe_validation_level forbids state-changing actions"
            )
        variants = {action["control_variant"] for action in actions}
        rollback = plan["rollback_plan"]
        if (
            rollback.get("required") is not True
            or not rollback.get("steps")
            or "readback" not in variants
            or "rollback" not in variants
        ):
            status = "invalid_plan"
            errors.append(
                "state changes require readback and a non-empty rollback plan"
            )

    return {
        "status": status,
        "ok": status == "ready_for_explicit_execution",
        "errors": errors,
        "missing_materials": missing_materials,
    }


def _probe_context(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "permitted": plan["policy"].get("permitted") is True,
        "material_ready": (
            plan.get("material_ready") is True
            and not plan.get("missing_materials")
            and plan.get("controlled_test_object") is True
        ),
        "candidate_id": plan["candidate_id"],
        "tactic_id": plan["tactic_id"],
        "route_decision_id": plan["route_decision_id"],
    }


def _candidate_slot(
    document: Any,
    candidate_id: str,
) -> dict[str, Any]:
    candidates: list[Any]
    if isinstance(document, dict) and document.get("id") == candidate_id:
        candidates = [document]
    elif isinstance(document, dict) and isinstance(
        document.get("candidates"),
        list,
    ):
        candidates = document["candidates"]
    elif isinstance(document, list):
        candidates = document
    else:
        raise DynamicValidationError(
            "candidate file has no supported candidate container"
        )
    matches = [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict) and candidate.get("id") == candidate_id
    ]
    if len(matches) != 1:
        raise DynamicValidationError(
            "candidate file must contain exactly one bound candidate"
        )
    return matches[0]


def _validate_candidate_binding(
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> None:
    if candidate.get("route_decision_id") != plan["route_decision_id"]:
        raise DynamicValidationError("candidate RouteDecision binding changed")
    tactic_ids = {
        item.get("id")
        for item in candidate.get("matched_tactics", [])
        if isinstance(item, dict)
    }
    resume_tactic = candidate.get("resume_tactic_id")
    if plan["tactic_id"] not in tactic_ids and plan["tactic_id"] != resume_tactic:
        raise DynamicValidationError("candidate tactic binding changed")


def _aggregate_outcome(records: list[dict[str, Any]]) -> str:
    outcomes = {
        record.get("hypothesis_outcome", "inconclusive")
        for record in records
    }
    if "rejected" in outcomes:
        return "rejected"
    if "supported" in outcomes:
        return "supported"
    return "inconclusive"


def _rollback_status(
    plan: Mapping[str, Any],
    records: list[dict[str, Any]],
) -> str:
    if not plan["rollback_plan"]["required"]:
        return "not-required"
    rollback_records = [
        record
        for record in records
        if record["control_variant"] == "rollback"
    ]
    if not rollback_records:
        return "pending"
    statuses = {record["rollback_status"] for record in rollback_records}
    if statuses == {"completed"}:
        return "completed"
    if "failed" in statuses:
        return "failed"
    if "blocked" in statuses:
        return "blocked"
    return "pending"


def _apply_candidate_feedback(
    document: Any,
    candidate: dict[str, Any],
    *,
    plan: Mapping[str, Any],
    envelopes: list[dict[str, Any]],
    outcome: str,
    rollback_status: str,
    execution_status: str = "completed",
    execution_ok: bool = True,
    error_category: str | None = None,
) -> dict[str, Any]:
    existing = {
        item.get("evidence_id")
        for item in candidate.get("evidence_envelopes", [])
        if isinstance(item, dict)
    }
    candidate.setdefault("evidence_envelopes", [])
    candidate["evidence_envelopes"].extend(
        envelope
        for envelope in envelopes
        if envelope["evidence_id"] not in existing
    )
    if outcome == "rejected":
        candidate["status"] = "false_positive"
        excluded = candidate.setdefault("excluded_routes", [])
        if plan["tactic_id"] not in excluded:
            excluded.append(plan["tactic_id"])
    elif outcome == "supported":
        candidate["status"] = "observed"
    else:
        candidate["status"] = "verifying"

    history = candidate.setdefault("dynamic_validation_history", [])
    history.append(
        {
            "plan_id": plan["plan_id"],
            "route_decision_id": plan["route_decision_id"],
            "tactic_id": plan["tactic_id"],
            "provider_capability": plan["provider_capability"],
            "outcome": outcome,
            "rollback_status": rollback_status,
            "execution_status": execution_status,
            "execution_ok": execution_ok,
            "error_category": error_category,
            "evidence_refs": [
                f"evidence/envelopes/{item['evidence_id']}.json"
                for item in envelopes
            ],
            "reroute_required": outcome == "rejected",
        }
    )
    return document


def _normalize_and_persist_envelopes(
    *,
    task_dir: Path,
    adapter: DynamicAdapter,
    execution: Any,
) -> list[dict[str, Any]]:
    envelopes = adapter.normalize_evidence(execution)
    missing_restricted_refs = sorted(
        {
            reference
            for envelope in envelopes
            for reference in envelope.get("evidence_refs", [])
            if isinstance(reference, str)
            and reference.startswith("evidence/restricted/")
            and not _task_path(task_dir, reference).is_file()
        }
    )
    if missing_restricted_refs:
        raise DynamicValidationError(
            "provider did not create required restricted evidence: "
            + ",".join(missing_restricted_refs)
        )
    for envelope in envelopes:
        reference = f"evidence/envelopes/{envelope['evidence_id']}.json"
        _write_json_atomic(_task_path(task_dir, reference), envelope)
    return envelopes


def build_adapter(
    plan: Mapping[str, Any],
    *,
    task_dir: Path,
) -> DynamicAdapter:
    capability = str(plan["provider_capability"])
    adapter_type = ADAPTER_TYPES[capability]
    if capability == "cli.http":
        return CLIHttpAdapter(task_dir=task_dir)
    command = plan.get("provider_command")
    transport = (
        JsonCommandTransport(command)
        if isinstance(command, list) and command
        else None
    )
    return adapter_type(transport)


def plan_report(
    plan: Mapping[str, Any],
    *,
    task_dir_provided: bool,
) -> dict[str, Any]:
    gate = assess_plan(plan)
    return {
        "schema_version": "1.0",
        "tool": "run_dynamic_validation",
        "ok": True,
        "mode": "plan_only",
        "status": gate["status"],
        "plan_id": plan["plan_id"],
        "candidate_id": plan["candidate_id"],
        "tactic_id": plan["tactic_id"],
        "route_decision_id": plan["route_decision_id"],
        "provider_capability": plan["provider_capability"],
        "execution_performed": False,
        "task_dir_ready": task_dir_provided,
        "gate": gate,
    }


def execute_plan(
    plan: Mapping[str, Any],
    *,
    task_dir: Path,
    adapter: DynamicAdapter,
) -> tuple[dict[str, Any], Any]:
    gate = assess_plan(plan)
    if not gate["ok"]:
        return (
            {
                **plan_report(plan, task_dir_provided=True),
                "mode": "execute",
                "ok": False,
                "execution_performed": False,
            },
            None,
        )
    adapter_errors = adapter.validate_plan(plan)
    if adapter_errors:
        raise DynamicValidationError(
            "adapter rejected plan: " + ";".join(adapter_errors)
        )

    candidate_path = _task_path(task_dir, plan["candidate_file"])
    candidate_document = load_json_document(candidate_path)
    candidate = _candidate_slot(candidate_document, plan["candidate_id"])
    _validate_candidate_binding(candidate, plan)

    probe = adapter.probe(_probe_context(plan))
    probe_payload = probe.as_dict()
    if not (
        probe.available
        and probe.installed
        and probe.configured
        and probe.reachable
        and probe.healthy
        and probe.permitted
        and probe.material_ready
        and probe.health == "ok"
    ):
        return (
            {
                "schema_version": "1.0",
                "tool": "run_dynamic_validation",
                "ok": False,
                "mode": "execute",
                "status": "blocked_need_capability",
                "plan_id": plan["plan_id"],
                "candidate_id": plan["candidate_id"],
                "tactic_id": plan["tactic_id"],
                "route_decision_id": plan["route_decision_id"],
                "provider_capability": plan["provider_capability"],
                "execution_performed": False,
                "error_category": probe.error_category or "environment",
                "error": "fresh provider probe is not healthy and available",
                "capability_probe": probe_payload,
                "evidence_refs": [],
            },
            None,
        )

    execution = adapter.execute(plan)
    envelopes: list[dict[str, Any]] = []
    if execution.records:
        try:
            envelopes = _normalize_and_persist_envelopes(
                task_dir=task_dir,
                adapter=adapter,
                execution=execution,
            )
        except (DynamicValidationError, TypeError, ValueError):
            return (
                {
                    "schema_version": "1.0",
                    "tool": "run_dynamic_validation",
                    "ok": False,
                    "mode": "execute",
                    "status": "provider_output_rejected",
                    "plan_id": plan["plan_id"],
                    "candidate_id": plan["candidate_id"],
                    "tactic_id": plan["tactic_id"],
                    "route_decision_id": plan["route_decision_id"],
                    "provider_capability": plan["provider_capability"],
                    "execution_performed": True,
                    "error_category": "provider",
                    "error": (
                        "provider output violated the portable evidence "
                        "or restricted evidence contract"
                    ),
                    "capability_probe": probe_payload,
                    "evidence_refs": [],
                },
                None,
            )

    if not execution.ok:
        updated_document = None
        rollback_status = _rollback_status(plan, execution.records)
        if envelopes:
            updated_document = copy.deepcopy(candidate_document)
            updated_candidate = _candidate_slot(
                updated_document,
                plan["candidate_id"],
            )
            updated_document = _apply_candidate_feedback(
                updated_document,
                updated_candidate,
                plan=plan,
                envelopes=envelopes,
                outcome="inconclusive",
                rollback_status=rollback_status,
                execution_status=execution.status,
                execution_ok=False,
                error_category=execution.error_category,
            )
            _write_json_atomic(candidate_path, updated_document)
        return (
            {
                "schema_version": "1.0",
                "tool": "run_dynamic_validation",
                "ok": False,
                "mode": "execute",
                "status": execution.status,
                "plan_id": plan["plan_id"],
                "candidate_id": plan["candidate_id"],
                "tactic_id": plan["tactic_id"],
                "route_decision_id": plan["route_decision_id"],
                "provider_capability": plan["provider_capability"],
                "execution_performed": bool(execution.records),
                "error_category": execution.error_category,
                "error": execution.error,
                "fallback_capability": execution.fallback_capability,
                "partial_execution": bool(envelopes),
                "rollback_status": rollback_status,
                "capability_probe": probe_payload,
                "evidence_refs": [
                    f"evidence/envelopes/{envelope['evidence_id']}.json"
                    for envelope in envelopes
                ],
                "candidate_file": plan["candidate_file"],
            },
            updated_document,
        )

    outcome = _aggregate_outcome(execution.records)
    rollback_status = _rollback_status(plan, execution.records)
    updated_document = copy.deepcopy(candidate_document)
    updated_candidate = _candidate_slot(
        updated_document,
        plan["candidate_id"],
    )
    updated_document = _apply_candidate_feedback(
        updated_document,
        updated_candidate,
        plan=plan,
        envelopes=envelopes,
        outcome=outcome,
        rollback_status=rollback_status,
    )
    _write_json_atomic(candidate_path, updated_document)

    report = {
        "schema_version": "1.0",
        "tool": "run_dynamic_validation",
        "ok": True,
        "mode": "execute",
        "status": "completed",
        "plan_id": plan["plan_id"],
        "candidate_id": plan["candidate_id"],
        "tactic_id": plan["tactic_id"],
        "route_decision_id": plan["route_decision_id"],
        "provider_capability": plan["provider_capability"],
        "execution_performed": True,
        "outcome": outcome,
        "candidate_status": {
            "supported": "observed",
            "rejected": "false_positive",
            "inconclusive": "verifying",
        }[outcome],
        "reroute_required": outcome == "rejected",
        "rollback_status": rollback_status,
        "stopped": execution.stopped,
        "stop_reason": execution.stop_reason,
        "capability_probe": probe_payload,
        "evidence_refs": [
            f"evidence/envelopes/{envelope['evidence_id']}.json"
            for envelope in envelopes
        ],
        "candidate_file": plan["candidate_file"],
    }
    return report, updated_document


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or explicitly execute one candidate/tactic/RouteDecision "
            "bound dynamic validation."
        )
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="Required acknowledgement of the authorized task scope.",
    )
    parser.add_argument("--plan", required=True, help="Dynamic plan JSON path.")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute once; omitted means read-only plan validation.",
    )
    parser.add_argument(
        "--task-dir",
        help="Existing task directory; mandatory with --execute.",
    )
    parser.add_argument(
        "--provider",
        choices=sorted(ADAPTER_TYPES),
        help="Optional explicit provider; must match the bound plan.",
    )
    parser.add_argument(
        "--output",
        help=(
            "Task-relative execution report path; only written with --execute."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        plan = load_plan(Path(args.plan))
        if args.provider and args.provider != plan["provider_capability"]:
            raise DynamicValidationError(
                "explicit provider does not match the bound plan"
            )
        task_dir = Path(args.task_dir).resolve() if args.task_dir else None
        if not args.execute:
            sys.stdout.write(
                canonical_json(
                    plan_report(
                        plan,
                        task_dir_provided=bool(
                            task_dir and task_dir.is_dir()
                        ),
                    )
                )
            )
            return 0
        if task_dir is None or not task_dir.is_dir():
            report = {
                **plan_report(plan, task_dir_provided=False),
                "ok": False,
                "mode": "execute",
                "status": "blocked_need_task_dir",
            }
            sys.stdout.write(canonical_json(report))
            return 1

        output_reference = args.output or (
            f"outputs/dynamic-validation/{plan['plan_id']}.json"
        )
        output_path = _task_path(task_dir, output_reference)
        adapter = build_adapter(plan, task_dir=task_dir)
        report, _updated = execute_plan(
            plan,
            task_dir=task_dir,
            adapter=adapter,
        )
        _write_json_atomic(
            output_path,
            report,
        )
        sys.stdout.write(canonical_json(report))
        return 0 if report["ok"] else 1
    except (
        DynamicValidationError,
        SchemaValidationError,
        OSError,
        ValueError,
    ) as exc:
        sys.stderr.write(
            canonical_json(
                {
                    "ok": False,
                    "tool": "run_dynamic_validation",
                    "error": str(exc),
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
