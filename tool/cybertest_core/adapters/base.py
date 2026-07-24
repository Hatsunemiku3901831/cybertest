"""Provider-neutral dynamic adapter contracts and JSON command transport."""

from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from ..evidence import build_evidence_envelope


ERROR_CATEGORIES = {
    "environment",
    "material",
    "policy",
    "target_response",
    "provider",
    "plan",
}
ROUTE_STATUSES = {
    "matched",
    "matched_with_fallback",
    "blocked_need_material",
    "blocked_need_capability",
}
SAFE_VALIDATION_LEVELS = {
    "readonly": 0,
    "log_confirmation": 1,
    "empty_body": 2,
    "fake_object": 3,
    "test_object": 4,
    "authorized_side_effect": 5,
}
HTTP_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HTTP_OPERATION_NAMES = frozenset(
    {"http_request", "replay", "authentication_matrix", "differential_compare"}
)
INHERENTLY_STATEFUL_OPERATIONS = frozenset({"form_interaction", "hook"})


def action_requires_state_change(action: Mapping[str, Any]) -> bool:
    """Derive conservative side-effect semantics from the actual operation.

    A plan cannot make a write-capable operation readonly merely by setting its
    caller-controlled ``state_change`` flag to false.
    """

    operation = action.get("operation")
    if operation in INHERENTLY_STATEFUL_OPERATIONS:
        return True
    parameters = action.get("parameters")
    if operation in HTTP_OPERATION_NAMES and isinstance(parameters, Mapping):
        method = parameters.get("method")
        if isinstance(method, str):
            return method.upper() in HTTP_MUTATING_METHODS
    return False


def validation_level_allows_state_change(value: Any) -> bool:
    """Return whether a policy level may perform a controlled state change."""

    return (
        isinstance(value, str)
        and SAFE_VALIDATION_LEVELS.get(value, -1)
        >= SAFE_VALIDATION_LEVELS["fake_object"]
    )


class ProviderTransport(Protocol):
    """Small transport boundary implemented by an MCP/CLI bridge or a fake."""

    provider_name: str

    def probe(
        self,
        capability_id: str,
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        ...

    def execute(
        self,
        capability_id: str,
        action: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class CapabilityProbeResult:
    capability_id: str
    installed: bool
    configured: bool
    reachable: bool
    healthy: bool
    permitted: bool
    material_ready: bool
    available: bool
    health: str
    provider: str | None = None
    error_category: str | None = None
    summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability_id,
            "installed": self.installed,
            "configured": self.configured,
            "reachable": self.reachable,
            "healthy": self.healthy,
            "permitted": self.permitted,
            "material_ready": self.material_ready,
            "available": self.available,
            "health": self.health,
            "provider": self.provider,
            "error_category": self.error_category,
            "summary": self.summary,
        }


@dataclass
class AdapterExecutionResult:
    capability_id: str
    ok: bool
    status: str
    records: list[dict[str, Any]] = field(default_factory=list)
    error_category: str | None = None
    error: str | None = None
    fallback_capability: str | None = None
    stopped: bool = False
    stop_reason: str | None = None


def _safe_provider_name(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(value.strip().replace("\\", "/")).name[:128] or None


class JsonCommandTransport:
    """Explicit JSON-in/JSON-out provider bridge.

    The command is supplied by the task plan. The adapter never discovers or
    starts a service automatically.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout: int = 30,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        if not command or any(
            not isinstance(item, str) or not item
            for item in command
        ):
            raise ValueError("provider command must contain non-empty strings")
        self.command = list(command)
        self.timeout = timeout
        self.runner = runner
        self.provider_name = _safe_provider_name(self.command[0]) or "provider"

    def _call(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        completed = self.runner(
            self.command,
            input=json.dumps(payload, ensure_ascii=False),
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"provider command returned {completed.returncode}"
            )
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("provider returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise RuntimeError("provider response must be an object")
        return response

    def probe(
        self,
        capability_id: str,
        context: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self._call(
            {
                "operation": "probe",
                "capability": capability_id,
                "context": dict(context),
            }
        )

    def execute(
        self,
        capability_id: str,
        action: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return self._call(
            {
                "operation": "execute",
                "capability": capability_id,
                "action": dict(action),
            }
        )


class DynamicAdapter(ABC):
    capability_id: str
    allowed_operations: frozenset[str] = frozenset()
    fallback_capability: str | None = None

    @abstractmethod
    def probe(self, context: Mapping[str, Any]) -> CapabilityProbeResult:
        """Run a no-business-side-effect provider health check."""

    def validate_plan(self, plan: Mapping[str, Any]) -> list[str]:
        errors: list[str] = []
        for field_name in (
            "candidate_id",
            "tactic_id",
            "route_decision_id",
            "provider_capability",
        ):
            value = plan.get(field_name)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"missing_{field_name}")
        if plan.get("provider_capability") != self.capability_id:
            errors.append("provider_capability_mismatch")
        if plan.get("route_status") not in ROUTE_STATUSES:
            errors.append("invalid_route_status")

        actions = plan.get("actions")
        if not isinstance(actions, list) or not actions:
            errors.append("missing_actions")
            return errors
        action_ids: set[str] = set()
        evidence_ids: set[str] = set()
        for action in actions:
            if not isinstance(action, dict):
                errors.append("invalid_action")
                continue
            action_id = action.get("action_id")
            evidence_id = action.get("evidence_id")
            operation = action.get("operation")
            if not isinstance(action_id, str) or not action_id:
                errors.append("missing_action_id")
            elif action_id in action_ids:
                errors.append("duplicate_action_id")
            else:
                action_ids.add(action_id)
            if not isinstance(evidence_id, str) or not evidence_id:
                errors.append("missing_evidence_id")
            elif evidence_id in evidence_ids:
                errors.append("duplicate_evidence_id")
            else:
                evidence_ids.add(evidence_id)
            if operation not in self.allowed_operations:
                errors.append(f"unsupported_operation:{operation}")
            parameters = action.get("parameters")
            if not isinstance(parameters, dict):
                errors.append(f"invalid_parameters:{action_id}")
            elif (
                operation in HTTP_OPERATION_NAMES
                and operation != "http_request"
                and not isinstance(parameters.get("method"), str)
            ):
                errors.append(f"missing_http_method:{action_id}")
            if not isinstance(action.get("invariants_checked"), list):
                errors.append(f"missing_invariants:{action_id}")
            if not isinstance(action.get("evidence_refs"), list):
                errors.append(f"missing_evidence_refs:{action_id}")
            if (
                action_requires_state_change(action)
                and action.get("state_change") is not True
            ):
                errors.append(
                    f"operation_requires_state_change:{action_id}"
                )
            if (
                action.get("state_change") is True
                and not validation_level_allows_state_change(
                    plan.get("policy", {}).get("safe_validation_level")
                    if isinstance(plan.get("policy"), Mapping)
                    else None
                )
            ):
                errors.append(
                    f"policy_level_forbids_state_change:{action_id}"
                )
        return list(dict.fromkeys(errors))

    @abstractmethod
    def execute(self, plan: Mapping[str, Any]) -> AdapterExecutionResult:
        """Execute a bound, already-gated validation plan."""

    def normalize_evidence(
        self,
        result: AdapterExecutionResult,
    ) -> list[dict[str, Any]]:
        envelopes: list[dict[str, Any]] = []
        for record in result.records:
            envelopes.append(
                build_evidence_envelope(
                    provider_capability=self.capability_id,
                    evidence_id=record["evidence_id"],
                    candidate_id=record["candidate_id"],
                    tactic_id=record["tactic_id"],
                    request_id=record.get("request_id"),
                    auth_context=record.get("auth_context"),
                    browser_context=record.get("browser_context"),
                    control_variant=record["control_variant"],
                    observation=record["observation"],
                    rollback_status=record["rollback_status"],
                    evidence_refs=record["evidence_refs"],
                    invariants_checked=record["invariants_checked"],
                    state_before=record.get("state_before"),
                    state_after=record.get("state_after"),
                )
            )
        return envelopes


class TransportDynamicAdapter(DynamicAdapter):
    """Shared implementation for MCP/provider-bridge backed adapters."""

    def __init__(self, transport: ProviderTransport | None = None) -> None:
        self.transport = transport

    def probe(self, context: Mapping[str, Any]) -> CapabilityProbeResult:
        permitted = context.get("permitted") is True
        material_ready = context.get("material_ready") is True
        if self.transport is None:
            return CapabilityProbeResult(
                capability_id=self.capability_id,
                installed=False,
                configured=False,
                reachable=False,
                healthy=False,
                permitted=permitted,
                material_ready=material_ready,
                available=False,
                health="unavailable",
                error_category="environment",
                summary="provider transport is not configured",
            )
        try:
            response = self.transport.probe(self.capability_id, context)
            reachable = response.get("reachable") is True
            healthy = response.get("healthy") is True
            available = (
                reachable and healthy and permitted and material_ready
            )
            return CapabilityProbeResult(
                capability_id=self.capability_id,
                installed=True,
                configured=True,
                reachable=reachable,
                healthy=healthy,
                permitted=permitted,
                material_ready=material_ready,
                available=available,
                health=(
                    "ok"
                    if healthy
                    else ("reachable" if reachable else "degraded")
                ),
                provider=self.transport.provider_name,
                error_category=None if healthy else "environment",
                summary=(
                    "provider health probe succeeded"
                    if healthy
                    else "provider health probe did not become healthy"
                ),
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError):
            return CapabilityProbeResult(
                capability_id=self.capability_id,
                installed=True,
                configured=True,
                reachable=False,
                healthy=False,
                permitted=permitted,
                material_ready=material_ready,
                available=False,
                health="degraded",
                provider=self.transport.provider_name,
                error_category="provider",
                summary="provider probe failed",
            )

    def execute(self, plan: Mapping[str, Any]) -> AdapterExecutionResult:
        errors = self.validate_plan(plan)
        if errors:
            return AdapterExecutionResult(
                capability_id=self.capability_id,
                ok=False,
                status="rejected",
                error_category="plan",
                error=";".join(errors),
            )
        if self.transport is None:
            return AdapterExecutionResult(
                capability_id=self.capability_id,
                ok=False,
                status="provider_unavailable",
                error_category="environment",
                error="provider transport is not configured",
                fallback_capability=self.fallback_capability,
            )

        records: list[dict[str, Any]] = []
        for action in plan["actions"]:
            try:
                response = self.transport.execute(
                    self.capability_id,
                    action,
                )
            except TimeoutError:
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_timeout",
                    records=records,
                    error_category="provider",
                    error="provider execution timed out",
                    fallback_capability=self.fallback_capability,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError):
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_error",
                    records=records,
                    error_category="provider",
                    error="provider execution failed",
                    fallback_capability=self.fallback_capability,
                )
            observation = response.get("observation")
            if not isinstance(observation, dict):
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_error",
                    records=records,
                    error_category="provider",
                    error="provider did not return a structured observation",
                    fallback_capability=self.fallback_capability,
                )
            records.append(
                _execution_record(plan, action, response, observation)
            )
            if (
                response.get("stop") is True
                or response.get("hypothesis_outcome") == "supported"
            ) and not action.get("state_change"):
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=True,
                    status="completed",
                    records=records,
                    stopped=True,
                    stop_reason=str(
                        response.get("stop_reason")
                        or "single_success_proven"
                    ),
                )
        return AdapterExecutionResult(
            capability_id=self.capability_id,
            ok=True,
            status="completed",
            records=records,
        )


def _execution_record(
    plan: Mapping[str, Any],
    action: Mapping[str, Any],
    response: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "action_id": action["action_id"],
        "evidence_id": action["evidence_id"],
        "candidate_id": plan["candidate_id"],
        "tactic_id": plan["tactic_id"],
        "request_id": action.get("request_id"),
        "auth_context": action.get("auth_context"),
        "browser_context": action.get("browser_context"),
        "control_variant": action["control_variant"],
        "observation": dict(observation),
        "rollback_status": response.get(
            "rollback_status",
            action.get("rollback_status", "not-required"),
        ),
        "evidence_refs": list(action["evidence_refs"]),
        "invariants_checked": list(action["invariants_checked"]),
        "state_before": response.get("state_before"),
        "state_after": response.get("state_after"),
        "hypothesis_outcome": response.get(
            "hypothesis_outcome",
            "inconclusive",
        ),
    }
