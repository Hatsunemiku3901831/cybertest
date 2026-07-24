"""Capability-neutral adapters for Cybertest Evidence Envelopes."""

from __future__ import annotations

import copy
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from .schema_validation import assert_valid, load_json_document


PROVIDER_OBSERVATION_KINDS = {
    "browser.interactive": "browser_ui",
    "http.replay": "http_replay",
    "js.cdp": "javascript_runtime",
    "http.capture": "traffic_capture",
    "oast.callback": "out_of_band_callback",
    "cli.http": "http_cli",
}
CONTROL_VARIANTS = {
    "baseline",
    "positive-control",
    "negative-control",
    "candidate-probe",
    "readback",
    "rollback",
}
ROLLBACK_STATUSES = {
    "not-required",
    "pending",
    "completed",
    "failed",
    "blocked",
}
REDACTION_LEVELS = {"restricted", "task", "reusable"}
FORBIDDEN_RAW_KEYS = {
    "authorization",
    "authorization_header",
    "auth_header",
    "cookie",
    "set_cookie",
    "password",
    "passwd",
    "client_secret",
    "app_secret",
    "api_key",
    "access_key",
    "access_token",
    "refresh_token",
    "id_token",
    "raw_request",
    "raw_response",
    "request_body",
    "response_body",
    "packet_bytes",
}
SENSITIVE_KEY_PARTS = {
    "authorization",
    "authorisation",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "password",
    "passwd",
    "secret",
    "secrets",
    "token",
    "tokens",
}
SAFE_SENSITIVE_METADATA_VALUES = {
    "token_type": {
        "api-key",
        "bearer",
        "cookie",
        "jwt",
        "none",
        "not-observed",
        "opaque",
        "other",
        "redacted",
        "unknown",
    },
}
JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"(?![A-Za-z0-9_-])"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE,
)
AUTHORIZATION_VALUE_PATTERN = re.compile(
    r"(?i)(?:"
    r"\b(?:bearer|basic)\s+\S+"
    r"|\bauthorization\s*[:=]\s*(?:token|api[-_]?key)\s+\S+"
    r")"
)
PLACEHOLDER_VALUE_PATTERN = re.compile(
    r"(?i)^\s*(?:bearer\s+|basic\s+)?"
    r"(?:\$\{[^}]+\}|\{[^}]+\}|<[^>]+>|redacted|placeholder)\s*$"
)
KNOWN_SECRET_PATTERNS = (
    re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])"),
)


def _schema_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "agent"
        / "schemas"
        / "evidence-envelope.schema.json"
    )


@lru_cache(maxsize=1)
def _evidence_schema() -> dict[str, Any]:
    schema = load_json_document(_schema_path())
    if not isinstance(schema, dict):
        raise ValueError("evidence envelope schema must be an object")
    return schema


def _strings(values: Iterable[str], label: str) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must contain non-empty strings")
        normalized.append(value.strip())
    return list(dict.fromkeys(normalized))


def _relative_evidence_refs(values: Iterable[str]) -> list[str]:
    references = _strings(values, "evidence_refs")
    for reference in references:
        path = Path(reference)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("evidence_refs must use task-relative paths")
    return references


def _normalized_key(value: Any) -> str:
    raw = str(value).strip()
    with_acronyms_split = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", raw)
    with_camel_split = re.sub(
        r"([a-z0-9])([A-Z])",
        r"\1_\2",
        with_acronyms_split,
    )
    return re.sub(
        r"[^A-Za-z0-9]+",
        "_",
        with_camel_split,
    ).strip("_").lower()


def _is_sensitive_key(normalized_key: str) -> bool:
    if normalized_key in SAFE_SENSITIVE_METADATA_VALUES:
        return False
    if normalized_key in FORBIDDEN_RAW_KEYS:
        return True
    parts = set(normalized_key.split("_"))
    if parts & SENSITIVE_KEY_PARTS:
        return True
    if {"api", "key"} <= parts or {"access", "key"} <= parts:
        return True
    if {"auth", "header"} <= parts:
        return True
    if "raw" in parts and parts & {
        "body",
        "headers",
        "packet",
        "payload",
        "request",
        "response",
    }:
        return True
    return False


def _assert_safe_metadata(key: str, value: Any, path: str) -> None:
    allowed_values = SAFE_SENSITIVE_METADATA_VALUES[key]
    if not isinstance(value, str):
        raise ValueError(f"{path} must use a controlled metadata descriptor")
    normalized_value = value.strip().lower().replace("_", "-")
    if normalized_value not in allowed_values:
        raise ValueError(f"{path} must use a controlled metadata descriptor")


def _assert_redacted(value: Any, path: str) -> None:
    """Reject obvious replayable/raw fields from the portable envelope."""

    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = _normalized_key(key)
            child_path = f"{path}.{key}"
            if normalized_key in SAFE_SENSITIVE_METADATA_VALUES:
                _assert_safe_metadata(normalized_key, child, child_path)
            elif _is_sensitive_key(normalized_key):
                raise ValueError(
                    f"{child_path} is raw or replayable; store it in restricted evidence and reference it"
                )
            _assert_redacted(child, child_path)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_redacted(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        if PLACEHOLDER_VALUE_PATTERN.fullmatch(value):
            return
        if (
            PRIVATE_KEY_PATTERN.search(value)
            or AUTHORIZATION_VALUE_PATTERN.search(value)
            or JWT_PATTERN.search(value)
            or any(pattern.search(value) for pattern in KNOWN_SECRET_PATTERNS)
        ):
            raise ValueError(
                f"{path} contains replayable credential material; use an evidence reference"
            )


def build_evidence_envelope(
    *,
    provider_capability: str,
    evidence_id: str,
    candidate_id: str,
    tactic_id: str,
    control_variant: str,
    observation: dict[str, Any],
    rollback_status: str,
    evidence_refs: Iterable[str],
    invariants_checked: Iterable[str],
    request_id: str | None = None,
    auth_context: str | None = None,
    browser_context: str | None = None,
    state_before: dict[str, Any] | None = None,
    state_after: dict[str, Any] | None = None,
    redaction_level: str = "task",
) -> dict[str, Any]:
    """Normalize one provider observation into a schema-valid envelope.

    The adapter only accepts already-redacted structured facts. Raw responses,
    tokens, cookies, screenshots, and packet contents remain in task evidence
    and are referenced by relative path.
    """

    if provider_capability not in PROVIDER_OBSERVATION_KINDS:
        raise ValueError(f"unsupported provider capability: {provider_capability}")
    if control_variant not in CONTROL_VARIANTS:
        raise ValueError(f"unsupported control variant: {control_variant}")
    if rollback_status not in ROLLBACK_STATUSES:
        raise ValueError(f"unsupported rollback status: {rollback_status}")
    if redaction_level not in REDACTION_LEVELS:
        raise ValueError(f"unsupported redaction level: {redaction_level}")
    if not isinstance(observation, dict):
        raise TypeError("observation must be an object")

    normalized_observation = copy.deepcopy(observation)
    _assert_redacted(normalized_observation, "observation")
    existing_provider = normalized_observation.get("provider_capability")
    if existing_provider not in {None, provider_capability}:
        raise ValueError("observation provider conflicts with selected capability")
    normalized_observation["provider_capability"] = provider_capability
    normalized_observation.setdefault(
        "provider_observation_kind",
        PROVIDER_OBSERVATION_KINDS[provider_capability],
    )

    envelope: dict[str, Any] = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "candidate_id": candidate_id,
        "tactic_id": tactic_id,
        "request_id": request_id,
        "auth_context": auth_context,
        "browser_context": browser_context,
        "control_variant": control_variant,
        "observation": normalized_observation,
        "rollback_status": rollback_status,
        "evidence_refs": _relative_evidence_refs(evidence_refs),
        "invariants_checked": _strings(
            invariants_checked,
            "invariants_checked",
        ),
        "redaction_level": redaction_level,
    }
    if state_before is not None:
        if not isinstance(state_before, dict):
            raise TypeError("state_before must be an object")
        _assert_redacted(state_before, "state_before")
        envelope["state_before"] = copy.deepcopy(state_before)
    if state_after is not None:
        if not isinstance(state_after, dict):
            raise TypeError("state_after must be an object")
        _assert_redacted(state_after, "state_after")
        envelope["state_after"] = copy.deepcopy(state_after)

    _assert_redacted(envelope, "envelope")
    assert_valid(envelope, _evidence_schema(), evidence_id)
    return envelope
