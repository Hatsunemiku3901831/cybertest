#!/usr/bin/env python3
"""Detect local Cybertest capabilities without exposing machine-specific paths."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "agent" / "capabilities" / "manifest.yaml"
DEFAULT_OUTPUT = REPO_ROOT / ".cybertest" / "capabilities.json"
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STATE_FIELDS = (
    "installed",
    "configured",
    "reachable",
    "healthy",
    "permitted",
    "material_ready",
)
HEALTH_VALUES = {
    "unknown",
    "installed_only",
    "configured",
    "reachable",
    "degraded",
    "ok",
    "unavailable",
}


class CapabilityError(ValueError):
    """Raised for invalid manifest or optional discovery input."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def display_path(path: Path | None) -> str | None:
    """Return a repository-relative path or a basename, never an absolute path."""
    if path is None:
        return None
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.name


def safe_name(value: Any) -> str | None:
    """Reduce provider/path input to a non-sensitive command-like identifier."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("\\", "/").rsplit("/", 1)[-1]
    return candidate if SAFE_NAME_RE.fullmatch(candidate) else None


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CapabilityError(f"{label} is not readable") from exc
    except json.JSONDecodeError as exc:
        raise CapabilityError(f"{label} is not valid JSON-compatible YAML") from exc


def load_manifest(path: Path) -> dict[str, Any]:
    payload = read_json(path, "manifest")
    if not isinstance(payload, dict):
        raise CapabilityError("manifest root must be an object")
    if payload.get("schema_version") != "2.0":
        raise CapabilityError("manifest schema_version must be 2.0")
    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise CapabilityError("manifest capabilities must be a non-empty array")

    seen: set[str] = set()
    for item in capabilities:
        if not isinstance(item, dict):
            raise CapabilityError("manifest capability entries must be objects")
        capability_id = item.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            raise CapabilityError("every manifest capability requires an id")
        if capability_id in seen:
            raise CapabilityError(f"duplicate capability id: {capability_id}")
        seen.add(capability_id)
        if not isinstance(item.get("provides"), list):
            raise CapabilityError(f"{capability_id} provides must be an array")
        if not isinstance(item.get("fallbacks"), list):
            raise CapabilityError(f"{capability_id} fallbacks must be an array")
        if not isinstance(item.get("detectors"), dict):
            raise CapabilityError(f"{capability_id} detectors must be an object")
        availability_requires = item.get("availability_requires")
        if (
            not isinstance(availability_requires, list)
            or not availability_requires
            or any(
                state not in STATE_FIELDS
                for state in availability_requires
            )
        ):
            raise CapabilityError(
                f"{capability_id} availability_requires must contain "
                "known state names"
            )
    return payload


def normalize_input(payload: Any) -> dict[str, dict[str, Any]]:
    """Normalize optional MCP/runtime discovery input by capability id."""
    if payload is None:
        return {}
    records: Any = payload
    if isinstance(payload, dict) and "capabilities" in payload:
        records = payload["capabilities"]

    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(records, dict):
        for capability_id, record in records.items():
            if isinstance(capability_id, str) and isinstance(record, dict):
                normalized[capability_id] = record
        return normalized

    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            capability_id = record.get("capability") or record.get("id")
            if isinstance(capability_id, str) and capability_id:
                normalized[capability_id] = record
        return normalized

    raise CapabilityError("input capabilities must be an object or array")


def input_record_for(
    capability: dict[str, Any],
    records: Mapping[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    capability_id = capability["id"]
    if capability_id in records:
        return capability_id, records[capability_id]
    aliases = capability.get("detectors", {}).get("input_aliases", [])
    for alias in aliases:
        if alias in records:
            return alias, records[alias]
    return None, None


def _derive_health(
    states: Mapping[str, bool],
    requested: Any = None,
) -> str:
    if requested is not None and requested not in HEALTH_VALUES:
        raise CapabilityError(f"unsupported capability health: {requested}")
    if requested == "ok" and not states["healthy"]:
        raise CapabilityError("health=ok requires healthy=true")
    if requested == "degraded" and states["healthy"]:
        raise CapabilityError("health=degraded requires healthy=false")
    if requested == "reachable" and not states["reachable"]:
        raise CapabilityError("health=reachable requires reachable=true")
    if requested == "configured" and not states["configured"]:
        raise CapabilityError("health=configured requires configured=true")
    if requested == "installed_only" and not states["installed"]:
        raise CapabilityError("health=installed_only requires installed=true")
    if requested in HEALTH_VALUES:
        return str(requested)
    if states["healthy"]:
        return "ok"
    if states["reachable"]:
        return "reachable"
    if states["configured"]:
        return "configured"
    if states["installed"]:
        return "installed_only"
    return "unavailable"


def _validate_state_coherence(
    capability: Mapping[str, Any],
    states: Mapping[str, bool],
    health: str,
) -> None:
    requirements = set(capability.get("availability_requires", STATE_FIELDS))
    if states["configured"] and not states["installed"]:
        raise CapabilityError("configured=true requires installed=true")
    if states["reachable"] and not states["installed"]:
        raise CapabilityError("reachable=true requires installed=true")
    if (
        states["reachable"]
        and "configured" in requirements
        and not states["configured"]
    ):
        raise CapabilityError("reachable=true requires configured=true")
    if states["healthy"] and not states["installed"]:
        raise CapabilityError("healthy=true requires installed=true")
    if (
        states["healthy"]
        and "reachable" in requirements
        and not states["reachable"]
    ):
        raise CapabilityError("healthy=true requires reachable=true")
    health_requirements = requirements & {
        "installed",
        "configured",
        "reachable",
        "healthy",
    }
    if health == "ok" and not all(
        states[field] for field in health_requirements
    ):
        raise CapabilityError(
            "health=ok requires all capability health prerequisites"
        )
    if health != "ok" and states["healthy"]:
        raise CapabilityError("healthy=true requires health=ok")


def _derive_available(
    capability: Mapping[str, Any],
    states: Mapping[str, bool],
) -> bool:
    requirements = capability.get("availability_requires", STATE_FIELDS)
    return all(states.get(field, False) for field in requirements)


def _checked_at(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    if not isinstance(value, str) or len(value) > 64:
        raise CapabilityError("input checked_at must be an ISO-8601 string")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CapabilityError("input checked_at must be an ISO-8601 string") from exc
    return value


def _states_from_v2_input(
    capability: Mapping[str, Any],
    record: Mapping[str, Any],
) -> tuple[dict[str, bool], bool, str]:
    states: dict[str, bool] = {}
    for field in STATE_FIELDS:
        value = record.get(field, False)
        if not isinstance(value, bool):
            raise CapabilityError(f"input {field} must be boolean")
        states[field] = value
    health = _derive_health(states, record.get("health"))
    _validate_state_coherence(capability, states, health)
    available = _derive_available(capability, states)
    declared_available = record.get("available")
    if (
        declared_available is not None
        and (
            not isinstance(declared_available, bool)
            or declared_available != available
        )
    ):
        raise CapabilityError(
            "v2 input available must equal the derived capability state"
        )
    return states, available, health


def _states_from_v1_input(
    record: Mapping[str, Any],
) -> tuple[dict[str, bool], bool, str]:
    available = record.get("available")
    if not isinstance(available, bool):
        raise CapabilityError(
            "v1 capability input requires boolean available"
        )
    requested_health = record.get("health")
    if requested_health is not None and requested_health not in HEALTH_VALUES:
        raise CapabilityError(
            f"unsupported capability health: {requested_health}"
        )
    health = (
        str(requested_health)
        if requested_health is not None
        else ("ok" if available else "unavailable")
    )
    states = {
        "installed": available,
        "configured": available,
        "reachable": available,
        "healthy": available and health == "ok",
        "permitted": available,
        "material_ready": available,
    }
    return states, available, health


def detect_one(
    capability: dict[str, Any],
    records: Mapping[str, dict[str, Any]],
    environ: Mapping[str, str],
    which: Callable[[str], str | None],
    checked_at: str,
) -> dict[str, Any]:
    capability_id = capability["id"]
    detectors = capability.get("detectors", {})
    source = "none"
    detected_by: str | None = None
    provider: str | None = None
    command_path: str | None = None
    states = {field: False for field in STATE_FIELDS}
    states["permitted"] = True
    available = False
    health = "unavailable"
    source_compatibility = "detector_v2"
    last_checked = checked_at
    version: str | None = None

    input_key, input_record = input_record_for(capability, records)
    if input_record is not None:
        provider = safe_name(input_record.get("provider"))
        command_path = safe_name(input_record.get("path"))
        source = "input"
        detected_by = safe_name(input_key)
        last_checked = _checked_at(
            input_record.get("checked_at"),
            checked_at,
        )
        version = safe_name(input_record.get("version"))
        if any(field in input_record for field in STATE_FIELDS):
            states, available, health = _states_from_v2_input(
                capability,
                input_record,
            )
            source_compatibility = "v2"
        else:
            states, available, health = _states_from_v1_input(input_record)
            source_compatibility = "v1"
    else:
        for env_name in detectors.get("environment", []):
            if isinstance(env_name, str) and environ.get(env_name):
                provider = safe_name(environ[env_name])
                source = "environment"
                detected_by = env_name
                states["installed"] = True
                states["configured"] = True
                health = "configured"
                break

    if source == "none":
        for command in detectors.get("commands", []):
            if not isinstance(command, str) or not SAFE_NAME_RE.fullmatch(command):
                continue
            if which(command):
                provider = command
                command_path = command
                source = "path"
                detected_by = command
                states["installed"] = True
                health = "installed_only"
                break

    if source != "input":
        available = _derive_available(capability, states)
        version = "detected" if states["installed"] else None

    return {
        "capability": capability_id,
        "kind": capability.get("kind", "unknown"),
        **states,
        "available": available,
        "provider": provider,
        "path": command_path,
        "source": source,
        "source_compatibility": source_compatibility,
        "detected_by": detected_by,
        "version": version,
        "last_checked": last_checked,
        "health": health,
        "provides": capability.get("provides", []),
        "fallbacks": capability.get("fallbacks", []),
        "unavailable_action": capability.get("unavailable_action"),
    }


def build_report(
    manifest_path: Path,
    input_path: Path | None = None,
    *,
    dry_run: bool = False,
    environ: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
    checked_at: str | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    input_payload = read_json(input_path, "input") if input_path else None
    records = normalize_input(input_payload)
    timestamp = checked_at or utc_now()
    environment = os.environ if environ is None else environ
    results = [
        detect_one(item, records, environment, which, timestamp)
        for item in manifest["capabilities"]
    ]
    summary = {
        state: sum(1 for item in results if item[state])
        for state in (
            "installed",
            "configured",
            "reachable",
            "healthy",
            "available",
        )
    }
    return {
        "ok": True,
        "tool": "detect_capabilities",
        "schema_version": "2.0",
        "generated_at": timestamp,
        "dry_run": dry_run,
        "manifest": display_path(manifest_path),
        "input": display_path(input_path),
        "summary": {
            "total": len(results),
            **summary,
            "unavailable": len(results) - summary["available"],
        },
        "capabilities": results,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only capability state detection. PATH hits are reported as "
            "installed_only; only healthy runtime input can become available."
        ),
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="JSON-compatible YAML manifest path.",
    )
    parser.add_argument(
        "--input",
        help=(
            "Optional v2 runtime probe JSON, or legacy v1 records containing "
            "only available/provider/health."
        ),
    )
    parser.add_argument(
        "--output",
        nargs="?",
        const=str(DEFAULT_OUTPUT),
        help="Write JSON cache; without a value uses .cybertest/capabilities.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Detect and print the report but never write --output.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = build_report(
            Path(args.manifest),
            Path(args.input) if args.input else None,
            dry_run=args.dry_run,
        )
        if args.output:
            report["would_write"] = display_path(Path(args.output))
            if not args.dry_run:
                write_report(Path(args.output), report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except CapabilityError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "tool": "detect_capabilities",
                    "error": str(exc),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
