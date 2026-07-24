#!/usr/bin/env python3
"""
Quality gate for cybertest scan pipeline runs.

Checks whether required reconnaissance phases completed, skipped,
or failed, and emits JSON plus an optional Markdown report.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from .cybertest_core.schema_validation import (
        load_json_document,
        validate_instance,
    )
except ImportError:
    from cybertest_core.schema_validation import (
        load_json_document,
        validate_instance,
    )


RECON_MODE_REQUIREMENTS: dict[str, list[str]] = {
    "quick": ["subfinder", "dnsx", "httpx", "katana", "gf", "nuclei"],
    "full": ["subfinder", "dnsx", "httpx", "tlsx", "naabu", "nmap", "katana", "history", "gf", "nuclei", "ffuf"],
    "deep": [
        "subfinder",
        "dnsx",
        "httpx",
        "tlsx",
        "naabu",
        "nmap",
        "katana",
        "history",
        "gf",
        "nuclei",
        "ffuf",
    ],
}

OFFLINE_SEMANTIC_PHASES = (
    "js_intel",
    "api_contract",
    "control_gap",
    "candidate_queue",
    "tactic_match",
)

MODE_REQUIREMENTS: dict[str, list[str]] = {
    mode: phases + list(OFFLINE_SEMANTIC_PHASES)
    for mode, phases in RECON_MODE_REQUIREMENTS.items()
}

EVIDENCE_ENVELOPE_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "agent"
    / "schemas"
    / "evidence-envelope.schema.json"
)

PHASE_RESULT_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    "subfinder": (("subdomains",), ("results",)),
    "dnsx": (("results",),),
    "httpx": (("results",),),
    "tlsx": (("results",),),
    "naabu": (("results",),),
    "nmap": (("nmap", "hosts"), ("hosts",), ("results",)),
    "katana": (("results",),),
    "history": (("results",), ("urls",)),
    "gf": (("patterns",), ("results",)),
    "nuclei": (("results",), ("findings",)),
    "ffuf": (("results",),),
}

ROUTE_STATUSES_WITHOUT_TACTIC = {
    "route_gap",
    "blocked_need_material",
    "blocked_need_capability",
    "policy_conflict",
}

ATTACK_SURFACE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "id": "js_chunks",
        "label": "JavaScript chunks",
        "aliases": ("js_chunks", "javascript_chunks", "script_assets"),
        "patterns": (r"\.js(?:[?#]|$)", r"(?:^|[/_.-])chunk[-_.]"),
    },
    {
        "id": "source_maps",
        "label": "source maps",
        "aliases": ("source_maps", "sourcemaps", "map_files"),
        "patterns": (r"\.(?:js|css)\.map(?:[?#]|$)", r"sourceMappingURL"),
    },
    {
        "id": "api_base",
        "label": "API bases",
        "aliases": ("api_bases", "api_base_urls", "api_roots"),
        "patterns": (r"://api\.", r"/api(?:/|[?#]|$)", r"/v[0-9]+(?:/|[?#]|$)"),
    },
    {
        "id": "api_docs",
        "label": "Swagger/OpenAPI/GraphQL surfaces",
        "aliases": ("api_docs", "swagger", "openapi", "graphql"),
        "patterns": (r"swagger", r"openapi", r"api-docs", r"graphql"),
    },
    {
        "id": "login",
        "label": "login surfaces",
        "aliases": ("login_surfaces", "login_endpoints", "signin_endpoints"),
        "patterns": (r"(?:^|[/_.-])login(?:[/_.?#-]|$)", r"(?:^|[/_.-])signin(?:[/_.?#-]|$)"),
    },
    {
        "id": "oauth",
        "label": "OAuth/OIDC surfaces",
        "aliases": ("oauth_surfaces", "oauth_endpoints", "oidc_endpoints"),
        "patterns": (r"oauth", r"oidc", r"/authorize(?:[/?.#]|$)"),
    },
    {
        "id": "upload",
        "label": "upload surfaces",
        "aliases": ("upload_surfaces", "upload_endpoints"),
        "patterns": (r"(?:^|[/_.-])upload(?:[/_.?#-]|$)",),
    },
    {
        "id": "download",
        "label": "download surfaces",
        "aliases": ("download_surfaces", "download_endpoints"),
        "patterns": (r"(?:^|[/_.-])download(?:[/_.?#-]|$)",),
    },
    {
        "id": "import_export",
        "label": "import/export surfaces",
        "aliases": ("import_export_surfaces", "import_endpoints", "export_endpoints"),
        "patterns": (
            r"(?:^|[/_.-])import(?:[/_.?#-]|$)",
            r"(?:^|[/_.-])export(?:[/_.?#-]|$)",
        ),
    },
    {
        "id": "nonproduction",
        "label": "test/pre/dev/staging surfaces",
        "aliases": ("nonproduction_surfaces", "nonprod_hosts", "test_environments"),
        "patterns": (
            r"(?:^|[./_-])(?:test|pre|dev|staging|uat|beta|sandbox)(?:[./_:-]|$)",
        ),
    },
)

VULNERABILITY_ARRAY_KEYS = ("vulnerabilities", "findings", "items", "risks")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def read_json_checked(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, f"declared JSON input does not exist: {path}"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"declared JSON input is not parseable: {path}: {exc}"
    if not isinstance(document, dict):
        return None, f"declared JSON input must contain an object: {path}"
    return document, None


def uses_legacy_quality_gate_alias(state: dict[str, Any]) -> bool:
    requested = state.get("phases_requested")
    return (
        isinstance(requested, list)
        and "quality_gate" in requested
        and "semantic_quality_gate" not in requested
    )


def requires_offline_semantic_chain(state: dict[str, Any]) -> bool:
    requested = state.get("phases_requested")
    if isinstance(requested, list) and "semantic_quality_gate" in requested:
        return True
    if uses_legacy_quality_gate_alias(state):
        return False
    return str(state.get("state_version", "")).startswith("2")


def required_phases_for_state(
    mode: str,
    state: dict[str, Any],
) -> list[str]:
    if requires_offline_semantic_chain(state):
        return list(MODE_REQUIREMENTS.get(mode, MODE_REQUIREMENTS["full"]))
    return list(
        RECON_MODE_REQUIREMENTS.get(mode, RECON_MODE_REQUIREMENTS["full"])
    )


def semantic_item(
    check_id: str,
    category: str,
    status: str,
    message: str,
    phase: str = "semantic",
    evidence: Any = None,
) -> dict[str, Any]:
    item = {
        "id": check_id,
        "category": category,
        "phase": phase,
        "status": status,
        "message": message,
    }
    if evidence is not None:
        item["evidence"] = evidence
    return item


def nested_value(document: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
    return value


def explicit_results(document: dict[str, Any], phase: str) -> list[Any] | None:
    for path in PHASE_RESULT_PATHS.get(phase, (("results",),)):
        value = nested_value(document, path)
        if isinstance(value, list):
            return value
    return None


def resolve_output_path(pipeline_dir: Path, raw_path: Any) -> Path | None:
    if not isinstance(raw_path, str) or not raw_path:
        return None
    path = Path(raw_path)
    if path.is_absolute():
        return path
    return pipeline_dir / path


def load_phase_documents(
    pipeline_dir: Path,
    state: dict[str, Any],
) -> dict[str, dict[str, Any] | None]:
    documents: dict[str, dict[str, Any] | None] = {}
    for phase, details in state.get("phase_outputs", {}).items():
        if not isinstance(details, dict):
            documents[phase] = None
            continue
        path = resolve_output_path(pipeline_dir, details.get("output_file"))
        if path and path.is_file():
            documents[phase], _error = read_json_checked(path)
        else:
            documents[phase] = None
    return documents


def load_consistency_inputs(
    pipeline_dir: Path,
    state: dict[str, Any],
    documents: dict[str, dict[str, Any] | None],
    *,
    report_path: str | None = None,
    vulnerability_archive_path: str | None = None,
) -> list[dict[str, Any]]:
    """Load explicitly supplied or state-declared consistency documents."""

    checks: list[dict[str, Any]] = []
    declarations = (
        (
            "report",
            report_path,
            ("report_file", "report_path", "report"),
        ),
        (
            "vulnerability_archive",
            vulnerability_archive_path,
            (
                "vulnerability_archive_file",
                "vulnerability_archive_path",
                "vulnerability_archive",
            ),
        ),
    )
    for document_key, cli_value, state_keys in declarations:
        declared: Any = cli_value
        source = "CLI"
        if declared is None:
            source = "pipeline state"
            for state_key in state_keys:
                if state_key in state:
                    declared = state[state_key]
                    break
        if declared is None:
            continue
        if isinstance(declared, dict):
            documents[document_key] = declared
            checks.append(
                semantic_item(
                    f"report_consistency.input.{document_key}",
                    "report_consistency",
                    "PASS",
                    f"{document_key} was loaded from {source}.",
                    document_key,
                )
            )
            continue
        if not isinstance(declared, str) or not declared.strip():
            checks.append(
                semantic_item(
                    f"report_consistency.input.{document_key}",
                    "report_consistency",
                    "FAIL",
                    f"{document_key} was declared by {source} but is not a path or object.",
                    document_key,
                )
            )
            documents[document_key] = None
            continue
        path = Path(declared)
        if not path.is_absolute():
            path = pipeline_dir / path
        document, error = read_json_checked(path)
        if error:
            checks.append(
                semantic_item(
                    f"report_consistency.input.{document_key}",
                    "report_consistency",
                    "FAIL",
                    error,
                    document_key,
                    {"path": str(path), "source": source},
                )
            )
            documents[document_key] = None
            continue
        documents[document_key] = document
        checks.append(
            semantic_item(
                f"report_consistency.input.{document_key}",
                "report_consistency",
                "PASS",
                f"{document_key} was loaded from {path}.",
                document_key,
            )
        )
    return checks


def iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_dicts(child)


def iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from iter_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_strings(child)


def normalized_host(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower().rstrip(".")
    if "://" in text:
        return (urlparse(text).hostname or "").rstrip(".")
    text = text.split("/", 1)[0]
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.rstrip(".")


def phase_hosts(document: dict[str, Any]) -> tuple[set[str], bool]:
    hosts: set[str] = set()
    semantic_fields_seen = False
    for key in ("target", "targets", "input", "inputs"):
        if key not in document:
            continue
        semantic_fields_seen = True
        values = document[key] if isinstance(document[key], list) else [document[key]]
        for value in values:
            host = normalized_host(value)
            if host:
                hosts.add(host)
    for record in explicit_results(document, "httpx") or []:
        if not isinstance(record, dict):
            continue
        for key in ("host", "input", "url", "name", "domain"):
            if key in record:
                semantic_fields_seen = True
                host = normalized_host(record[key])
                if host:
                    hosts.add(host)
    return hosts, semantic_fields_seen


def evaluate_coverage(
    state: dict[str, Any],
    documents: dict[str, dict[str, Any] | None],
    required: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    root_domain = normalized_host(state.get("domain"))
    if not root_domain:
        checks.append(
            semantic_item(
                "coverage.root_domain",
                "coverage",
                "WARN",
                "pipeline state has no root domain; root coverage cannot be verified.",
            )
        )
    else:
        for phase in ("dnsx", "httpx"):
            document = documents.get(phase)
            if document is None:
                checks.append(
                    semantic_item(
                        f"coverage.root_domain.{phase}",
                        "coverage",
                        "WARN",
                        f"{phase} output is unavailable; root coverage cannot be verified.",
                        phase,
                    )
                )
                continue
            hosts, fields_seen = phase_hosts(document)
            if root_domain in hosts:
                status = "PASS"
                message = f"root domain {root_domain} is present in {phase} input or results."
            elif fields_seen:
                status = "FAIL"
                message = f"root domain {root_domain} is explicitly absent from {phase} input and results."
            else:
                status = "WARN"
                message = f"{phase} output lacks input/result host fields; root coverage is unknown."
            checks.append(
                semantic_item(
                    f"coverage.root_domain.{phase}",
                    "coverage",
                    status,
                    message,
                    phase,
                    {"root_domain": root_domain, "observed_hosts": sorted(hosts)},
                )
            )

    for phase in required:
        if phase in OFFLINE_SEMANTIC_PHASES:
            continue
        details = state.get("phase_outputs", {}).get(phase)
        if not isinstance(details, dict) or not details.get("ok"):
            continue
        document = documents.get(phase)
        if document is None:
            checks.append(
                semantic_item(
                    f"coverage.output.{phase}",
                    "coverage",
                    "WARN",
                    "phase is marked ok but its output cannot be read.",
                    phase,
                )
            )
            continue
        results = explicit_results(document, phase)
        if results is None:
            checks.append(
                semantic_item(
                    f"coverage.output.{phase}",
                    "coverage",
                    "WARN",
                    "phase is marked ok but has no recognized semantic result field.",
                    phase,
                )
            )
        elif not results:
            status = "FAIL" if phase in {"dnsx", "httpx"} else "WARN"
            checks.append(
                semantic_item(
                    f"coverage.output.{phase}",
                    "coverage",
                    status,
                    "phase is marked ok but its explicit result collection is empty.",
                    phase,
                    {"result_count": 0},
                )
            )
        else:
            checks.append(
                semantic_item(
                    f"coverage.output.{phase}",
                    "coverage",
                    "PASS",
                    "phase has a non-empty semantic result collection.",
                    phase,
                    {"result_count": len(results)},
                )
            )
    return checks


def fake_ip_checks(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if document is None:
        return []
    records = explicit_results(document, "dnsx")
    if records is None:
        return [
            semantic_item(
                "noise.fake_ip",
                "noise",
                "WARN",
                "dnsx output has no result records for Fake-IP review.",
                "dnsx",
            )
        ]
    flags_seen = False
    unverified = 0
    fake_count = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        flags = record.get("codex_dns_flags")
        if not isinstance(flags, dict):
            continue
        flags_seen = True
        if not flags.get("fake_ip"):
            continue
        fake_count += 1
        verified = any(
            flags.get(key) is True
            for key in (
                "external_verified",
                "trusted_resolver_verified",
                "doh_verified",
                "fake_ip_rechecked",
            )
        ) or flags.get("verification_status") in {"verified", "rechecked"}
        if not verified:
            unverified += 1
    if not flags_seen:
        status, message = "WARN", "dnsx output lacks Fake-IP classification fields."
    elif unverified:
        status, message = "FAIL", f"{unverified} Fake-IP result(s) lack trusted external recheck."
    else:
        status, message = "PASS", f"Fake-IP review is complete ({fake_count} flagged result(s))."
    return [
        semantic_item(
            "noise.fake_ip",
            "noise",
            status,
            message,
            "dnsx",
            {"fake_ip_count": fake_count, "unverified_count": unverified},
        )
    ]


def http_noise_checks(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if document is None:
        return []
    records = explicit_results(document, "httpx")
    if records is None:
        return [
            semantic_item(
                "noise.http",
                "noise",
                "WARN",
                "httpx output has no result records for noise analysis.",
                "httpx",
            )
        ]
    if not records:
        return []

    spa_seen = False
    spa_count = 0
    hashes: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        spa_value = record.get("spa_fallback")
        if spa_value is None and isinstance(record.get("codex_http_flags"), dict):
            spa_value = record["codex_http_flags"].get("spa_fallback")
        if spa_value is not None:
            spa_seen = True
            spa_count += int(bool(spa_value))
        body_hash = (
            record.get("body_hash")
            or record.get("body_sha256")
            or record.get("content_hash")
        )
        if isinstance(body_hash, str) and body_hash:
            hashes.append(body_hash)

    checks: list[dict[str, Any]] = []
    if not spa_seen:
        spa_status, spa_message = "WARN", "httpx output lacks SPA fallback classification."
    else:
        ratio = spa_count / len(records)
        spa_status = "FAIL" if ratio >= 0.5 else ("WARN" if spa_count else "PASS")
        spa_message = f"SPA fallback ratio is {ratio:.0%} ({spa_count}/{len(records)})."
    checks.append(
        semantic_item(
            "noise.http.spa_fallback",
            "noise",
            spa_status,
            spa_message,
            "httpx",
        )
    )

    if len(hashes) < 2:
        hash_status, hash_message = "WARN", "fewer than two HTTP body hashes; duplicate-body noise is unknown."
    else:
        count = Counter(hashes).most_common(1)[0][1]
        ratio = count / len(hashes)
        hash_status = "FAIL" if len(hashes) >= 3 and ratio >= 0.8 else ("WARN" if ratio >= 0.5 else "PASS")
        hash_message = f"largest identical body-hash group is {ratio:.0%} ({count}/{len(hashes)})."
    checks.append(
        semantic_item(
            "noise.http.body_hash",
            "noise",
            hash_status,
            hash_message,
            "httpx",
        )
    )
    return checks


def nmap_noise_checks(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if document is None:
        return []
    records = explicit_results(document, "nmap")
    if records is None:
        return [
            semantic_item(
                "noise.nmap",
                "noise",
                "WARN",
                "nmap output lacks host/port fields for all-open and tcpwrapped analysis.",
                "nmap",
            )
        ]
    all_open = any(
        item.get("all_open") is True or item.get("all_ports_open") is True
        for item in iter_dicts(document)
    )
    services: list[str] = []
    for host in records:
        if not isinstance(host, dict):
            continue
        for port in host.get("ports", []):
            if not isinstance(port, dict):
                continue
            service = port.get("service")
            if isinstance(service, dict):
                service = service.get("name")
            if isinstance(service, str):
                services.append(service.lower())
    wrapped = sum(service == "tcpwrapped" for service in services)
    ratio = wrapped / len(services) if services else 0.0
    if all_open:
        status, message = "FAIL", "nmap output explicitly reports an all-open condition."
    elif len(services) >= 5 and ratio >= 0.8:
        status, message = "FAIL", f"tcpwrapped ratio is {ratio:.0%}."
    elif services and ratio >= 0.5:
        status, message = "WARN", f"tcpwrapped ratio is {ratio:.0%}."
    elif services:
        status, message = "PASS", f"tcpwrapped ratio is {ratio:.0%}."
    else:
        status, message = "WARN", "nmap service fields are absent; tcpwrapped noise is unknown."
    return [semantic_item("noise.nmap", "noise", status, message, "nmap")]


def _attack_surface_coverage_value(
    documents: dict[str, dict[str, Any] | None],
    aliases: tuple[str, ...],
) -> tuple[bool, Any]:
    """Return explicit coverage metadata without treating arbitrary text as proof."""

    for document in documents.values():
        if not isinstance(document, dict):
            continue
        containers: list[dict[str, Any]] = [document]
        for key in ("attack_surface_coverage", "coverage"):
            value = document.get(key)
            if isinstance(value, dict):
                containers.append(value)
                nested = value.get("attack_surface")
                if isinstance(nested, dict):
                    containers.append(nested)
        for container in containers:
            for alias in aliases:
                if alias in container:
                    return True, container[alias]
    return False, None


def _explicit_coverage_result(value: Any) -> tuple[str, str] | None:
    if isinstance(value, bool):
        return (
            ("PASS", "explicit coverage metadata marks this surface as checked.")
            if value
            else ("FAIL", "explicit coverage metadata marks this surface as not checked.")
        )
    if isinstance(value, list):
        return "PASS", f"explicit coverage collection is present ({len(value)} item(s))."
    if isinstance(value, dict):
        for key in ("checked", "covered", "executed"):
            if isinstance(value.get(key), bool):
                return (
                    ("PASS", f"explicit coverage metadata has {key}=true.")
                    if value[key]
                    else ("FAIL", f"explicit coverage metadata has {key}=false.")
                )
        status = str(value.get("status", "")).strip().lower()
        if status in {"pass", "passed", "complete", "completed", "checked"}:
            return "PASS", f"explicit coverage metadata reports status={status}."
        if status in {"fail", "failed", "not_checked", "not-covered", "missing"}:
            return "FAIL", f"explicit coverage metadata reports status={status}."
    return None


def evaluate_attack_surface(
    documents: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Check whether high-value Web attack-surface families have evidence."""

    searchable_documents = {
        key: document
        for key, document in documents.items()
        if key
        in {
            "httpx",
            "katana",
            "history",
            "gf",
            "js_intel",
            "api_contract",
            "control_gap",
            "candidate_queue",
            "attack_surface",
        }
        and isinstance(document, dict)
    }
    observed_strings = [
        text
        for document in searchable_documents.values()
        for text in iter_strings(document)
    ]
    checks: list[dict[str, Any]] = []
    for spec in ATTACK_SURFACE_SPECS:
        explicit, raw_value = _attack_surface_coverage_value(
            documents,
            spec["aliases"],
        )
        explicit_result = _explicit_coverage_result(raw_value) if explicit else None
        matches = [
            text
            for text in observed_strings
            if any(
                re.search(pattern, text, re.IGNORECASE)
                for pattern in spec["patterns"]
            )
        ]
        if explicit_result is not None:
            status, message = explicit_result
        elif matches:
            status = "PASS"
            message = f"{spec['label']} have structured or URL evidence."
        else:
            status = "WARN"
            message = (
                f"no explicit coverage metadata or observed evidence for "
                f"{spec['label']}; absence is not treated as a finding."
            )
        checks.append(
            semantic_item(
                f"attack_surface.{spec['id']}",
                "attack_surface",
                status,
                message,
                "attack_surface",
                {
                    "observed_count": len(matches),
                    "samples": matches[:3],
                    "explicit_coverage": explicit,
                },
            )
        )

    history = documents.get("history")
    if isinstance(history, dict):
        results = explicit_results(history, "history")
        if results is not None:
            checks.append(
                semantic_item(
                    "attack_surface.history_urls",
                    "attack_surface",
                    "PASS",
                    f"historical URL collection was executed ({len(results)} result(s)).",
                    "history",
                    {"result_count": len(results)},
                )
            )
        else:
            checks.append(
                semantic_item(
                    "attack_surface.history_urls",
                    "attack_surface",
                    "WARN",
                    "history output exists but has no recognized URL collection.",
                    "history",
                )
            )
    else:
        checks.append(
            semantic_item(
                "attack_surface.history_urls",
                "attack_surface",
                "WARN",
                "historical URL output is unavailable; coverage cannot be verified.",
                "history",
            )
        )
    return checks


def _vulnerability_entries(document: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    if not isinstance(document, dict):
        return None
    for key in VULNERABILITY_ARRAY_KEYS:
        value = document.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return None


def _first_document(
    documents: dict[str, dict[str, Any] | None],
    names: tuple[str, ...],
) -> dict[str, Any] | None:
    for name in names:
        value = documents.get(name)
        if isinstance(value, dict):
            return value
    return None


def _count_value(container: dict[str, Any], aliases: tuple[str, ...]) -> tuple[bool, Any]:
    for alias in aliases:
        if alias in container:
            return True, container[alias]
    return False, None


def _entity_count_check(report: dict[str, Any] | None) -> dict[str, Any]:
    if report is None:
        return semantic_item(
            "report_consistency.entity_counts",
            "report_consistency",
            "WARN",
            "report data is unavailable; total/sample/unique separation cannot be verified.",
            "report",
        )
    containers = [
        value
        for key in ("entity_counts", "report_metrics", "data_counts")
        if isinstance((value := report.get(key)), dict)
    ]
    if not containers:
        aliases = {
            "server_declared_total",
            "declared_total",
            "sample_rows",
            "sample_count",
            "unique_entities",
            "unique_entity_count",
        }
        if aliases.intersection(report):
            containers = [report]
    if not containers:
        return semantic_item(
            "report_consistency.entity_counts",
            "report_consistency",
            "WARN",
            "report has no structured entity-count metrics.",
            "report",
        )

    container = containers[0]
    found_total, total = _count_value(
        container,
        ("server_declared_total", "declared_total", "total_count", "total"),
    )
    found_sample, sample = _count_value(
        container,
        ("sample_rows", "sample_count", "actual_sample_rows", "sampled_rows"),
    )
    found_unique, unique = _count_value(
        container,
        ("unique_entities", "unique_entity_count", "distinct_entities", "unique_count"),
    )
    missing = [
        name
        for name, found in (
            ("server_declared_total", found_total),
            ("sample_rows", found_sample),
            ("unique_entities", found_unique),
        )
        if not found
    ]
    values = (total, sample, unique)
    invalid = any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        for value in values
        if value is not None
    )
    inconsistent = (
        not missing
        and not invalid
        and (sample > total or unique > sample)
    )
    if missing:
        status, message = "FAIL", f"entity-count metrics are not separated; missing {', '.join(missing)}."
    elif invalid:
        status, message = "FAIL", "entity-count metrics must be non-negative integers."
    elif inconsistent:
        status, message = "FAIL", "entity-count metrics violate unique_entities <= sample_rows <= server_declared_total."
    else:
        status, message = "PASS", "server total, sampled rows, and unique entities are explicitly separated."
    return semantic_item(
        "report_consistency.entity_counts",
        "report_consistency",
        status,
        message,
        "report",
        {
            "server_declared_total": total,
            "sample_rows": sample,
            "unique_entities": unique,
        },
    )


def _archive_total_check(archive: dict[str, Any] | None) -> dict[str, Any]:
    if archive is None:
        return semantic_item(
            "report_consistency.archive_totals",
            "report_consistency",
            "WARN",
            "vulnerability archive JSON is unavailable; totals cannot be verified.",
            "vulnerability_archive",
        )
    entries = _vulnerability_entries(archive)
    if entries is None:
        return semantic_item(
            "report_consistency.archive_totals",
            "report_consistency",
            "WARN",
            "vulnerability archive has no recognized entry array.",
            "vulnerability_archive",
        )
    total_containers = [
        value
        for key in ("totals", "summary")
        if isinstance((value := archive.get(key)), dict)
    ]
    total_containers.append(archive)
    declared_total: Any = None
    for container in total_containers:
        found, value = _count_value(
            container,
            ("total", "total_entries", "total_vulnerabilities", "item_count"),
        )
        if found:
            declared_total = value
            break
    if declared_total is None:
        return semantic_item(
            "report_consistency.archive_totals",
            "report_consistency",
            "WARN",
            "archive entries exist but JSON totals are not explicitly declared.",
            "vulnerability_archive",
            {"actual_total": len(entries)},
        )
    if (
        isinstance(declared_total, bool)
        or not isinstance(declared_total, int)
        or declared_total < 0
    ):
        status, message = "FAIL", "archive total must be a non-negative integer."
    elif declared_total != len(entries):
        status, message = "FAIL", f"archive declares {declared_total} entries but contains {len(entries)}."
    else:
        status, message = "PASS", f"archive total matches its {len(entries)} entry array."
    return semantic_item(
        "report_consistency.archive_totals",
        "report_consistency",
        status,
        message,
        "vulnerability_archive",
        {"declared_total": declared_total, "actual_total": len(entries)},
    )


def _entry_identity(entry: dict[str, Any]) -> str:
    return str(entry.get("id") or entry.get("candidate_id") or "")


def _requires_rating_review(entry: dict[str, Any]) -> bool:
    return str(entry.get("severity", "")).strip().lower() in {
        "medium",
        "high",
        "critical",
        "中危",
        "高危",
    }


def _rating_review_check(
    archive: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    archive_entries = _vulnerability_entries(archive)
    if archive_entries is None:
        return semantic_item(
            "report_consistency.rating_review",
            "report_consistency",
            "WARN",
            "archive entries are unavailable; rating_review coverage cannot be verified.",
            "vulnerability_archive",
        )
    report_entries = _vulnerability_entries(report)
    report_by_id = {
        _entry_identity(entry): entry
        for entry in report_entries or []
        if _entry_identity(entry)
    }
    required = [entry for entry in archive_entries if _requires_rating_review(entry)]
    missing: list[str] = []
    inconsistent: list[str] = []
    for entry in required:
        entry_id = _entry_identity(entry) or "<unknown>"
        review = entry.get("rating_review")
        if not isinstance(review, dict) or not review:
            missing.append(entry_id)
            continue
        report_entry = report_by_id.get(entry_id)
        if report_entry is not None:
            report_review = report_entry.get("rating_review")
            if not isinstance(report_review, dict) or not report_review:
                missing.append(f"report:{entry_id}")
            elif report_review != review:
                inconsistent.append(entry_id)
    if missing:
        status, message = "FAIL", f"medium/high entries lack rating_review: {', '.join(missing)}."
    elif inconsistent:
        status, message = "FAIL", f"rating_review differs between archive and report: {', '.join(inconsistent)}."
    elif report is None:
        status, message = "WARN", "archive rating_review fields are present, but report data is unavailable for comparison."
    else:
        status, message = "PASS", f"rating_review is present and consistent for {len(required)} medium/high entry(s)."
    return semantic_item(
        "report_consistency.rating_review",
        "report_consistency",
        status,
        message,
        "vulnerability_archive",
    )


def _do_not_overclaim_check(
    archive: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> dict[str, Any]:
    if report is None:
        return semantic_item(
            "report_consistency.do_not_overclaim",
            "report_consistency",
            "WARN",
            "report data is unavailable; do_not_overclaim compliance cannot be verified.",
            "report",
        )
    explicit_violations = report.get("do_not_overclaim_violations")
    if isinstance(explicit_violations, list) and explicit_violations:
        return semantic_item(
            "report_consistency.do_not_overclaim",
            "report_consistency",
            "FAIL",
            f"report declares {len(explicit_violations)} do_not_overclaim violation(s).",
            "report",
        )
    if report.get("do_not_overclaim_compliant") is False:
        return semantic_item(
            "report_consistency.do_not_overclaim",
            "report_consistency",
            "FAIL",
            "report explicitly marks do_not_overclaim compliance as false.",
            "report",
        )

    archive_entries = _vulnerability_entries(archive) or []
    boundaries = {
        _entry_identity(entry): entry["do_not_overclaim"]
        for entry in archive_entries
        if _entry_identity(entry)
        and isinstance(entry.get("do_not_overclaim"), str)
        and entry["do_not_overclaim"].strip()
    }
    report_entries = _vulnerability_entries(report) or []
    compared = 0
    violations: list[str] = []
    for entry in report_entries:
        entry_id = _entry_identity(entry)
        if entry_id not in boundaries:
            continue
        compared += 1
        if entry.get("do_not_overclaim") != boundaries[entry_id]:
            violations.append(entry_id)
        if entry.get("overclaim_detected") is True:
            violations.append(entry_id)
    if violations:
        status, message = "FAIL", f"report does not preserve do_not_overclaim boundary for {', '.join(sorted(set(violations)))}."
    elif report.get("do_not_overclaim_compliant") is True:
        status, message = "PASS", "report explicitly records do_not_overclaim compliance."
    elif compared:
        status, message = "PASS", f"report preserves {compared} archive do_not_overclaim boundary/boundaries."
    else:
        status, message = "WARN", "no comparable do_not_overclaim boundary was found in archive and report."
    return semantic_item(
        "report_consistency.do_not_overclaim",
        "report_consistency",
        status,
        message,
        "report",
    )


def evaluate_report_consistency(
    documents: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    report = _first_document(documents, ("report", "final_report", "report_data"))
    archive = _first_document(
        documents,
        ("vulnerability_archive", "archive", "vulnerabilities"),
    )
    return [
        _entity_count_check(report),
        _archive_total_check(archive),
        _rating_review_check(archive, report),
        _do_not_overclaim_check(archive, report),
    ]


MATRIX_ROLE_TO_VARIANT = {
    "baseline": "baseline",
    "positive_control": "positive-control",
    "negative_control": "negative-control",
    "candidate_probe": "candidate-probe",
    "readback": "readback",
    "rollback": "rollback",
}


def _matrix_binding(
    envelope: dict[str, Any],
    matrix_roles: dict[str, str],
) -> str | None:
    candidates = [envelope.get("request_id")]
    observation = envelope.get("observation")
    if isinstance(observation, dict):
        candidates.append(observation.get("matrix_request_id"))
    for value in candidates:
        if isinstance(value, str) and value in matrix_roles:
            return value
    return None


def _task_evidence_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    path = Path(value)
    return (
        not path.is_absolute()
        and len(path.parts) >= 2
        and path.parts[0] == "evidence"
        and ".." not in path.parts
    )


def confirmed_evidence_gaps(
    candidate: dict[str, Any],
    candidate_id: str,
) -> list[str]:
    """Return gaps in executed, matrix-bound, schema-valid evidence."""

    envelopes = candidate.get("evidence_envelopes")
    if not isinstance(envelopes, list) or not envelopes:
        return ["evidence_envelopes"]

    contract = candidate.get("validation_contract")
    request_matrix = (
        contract.get("request_matrix", [])
        if isinstance(contract, dict)
        else []
    )
    matrix_roles: dict[str, str] = {}
    gaps: list[str] = []
    for index, item in enumerate(request_matrix):
        if not isinstance(item, dict):
            gaps.append(f"validation_contract.request_matrix[{index}].invalid")
            continue
        request_id = item.get("id")
        role = item.get("role")
        if (
            not isinstance(request_id, str)
            or not request_id.strip()
            or role not in MATRIX_ROLE_TO_VARIANT
        ):
            gaps.append(f"validation_contract.request_matrix[{index}].invalid")
            continue
        if request_id in matrix_roles:
            gaps.append("validation_contract.request_matrix.duplicate_id")
            continue
        matrix_roles[request_id] = str(role)

    required_role_groups = (
        ({"baseline", "positive_control"}, "positive_control"),
        ({"negative_control"}, "negative_control"),
        ({"candidate_probe"}, "candidate_probe"),
    )
    for roles, label in required_role_groups:
        if not roles.intersection(matrix_roles.values()):
            gaps.append(f"validation_contract.request_matrix.{label}")

    schema = load_json_document(EVIDENCE_ENVELOPE_SCHEMA)
    bound_envelopes: list[tuple[dict[str, Any], str, int]] = []
    evidence_ids: list[str] = []
    matched_tactic_ids = {
        item.get("id")
        for item in candidate.get("matched_tactics", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for index, envelope in enumerate(envelopes):
        if not isinstance(envelope, dict):
            gaps.append(f"evidence_envelopes[{index}].invalid")
            continue
        errors = validate_instance(envelope, schema)
        if errors:
            gaps.append(f"evidence_envelopes[{index}].schema")
            continue
        if envelope.get("candidate_id") != candidate_id:
            gaps.append(f"evidence_envelopes[{index}].candidate_id")
            continue
        if (
            matched_tactic_ids
            and envelope.get("tactic_id") not in matched_tactic_ids
        ):
            gaps.append(f"evidence_envelopes[{index}].tactic_id")
            continue
        references = envelope.get("evidence_refs", [])
        if not all(_task_evidence_reference(item) for item in references):
            gaps.append(f"evidence_envelopes[{index}].evidence_refs")
            continue
        binding = _matrix_binding(envelope, matrix_roles)
        if binding is None:
            gaps.append(f"evidence_envelopes[{index}].matrix_binding")
            continue
        role = matrix_roles[binding]
        if envelope.get("control_variant") != MATRIX_ROLE_TO_VARIANT[role]:
            gaps.append(f"evidence_envelopes[{index}].matrix_role")
            continue
        bound_envelopes.append((envelope, role, index))
        evidence_ids.append(str(envelope["evidence_id"]))

    if len(evidence_ids) != len(set(evidence_ids)):
        gaps.append("evidence_envelopes.duplicate_id")

    evidence_ref_roles: dict[str, str] = {}
    for envelope, role, _index in bound_envelopes:
        for reference in envelope["evidence_refs"]:
            prior_role = evidence_ref_roles.setdefault(reference, role)
            if prior_role != role:
                gaps.append("evidence_envelopes.cross_role_evidence_ref_reuse")

    executed_roles = {role for _envelope, role, _index in bound_envelopes}
    if not executed_roles.intersection({"baseline", "positive_control"}):
        gaps.append("executed_positive_control")
    if "negative_control" not in executed_roles:
        gaps.append("executed_negative_control")
    if "candidate_probe" not in executed_roles:
        gaps.append("executed_candidate_probe")

    observed_invariants: set[str] = set()
    for envelope, _role, index in bound_envelopes:
        observation = envelope["observation"]
        invariant_results = observation.get("invariant_results", {})
        for invariant in envelope.get("invariants_checked", []):
            result = (
                invariant_results.get(invariant)
                if isinstance(invariant_results, dict)
                else None
            )
            if not isinstance(result, str) or not result.strip():
                gaps.append(
                    f"evidence_envelopes[{index}].invariant_observation"
                )
                continue
            observed_invariants.add(invariant)

    required_invariants = {
        invariant
        for invariant in candidate.get("evidence_invariants", [])
        if isinstance(invariant, str) and invariant.strip()
    }
    if not required_invariants:
        gaps.append("evidence_invariants")
    elif not required_invariants.issubset(observed_invariants):
        gaps.append("executed_evidence_invariants")

    stateful = candidate.get("safe_validation_level") in {
        "test_object",
        "authorized_side_effect",
    }
    if stateful:
        for role in ("readback", "rollback"):
            if role not in matrix_roles.values():
                gaps.append(f"validation_contract.request_matrix.{role}")
        if "readback" not in executed_roles:
            gaps.append("executed_readback")
        rollback_envelopes = [
            envelope
            for envelope, role, _index in bound_envelopes
            if role == "rollback"
        ]
        if not rollback_envelopes:
            gaps.append("executed_rollback")
        elif not any(
            envelope.get("rollback_status") == "completed"
            and isinstance(envelope.get("state_before"), dict)
            and bool(envelope["state_before"])
            and isinstance(envelope.get("state_after"), dict)
            and bool(envelope["state_after"])
            for envelope in rollback_envelopes
        ):
            gaps.append("completed_rollback_state")

        rollback_plan = candidate.get("rollback_plan")
        if (
            not isinstance(rollback_plan, dict)
            or rollback_plan.get("status") != "completed"
        ):
            gaps.append("rollback_plan.completed")

    return list(dict.fromkeys(gaps))


def evaluate_candidate_closure(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if document is None:
        return [
            semantic_item(
                "candidate_closure.available",
                "candidate_closure",
                "WARN",
                "candidate queue output is unavailable; closure semantics cannot be verified.",
                "candidate_queue",
            )
        ]
    candidates = document.get("candidates")
    if not isinstance(candidates, list):
        return [
            semantic_item(
                "candidate_closure.available",
                "candidate_closure",
                "WARN",
                "candidate queue output has no candidates array.",
                "candidate_queue",
            )
        ]
    checks: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        candidate_id = str(candidate.get("id") or f"candidate-{index + 1}")
        status = candidate.get("status")
        is_v2 = candidate.get("schema_version") == "2.0"
        if (
            is_v2
            and candidate.get("queue") == "P0"
            and status == "discovered"
        ):
            checks.append(
                semantic_item(
                    f"candidate_closure.p0_triage.{candidate_id}",
                    "candidate_closure",
                    "FAIL",
                    "P0 candidate remains discovered and has not entered triage.",
                    "candidate_queue",
                )
            )
        if is_v2 and not candidate.get("matched_tactics"):
            route_status = candidate.get("route_status")
            if route_status not in ROUTE_STATUSES_WITHOUT_TACTIC:
                checks.append(
                    semantic_item(
                        f"candidate_closure.route_status.{candidate_id}",
                        "candidate_closure",
                        "FAIL",
                        "v2 candidate without a matched tactic must preserve an explicit no-match, blocked, or policy-conflict route_status.",
                        "candidate_queue",
                        {
                            "route_status": route_status,
                            "allowed": sorted(ROUTE_STATUSES_WITHOUT_TACTIC),
                        },
                    )
                )
            pending_tactic = (
                route_status
                in {"blocked_need_material", "blocked_need_capability"}
                and isinstance(candidate.get("resume_tactic_id"), str)
                and bool(candidate["resume_tactic_id"].strip())
            )
            if not pending_tactic:
                checks.append(
                    semantic_item(
                        f"candidate_closure.tactic.{candidate_id}",
                        "candidate_closure",
                        "FAIL" if status == "confirmed" else "WARN",
                        "v2 candidate has no matched tactic; preserve a route-gap before closure.",
                        "candidate_queue",
                    )
                )
        if status == "confirmed":
            missing = []
            contract = candidate.get("validation_contract")
            if not isinstance(contract, dict) or not contract:
                missing.append("validation_contract")
            if not candidate.get("negative_controls"):
                missing.append("negative_controls")
            if not candidate.get("evidence_invariants"):
                missing.append("evidence_invariants")
            if not candidate.get("stop_conditions"):
                missing.append("stop_conditions")
            matrix = (
                contract.get("request_matrix", [])
                if isinstance(contract, dict)
                else []
            )
            roles = {
                item.get("role")
                for item in matrix
                if isinstance(item, dict)
            }
            if not roles.intersection({"baseline", "positive_control"}):
                missing.append("positive_control")
            if candidate.get("safe_validation_level") in {
                "test_object",
                "authorized_side_effect",
            } and not candidate.get("rollback_plan"):
                missing.append("rollback_plan")
            missing.extend(
                confirmed_evidence_gaps(candidate, candidate_id)
            )
            if missing:
                checks.append(
                    semantic_item(
                        f"candidate_closure.confirmed.{candidate_id}",
                        "candidate_closure",
                        "FAIL",
                        f"confirmed candidate lacks {', '.join(missing)}.",
                        "candidate_queue",
                    )
                )
        if status == "blocked_need_material":
            blocked_missing = [
                field
                for field in (
                    "missing_materials",
                    "blocked_reason",
                    "recovery_first_action",
                    "resume_tactic_id",
                    "reopen_conditions",
                )
                if not candidate.get(field)
            ]
            if blocked_missing:
                checks.append(
                    semantic_item(
                        f"candidate_closure.reopen.{candidate_id}",
                        "candidate_closure",
                        "FAIL",
                        f"blocked candidate lacks {', '.join(blocked_missing)}.",
                        "candidate_queue",
                        {"missing_fields": blocked_missing},
                    )
                )
        automatic_rating = (
            candidate.get("automatic_rating")
            or candidate.get("auto_rating")
            or candidate.get("auto_severity")
        )
        if str(automatic_rating).lower() in {"medium", "high", "critical", "中危", "高危"} and not candidate.get("rating_review"):
            checks.append(
                semantic_item(
                    f"candidate_closure.rating.{candidate_id}",
                    "candidate_closure",
                    "FAIL" if status == "confirmed" else "WARN",
                    "automatic medium/high rating lacks rating_review.",
                    "candidate_queue",
                )
            )
    if not checks:
        checks.append(
            semantic_item(
                "candidate_closure.complete",
                "candidate_closure",
                "PASS",
                f"candidate closure fields are consistent ({len(candidates)} candidate(s)).",
                "candidate_queue",
            )
        )
    return checks


def evaluate_semantics(
    state: dict[str, Any],
    documents: dict[str, dict[str, Any] | None],
    required: list[str],
) -> dict[str, list[dict[str, Any]]]:
    coverage = evaluate_coverage(state, documents, required)
    noise = (
        fake_ip_checks(documents.get("dnsx"))
        + http_noise_checks(documents.get("httpx"))
        + nmap_noise_checks(documents.get("nmap"))
    )
    attack_surface = evaluate_attack_surface(documents)
    candidate_closure = evaluate_candidate_closure(documents.get("candidate_queue"))
    report_consistency = evaluate_report_consistency(documents)
    return {
        "coverage": coverage,
        "noise": noise,
        "attack_surface": attack_surface,
        "candidate_closure": candidate_closure,
        "report_consistency": report_consistency,
        "semantic_checks": (
            coverage
            + noise
            + attack_surface
            + candidate_closure
            + report_consistency
        ),
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# 质量门禁",
        "",
        f"- 模式：`{payload.get('mode')}`",
        f"- 状态：`{payload.get('status')}`",
        f"- 结论：{payload.get('conclusion')}",
        "",
        "| 阶段 | 状态 | 说明 | 证据 |",
        "|---|---|---|---|",
    ]
    for item in payload.get("checks", []):
        lines.append(
            f"| `{item['phase']}` | `{item['status']}` | {item.get('message', '')} | `{item.get('output_file', '')}` |"
        )
    lines.append("")
    if payload.get("blocking_gaps"):
        lines.append("## 阻塞项")
        lines.append("")
        for item in payload["blocking_gaps"]:
            lines.append(f"- `{item['phase']}`：{item.get('message', '')}")
        lines.append("")
    if payload.get("semantic_checks"):
        lines.extend(
            [
                "## 语义检查",
                "",
                "| 类别 | 检查 | 状态 | 说明 |",
                "|---|---|---|---|",
            ]
        )
        for item in payload["semantic_checks"]:
            lines.append(
                f"| `{item['category']}` | `{item['id']}` | `{item['status']}` | {item['message']} |"
            )
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate scan pipeline quality gate.")
    parser.add_argument("--pipeline-dir", required=True, help="Pipeline output directory containing pipeline_state.json.")
    parser.add_argument("--mode", choices=["quick", "full", "deep"], help="Override scan mode.")
    parser.add_argument(
        "--report",
        help="Optional JSON report input for report/archive consistency checks.",
    )
    parser.add_argument(
        "--vulnerability-archive",
        help="Optional JSON vulnerability archive input for consistency checks.",
    )
    parser.add_argument("--output", help="Optional JSON output path.")
    parser.add_argument("--markdown-output", help="Optional Markdown output path.")
    parser.add_argument("--strict", action="store_true", help="Treat skipped required phases as FAIL instead of WARN.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    started_at = utc_now()
    pipeline_dir = Path(args.pipeline_dir)
    state_path = pipeline_dir / "pipeline_state.json"
    state = read_json(state_path)
    mode = args.mode or state.get("mode", "full")
    required = required_phases_for_state(mode, state)
    offline_chain_required = requires_offline_semantic_chain(state)
    phase_outputs = state.get("phase_outputs", {})
    documents = load_phase_documents(pipeline_dir, state)
    consistency_input_checks = load_consistency_inputs(
        pipeline_dir,
        state,
        documents,
        report_path=args.report,
        vulnerability_archive_path=args.vulnerability_archive,
    )

    checks: list[dict[str, Any]] = []
    blocking: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    for phase in required:
        details = phase_outputs.get(phase)
        if not details:
            item = {
                "phase": phase,
                "status": "FAIL",
                "message": "required phase was not executed",
                "output_file": "",
            }
            checks.append(item)
            blocking.append(item)
            continue
        if details.get("ok"):
            if offline_chain_required and phase in OFFLINE_SEMANTIC_PHASES:
                output = documents.get(phase)
                phase_errors: list[str] = []
                if details.get("status") != "completed":
                    phase_errors.append("state status is not completed")
                if not isinstance(output, dict):
                    phase_errors.append("output is missing or not parseable JSON")
                elif phase == "candidate_queue":
                    if output.get("ok") is not True:
                        phase_errors.append("candidate queue output is not successful")
                    if not isinstance(output.get("candidates"), list):
                        phase_errors.append(
                            "candidate queue output has no candidates array"
                        )
                else:
                    if output.get("phase_id") != phase:
                        phase_errors.append("output phase_id does not match")
                    if output.get("analysis_mode") != "offline":
                        phase_errors.append("output is not marked as offline analysis")
                    if output.get("status") != "completed":
                        phase_errors.append("output status is not completed")
                    if not isinstance(output.get("observations"), dict):
                        phase_errors.append("output has no observations object")
                if phase_errors:
                    item = {
                        "phase": phase,
                        "status": "FAIL",
                        "message": "; ".join(phase_errors),
                        "output_file": details.get("output_file", ""),
                    }
                    checks.append(item)
                    blocking.append(item)
                    continue
            item = {
                "phase": phase,
                "status": "PASS",
                "message": details.get("summary", "completed"),
                "output_file": details.get("output_file", ""),
            }
            checks.append(item)
            continue
        skipped = bool(details.get("skipped"))
        status = (
            "FAIL"
            if (
                args.strict
                or not skipped
                or (offline_chain_required and phase in OFFLINE_SEMANTIC_PHASES)
            )
            else "WARN"
        )
        item = {
            "phase": phase,
            "status": status,
            "message": details.get("error", "phase did not complete"),
            "output_file": details.get("output_file", ""),
        }
        checks.append(item)
        if status == "FAIL":
            blocking.append(item)
        else:
            warnings.append(item)

    if uses_legacy_quality_gate_alias(state):
        item = {
            "phase": "quality_gate",
            "status": "WARN",
            "message": (
                "legacy quality_gate alias retained compatibility checks only; "
                "migrate to semantic_quality_gate for the required offline chain"
            ),
            "output_file": "",
        }
        checks.append(item)
        warnings.append(item)

    semantics = evaluate_semantics(state, documents, required)
    if consistency_input_checks:
        semantics["report_consistency"] = (
            consistency_input_checks + semantics["report_consistency"]
        )
        semantics["semantic_checks"] = (
            consistency_input_checks + semantics["semantic_checks"]
        )
    for item in semantics["semantic_checks"]:
        if item["status"] == "FAIL":
            blocking.append(item)
        elif item["status"] == "WARN":
            warnings.append(item)

    status = "PASS"
    conclusion = "Required reconnaissance phases completed with valid semantic coverage."
    if blocking:
        status = "FAIL"
        conclusion = "Execution or semantic coverage is incomplete; do not claim complete coverage or exhausted directions."
    elif warnings:
        status = "WARN"
        conclusion = "Core flow ran with semantic or execution gaps; document them before claiming coverage."

    payload = {
        "ok": status != "FAIL",
        "tool": "quality_gate",
        "started_at": started_at,
        "finished_at": utc_now(),
        "pipeline_dir": str(pipeline_dir),
        "state_file": str(state_path),
        "mode": mode,
        "status": status,
        "conclusion": conclusion,
        "checks": checks,
        "semantic_checks": semantics["semantic_checks"],
        "coverage": semantics["coverage"],
        "noise": semantics["noise"],
        "attack_surface": semantics["attack_surface"],
        "candidate_closure": semantics["candidate_closure"],
        "report_consistency": semantics["report_consistency"],
        "blocking_gaps": blocking,
        "warnings": warnings,
    }

    if args.output:
        write_json(Path(args.output), payload)
    if args.markdown_output:
        write_markdown(Path(args.markdown_output), payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
