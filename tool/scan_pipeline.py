#!/usr/bin/env python3
"""
Scan pipeline orchestrator — codified recon → attack-surface discovery chain.

Orchestrates the standard penetration-testing information-gathering phases
(subfinder → dnsx → httpx → tlsx/naabu/nmap → katana/history → gf-patterns
→ nuclei → ffuf → offline intelligence → candidate/tactic routing
→ semantic quality gate) into a
single command with mode presets (quick / full / deep), async polling for
long-running phases, persistent state for resume, and a unified output tree.

Examples:
  # Quick first-look (subfinder + httpx + shallow katana + gf + nuclei-top)
  ./tool/scan_pipeline.py --authorized --domain example.com --mode quick

  # Full coverage
  ./tool/scan_pipeline.py --authorized --domain example.com --mode full

  # Deep: adds depth-5 headless katana + ffuf directory brute-force
  ./tool/scan_pipeline.py --authorized --domain example.com --mode deep

  # Custom phase selection
  ./tool/scan_pipeline.py --authorized --domain example.com --phases subfinder,httpx,katana,gf

  # Resume from a previous interrupted run
  ./tool/scan_pipeline.py --resume /path/to/pipeline_state.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

try:
    from cybertest_core.pipeline.dynamic_planning import (
        available_capability_ids as _core_available_capability_ids,
        available_material_ids as _core_available_material_ids,
        build_dynamic_plan_draft as _core_build_dynamic_plan_draft,
        dynamic_route_bindings as _core_dynamic_route_bindings,
    )
except ModuleNotFoundError:  # Imported as ``tool.scan_pipeline``.
    from tool.cybertest_core.pipeline.dynamic_planning import (
        available_capability_ids as _core_available_capability_ids,
        available_material_ids as _core_available_material_ids,
        build_dynamic_plan_draft as _core_build_dynamic_plan_draft,
        dynamic_route_bindings as _core_dynamic_route_bindings,
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_BASE = Path("/tmp/codex-scan-pipelines")
ASYNC_POLL_INTERVAL = 15       # seconds between polls for async phases
ASYNC_STALE_THRESHOLD = 300    # seconds before an async task is considered stale
ASYNC_DEFAULT_TIMEOUT = 3600   # 1 hour max wait per async phase

HTTPX_PORTS = "80,443,8080,8443,9090"

# The DAG is the single source of truth for phase dependencies and fallbacks.
# PHASE_DEPS remains as a compatibility view for existing imports.
PHASE_DAG: dict[str, dict[str, list[str]]] = {
    "subfinder": {"depends_on": [], "fallback_inputs": ["root_domain", "input_file"]},
    "dnsx": {"depends_on": ["subfinder"], "fallback_inputs": ["root_domain", "input_file"]},
    "httpx": {"depends_on": ["subfinder"], "fallback_inputs": ["root_domain", "input_file"]},
    "tlsx": {"depends_on": ["httpx"], "fallback_inputs": []},
    "naabu": {"depends_on": ["httpx"], "fallback_inputs": []},
    "nmap": {"depends_on": ["httpx"], "fallback_inputs": []},
    "katana": {"depends_on": ["httpx"], "fallback_inputs": []},
    "history": {"depends_on": ["httpx"], "fallback_inputs": []},
    "gf": {"depends_on": ["katana", "history"], "fallback_inputs": []},
    "nuclei": {"depends_on": ["httpx"], "fallback_inputs": []},
    "ffuf": {"depends_on": ["httpx"], "fallback_inputs": []},
    "js_intel": {
        "depends_on": ["katana", "history", "gf"],
        "fallback_inputs": [],
    },
    "api_contract": {
        "depends_on": ["js_intel", "katana", "history", "gf", "httpx"],
        "fallback_inputs": [],
    },
    "control_gap": {
        "depends_on": ["js_intel", "api_contract"],
        "fallback_inputs": [],
    },
    "candidate_queue": {
        "depends_on": ["control_gap"],
        "fallback_inputs": ["pipeline_state"],
    },
    "tactic_match": {
        "depends_on": ["candidate_queue", "js_intel", "api_contract"],
        "fallback_inputs": [],
    },
    "semantic_quality_gate": {
        "depends_on": ["tactic_match", "control_gap", "candidate_queue"],
        "fallback_inputs": ["pipeline_state"],
    },
    # Compatibility alias retained for callers that explicitly request the
    # historical phase id. New presets use semantic_quality_gate.
    "quality_gate": {
        "depends_on": ["candidate_queue"],
        "fallback_inputs": ["pipeline_state"],
    },
    "browser_validate": {
        "depends_on": ["tactic_match"],
        "fallback_inputs": ["capability_report", "material_manifest"],
    },
    "burp_replay": {
        "depends_on": ["tactic_match"],
        "fallback_inputs": ["capability_report", "material_manifest"],
    },
    "js_runtime_validate": {
        "depends_on": ["js_intel", "tactic_match"],
        "fallback_inputs": ["capability_report", "material_manifest"],
    },
    "oast_check": {
        "depends_on": ["tactic_match"],
        "fallback_inputs": ["capability_report", "material_manifest"],
    },
}
PHASE_DEPS: dict[str, list[str]] = {
    phase_id: list(spec["depends_on"]) for phase_id, spec in PHASE_DAG.items()
}

NETWORK_PROFILES: dict[str, dict[str, str]] = {
    "internet-web": {"nmap_profile": "web"},
    "internet-api": {"nmap_profile": "web"},
    "lan": {"nmap_profile": "lan-fast"},
    "mobile-api": {"nmap_profile": "web"},
}

# Each mode selects a subset of phases + per-phase overrides.
MODE_PHASES: dict[str, dict[str, dict[str, Any]]] = {
    "quick": {
        "subfinder":  {},
        "dnsx":       {},
        "httpx":      {},
        "katana":     {"depth": 1, "headless": False, "js_crawl": False},
        "gf":         {},
        "nuclei":     {"severity": "high,critical"},
        "js_intel":   {},
        "api_contract": {},
        "control_gap": {},
        "candidate_queue": {},
        "tactic_match": {},
        "semantic_quality_gate": {},
    },
    "full": {
        "subfinder":  {},
        "dnsx":       {},
        "httpx":      {},
        "tlsx":       {},
        "naabu":      {"ports": "1-65535", "rate": 1000},
        "nmap":       {},
        "katana":     {"depth": 3, "headless": False, "js_crawl": True},
        "history":    {},
        "gf":         {},
        "nuclei":     {"severity": "medium,high,critical"},
        "ffuf":       {"wordlist": "auto"},
        "js_intel":   {},
        "api_contract": {},
        "control_gap": {},
        "candidate_queue": {},
        "tactic_match": {},
        "semantic_quality_gate": {},
    },
    "deep": {
        "subfinder":  {},
        "dnsx":       {},
        "httpx":      {},
        "tlsx":       {},
        "naabu":      {"ports": "1-65535", "rate": 1000},
        "nmap":       {},
        "katana":     {"depth": 5, "headless": True, "js_crawl": True},
        "history":    {},
        "gf":         {},
        "nuclei":     {"severity": "medium,high,critical"},
        "ffuf":       {"wordlist": "auto"},
        "js_intel":   {},
        "api_contract": {},
        "control_gap": {},
        "candidate_queue": {},
        "tactic_match": {},
        "semantic_quality_gate": {},
    },
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool(name: str) -> Path:
    """Return the absolute path to a tool/ script."""
    return TOOL_DIR / name


def _normalize_phase_order(phases: list[str]) -> list[str]:
    """Stable topological order for the explicitly selected DAG subset.

    Dependencies are not auto-added: ``--phases`` remains an explicit
    selection mechanism. When both a phase and one of its dependencies are
    selected, the dependency is placed first.
    """

    selected = list(dict.fromkeys(phases))
    selected_set = set(selected)
    visiting: set[str] = set()
    visited: set[str] = set()
    ordered: list[str] = []

    def visit(phase: str) -> None:
        if phase in visited:
            return
        if phase in visiting:
            raise ValueError(f"phase dependency cycle involving {phase}")
        visiting.add(phase)
        for dependency in PHASE_DAG.get(phase, {}).get("depends_on", []):
            if dependency in selected_set:
                visit(dependency)
        visiting.remove(phase)
        visited.add(phase)
        ordered.append(phase)

    for phase in selected:
        visit(phase)
    return ordered


def read_json(path: Path) -> dict[str, Any]:
    """Read an existing JSON file; return empty dict on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _error_message(result: dict[str, Any], cp: subprocess.CompletedProcess[str] | None) -> str:
    error = result.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or "")
    if isinstance(error, str):
        return error
    if cp is not None and cp.stderr:
        return cp.stderr.strip()
    return ""


def _tool_missing(result: dict[str, Any]) -> bool:
    payload = result.get("result", result)
    error = payload.get("error") if isinstance(payload, dict) else None
    return isinstance(error, dict) and error.get("type") == "binary_not_found"


def _run(argv: list[str], timeout: int | None = None, **kw: Any) -> subprocess.CompletedProcess[str]:
    """Thin wrapper around subprocess.run with unified kwargs.

    Returns a CompletedProcess; caller inspects .returncode / .stdout / .stderr.
    """
    return subprocess.run(
        [sys.executable, *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        **kw,
    )


# ---------------------------------------------------------------------------
# Phase executors
# ---------------------------------------------------------------------------

def run_subfinder(domain: str | None, input_file: Path | None,
                  output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("subfinder_json.py")), "--authorized",
        "--output", str(output_file),
        "--timeout", str(timeout),
    ]
    if domain:
        argv.extend(["--domain", domain])
    if input_file:
        argv.extend(["--input", str(input_file)])
    # Overrides
    if overrides.get("all_sources", True):
        argv.append("--all")
    if overrides.get("recursive", True):
        argv.append("--recursive")

    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
    }


def run_httpx(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("httpx_probe.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--ports", HTTPX_PORTS,
        "--timeout", str(timeout),
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
    }


def run_dnsx(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("dnsx_json.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--timeout", str(timeout),
    ]
    for resolver in overrides.get("resolvers", ["1.1.1.1", "8.8.8.8"]):
        argv.extend(["--resolver", resolver])
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


def run_tlsx(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("tlsx_json.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--timeout", str(timeout),
    ]
    if overrides.get("ports"):
        argv.extend(["--ports", str(overrides["ports"])])
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


def run_naabu(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("naabu_json_scan.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--ports", str(overrides.get("ports", "1-65535")),
        "--rate", str(overrides.get("rate", 1000)),
        "--timeout", str(timeout),
    ]
    if overrides.get("verify", True):
        argv.append("--verify")
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


def run_nmap(target_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    profile = overrides.get("profile", "web")
    argv = [
        str(_tool("nmap_json_scan.py")), "--authorized",
        "--output", str(output_file),
        "--profile", profile,
        "--timeout", str(timeout),
    ]
    for target in read_lines(target_file)[:200]:
        argv.extend(["--target", target])
    cp = _run(argv, timeout=timeout + 60)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
    }


def run_katana(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    depth = overrides.get("depth", 3)
    argv = [
        str(_tool("katana_crawl.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--depth", str(depth),
        "--known-files", "robotstxt,sitemapxml",
        "--timeout", str(timeout),
    ]
    if overrides.get("js_crawl", True):
        argv.append("--js-crawl")
    if overrides.get("headless", False):
        argv.append("--headless")
        argv.append("--no-sandbox")

    # Use async-start for headless or depth >= 3 (may exceed 10 min).
    if overrides.get("headless") or depth >= 3:
        argv.append("--async-start")
        cp = _run(argv, timeout=60)
        try:
            stdout = json.loads(cp.stdout)
        except json.JSONDecodeError:
            return {"ok": False, "returncode": cp.returncode, "error": "failed to parse async-start output"}
        task_id = stdout.get("task_id", "")
        if not task_id:
            return {"ok": False, "returncode": cp.returncode, "error": "no task_id in async-start output"}
        return _poll_async(
            str(_tool("katana_crawl.py")), task_id, output_file,
            async_timeout=timeout,
        )
    else:
        cp = _run(argv, timeout=timeout + 30)
        result = read_json(output_file)
        return {
            "ok": cp.returncode == 0 and result.get("ok", False),
            "returncode": cp.returncode,
            "result": result,
        }


def run_gf(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("gf_pattern_match.py")),
        "--input", str(input_file),
        "--output", str(output_file),
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
    }


def run_history(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    argv = [
        str(_tool("url_history_collect.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--timeout", str(timeout),
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


def run_nuclei(input_file: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    severity = overrides.get("severity", "medium,high,critical")
    argv = [
        str(_tool("nuclei_json_scan.py")), "--authorized",
        "--input", str(input_file),
        "--output", str(output_file),
        "--severity", severity,
        "--disable-update-check",
        "--timeout", str(timeout),
    ]
    # Always async — nuclei can easily exceed 10 min.
    argv.append("--async-start")
    cp = _run(argv, timeout=60)
    try:
        stdout = json.loads(cp.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "returncode": cp.returncode, "error": "failed to parse async-start output"}
    task_id = stdout.get("task_id", "")
    if not task_id:
        return {"ok": False, "returncode": cp.returncode, "error": "no task_id in async-start output"}
    return _poll_async(
        str(_tool("nuclei_json_scan.py")), task_id, output_file,
        async_timeout=timeout,
    )


def run_ffuf(target_urls: list[str], output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    """Run ffuf against a set of target base URLs (FUZZ placeholder appended).

    This is a simplified per-host stub — a full implementation would need a
    wordlist selection strategy.  In ``deep`` mode we only run ffuf if a
    wordlist is explicitly provided or an auto wordlist file exists.
    """
    wordlist = overrides.get("wordlist")
    if not wordlist or wordlist == "auto":
        # Look for a default small wordlist; skip if absent.
        candidates = [
            Path("/usr/share/wordlists/dirb/common.txt"),
            Path("/opt/wordlists/common.txt"),
            TOOL_DIR.parent / "wordlists" / "common.txt",
        ]
        wordlist = None
        for c in candidates:
            if c.is_file():
                wordlist = str(c)
                break
        if not wordlist:
            return {
                "ok": False,
                "skipped": True,
                "reason": "no wordlist found — pass --wordlist or place common.txt in tool/wordlists/",
            }

    all_results: list[dict[str, Any]] = []
    ok_count = 0
    for url in target_urls[:20]:  # cap to avoid runaway
        phase_dir = output_file.parent
        single_out = phase_dir / f"ffuf_{url.replace('://', '_').replace('/', '_').replace(':', '_')[:80]}.json"
        argv = [
            str(_tool("ffuf_json.py")), "--authorized",
            "--url", f"{url.rstrip('/')}/FUZZ",
            "--wordlist", wordlist,
            "--output", str(single_out),
            "--filter-code", "404,403,405,410",
            "--timeout", str(timeout),
        ]
        cp = _run(argv, timeout=timeout + 30)
        r = read_json(single_out)
        if cp.returncode == 0 and r.get("ok"):
            ok_count += 1
        all_results.append({"url": url, "output_file": str(single_out), "ok": r.get("ok", False)})

    summary = {
        "ok": ok_count > 0,
        "targets_scanned": len(target_urls[:20]),
        "targets_ok": ok_count,
        "wordlist": wordlist,
        "per_target": all_results,
    }
    write_json(output_file, summary)
    return {"ok": ok_count > 0, "result": summary}


def run_quality_gate(pipeline_dir: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    markdown_output = output_file.with_suffix(".md")
    argv = [
        str(_tool("quality_gate.py")),
        "--pipeline-dir", str(pipeline_dir),
        "--mode", str(overrides.get("mode", "full")),
        "--output", str(output_file),
        "--markdown-output", str(markdown_output),
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": result.get("conclusion") or _error_message(result, cp),
    }


def run_candidate_queue(pipeline_dir: Path, output_file: Path, timeout: int, **overrides: Any) -> dict[str, Any]:
    markdown_output = output_file.with_suffix(".md")
    argv = [
        str(_tool("bounty_candidate_queue.py")),
        "--pipeline-dir", str(pipeline_dir),
        "--output-json", str(output_file),
        "--output-md", str(markdown_output),
        "--enable-tactics",
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


OFFLINE_RULE_VERSION = "pipeline-offline-v1"
JS_REFERENCE_RE = re.compile(
    r"(?:https?://[^\s\"'<>]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)"
    r"(?:\.m?js|\.map)(?:\?[^\s\"'<>]*)?",
    re.IGNORECASE,
)
API_REFERENCE_RE = re.compile(
    r"(?:https?://[^\s\"'<>]+|/)"
    r"(?:api|v[0-9]+|graphql|oauth|auth|admin|user|account|file|upload|"
    r"download|export|import|callback|webhook)"
    r"[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*",
    re.IGNORECASE,
)
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
DYNAMIC_PHASE_SPECS: dict[str, dict[str, Any]] = {
    "browser_validate": {
        "capability": "browser.interactive",
        "materials": ["target_url", "authorized_test_session"],
        "safe_validation_level": "readonly",
        "operation": "navigate",
    },
    "burp_replay": {
        "capability": "http.replay",
        "materials": ["replayable_request"],
        "safe_validation_level": "readonly",
        "operation": "replay",
    },
    "js_runtime_validate": {
        "capability": "js.cdp",
        "materials": ["target_url", "browser_session"],
        "safe_validation_level": "readonly",
        "operation": "observe_runtime",
    },
    "oast_check": {
        "capability": "oast.callback",
        "materials": ["callback_endpoint", "correlation_id"],
        "safe_validation_level": "readonly",
        "operation": "observe_callback",
    },
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_sidecars(source_files: list[Path]) -> list[dict[str, str]]:
    sidecars: list[dict[str, str]] = []
    for path in sorted(set(source_files), key=lambda item: str(item)):
        if path.is_file():
            parent_id = path.parent.name.removeprefix("phase_")
            sidecars.append(
                {
                    "source_id": parent_id or "input",
                    "file_name": path.name,
                    "sha256": _sha256_file(path),
                }
            )
    return sidecars


def _walk_json(value: Any) -> list[tuple[str | None, Any, dict[str, Any] | None]]:
    """Return scalar values with their key and nearest object context."""

    walked: list[tuple[str | None, Any, dict[str, Any] | None]] = []

    def visit(item: Any, key: str | None, parent: dict[str, Any] | None) -> None:
        if isinstance(item, dict):
            for child_key, child in item.items():
                visit(child, str(child_key), item)
        elif isinstance(item, list):
            for child in item:
                visit(child, key, parent)
        else:
            walked.append((key, item, parent))

    visit(value, None, None)
    return walked


def _strings_from_sources(source_files: list[Path]) -> list[str]:
    values: set[str] = set()
    for source in source_files:
        payload = read_json(source)
        for _key, value, _parent in _walk_json(payload):
            if isinstance(value, str) and value.strip():
                values.add(value.strip())
    return sorted(values)


def _offline_payload(
    phase_id: str,
    source_files: list[Path],
    observations: dict[str, Any],
    *,
    status: str = "completed",
    reason: str | None = None,
) -> dict[str, Any]:
    input_sources = _source_sidecars(source_files)
    stable_content = {
        "phase_id": phase_id,
        "rule_version": OFFLINE_RULE_VERSION,
        "input_sources": input_sources,
        "observations": observations,
        "status": status,
    }
    payload: dict[str, Any] = {
        "ok": status == "completed",
        "schema_version": "1.0",
        "phase_id": phase_id,
        "analysis_mode": "offline",
        "rule_version": OFFLINE_RULE_VERSION,
        "generated_at": utc_now(),
        "status": status,
        "input_sources": input_sources,
        "analysis_hash": _stable_hash(stable_content),
        "observations": observations,
    }
    if reason:
        payload["reason"] = reason
    return payload


def _offline_result(
    output_file: Path,
    payload: dict[str, Any],
) -> dict[str, Any]:
    write_json(output_file, payload)
    if payload["status"] == "skipped":
        return {
            "ok": False,
            "skipped": True,
            "reason": payload.get("reason", "no usable offline input"),
            "result": payload,
        }
    return {"ok": True, "result": payload}


def run_js_intel(
    source_files: list[Path],
    output_file: Path,
    timeout: int,
    **overrides: Any,
) -> dict[str, Any]:
    del timeout, overrides
    if not source_files:
        return _offline_result(
            output_file,
            _offline_payload(
                "js_intel",
                [],
                {"javascript_assets": [], "source_maps": [], "api_references": []},
                status="skipped",
                reason="no completed crawl/history/pattern outputs",
            ),
        )

    javascript_assets: set[str] = set()
    source_maps: set[str] = set()
    api_references: set[str] = set()
    for value in _strings_from_sources(source_files):
        for match in JS_REFERENCE_RE.finditer(value):
            reference = match.group(0).rstrip(".,;)")
            if reference.lower().split("?", 1)[0].endswith(".map"):
                source_maps.add(reference)
            else:
                javascript_assets.add(reference)
        for match in API_REFERENCE_RE.finditer(value):
            api_references.add(match.group(0).rstrip(".,;)"))

    observations = {
        "javascript_assets": sorted(javascript_assets),
        "source_maps": sorted(source_maps),
        "api_references": sorted(api_references),
        "counts": {
            "javascript_assets": len(javascript_assets),
            "source_maps": len(source_maps),
            "api_references": len(api_references),
        },
    }
    return _offline_result(
        output_file,
        _offline_payload("js_intel", source_files, observations),
    )


def _endpoint_parts(value: str) -> tuple[str | None, set[str]]:
    candidate = value.strip()
    if not candidate:
        return None, set()
    if candidate.startswith(("http://", "https://")):
        parsed = urlparse(candidate)
        path = parsed.path or "/"
        query = parsed.query
    elif candidate.startswith("/"):
        path, _, query = candidate.partition("?")
    else:
        return None, set()
    if len(path) > 300:
        return None, set()
    path = re.sub(
        r"/[0-9a-f]{8}-[0-9a-f-]{27,}",
        "/{id}",
        path,
        flags=re.IGNORECASE,
    )
    path = re.sub(r"/[0-9]{2,}", "/{id}", path)
    params = {key for key, _value in parse_qsl(query, keep_blank_values=True)}
    return path, params


def run_api_contract(
    source_files: list[Path],
    output_file: Path,
    timeout: int,
    **overrides: Any,
) -> dict[str, Any]:
    del timeout, overrides
    if not source_files:
        return _offline_result(
            output_file,
            _offline_payload(
                "api_contract",
                [],
                {"endpoints": [], "endpoint_count": 0},
                status="skipped",
                reason="no completed JS/crawl/history/pattern/HTTP outputs",
            ),
        )

    endpoints: dict[str, dict[str, set[str]]] = {}
    for source in source_files:
        payload = read_json(source)
        for key, value, parent in _walk_json(payload):
            if not isinstance(value, str):
                continue
            candidates = [value]
            candidates.extend(
                match.group(0) for match in API_REFERENCE_RE.finditer(value)
            )
            for candidate in candidates:
                endpoint, params = _endpoint_parts(candidate)
                if endpoint is None:
                    continue
                entry = endpoints.setdefault(
                    endpoint,
                    {"methods": set(), "parameters": set()},
                )
                entry["parameters"].update(params)
                if key and key.lower() in {"method", "http_method"}:
                    method = value.upper()
                    if method in HTTP_METHODS:
                        entry["methods"].add(method)
                if parent:
                    for method_key in ("method", "http_method"):
                        method_value = parent.get(method_key)
                        if isinstance(method_value, str):
                            method = method_value.upper()
                            if method in HTTP_METHODS:
                                entry["methods"].add(method)
                    for param_key in ("params", "parameters", "query"):
                        raw_params = parent.get(param_key)
                        if isinstance(raw_params, dict):
                            entry["parameters"].update(str(item) for item in raw_params)

    endpoint_records = [
        {
            "route_template": endpoint,
            "methods": sorted(details["methods"]),
            "parameter_names": sorted(details["parameters"]),
        }
        for endpoint, details in sorted(endpoints.items())
    ]
    observations = {
        "endpoints": endpoint_records,
        "endpoint_count": len(endpoint_records),
    }
    return _offline_result(
        output_file,
        _offline_payload("api_contract", source_files, observations),
    )


def run_control_gap(
    source_files: list[Path],
    output_file: Path,
    timeout: int,
    **overrides: Any,
) -> dict[str, Any]:
    del timeout, overrides
    if not source_files:
        return _offline_result(
            output_file,
            _offline_payload(
                "control_gap",
                [],
                {"suspected_control_gaps": [], "gap_count": 0},
                status="skipped",
                reason="no completed JS intelligence or API contract outputs",
            ),
        )

    strings = "\n".join(_strings_from_sources(source_files)).lower()
    rules = {
        "object_level_authorization": (
            "userid",
            "user_id",
            "tenantid",
            "tenant_id",
            "orderid",
            "fileid",
            "/{id}",
        ),
        "function_level_authorization": (
            "/admin",
            "/manage",
            "/approve",
            "/audit",
        ),
        "server_owned_field_protection": (
            "/update",
            "/patch",
            "role",
            "permission",
        ),
        "file_operation_authorization": (
            "/upload",
            "/download",
            "/export",
            "/import",
        ),
        "authentication_token_boundary": (
            "/oauth",
            "/auth",
            "/login",
            "/token",
        ),
        "outbound_request_validation": (
            "/callback",
            "/webhook",
            "/fetch",
            "/preview",
        ),
        "exposed_client_metadata": (".map", "source_maps"),
        "undocumented_api_surface": (
            "/swagger",
            "/openapi",
            "/graphql",
            "/api-docs",
        ),
    }
    gaps = [
        {
            "id": gap_id,
            "matched_signals": sorted(
                signal for signal in signals if signal in strings
            ),
            "confidence": "hypothesis",
        }
        for gap_id, signals in sorted(rules.items())
        if any(signal in strings for signal in signals)
    ]
    observations = {
        "suspected_control_gaps": gaps,
        "gap_count": len(gaps),
        "do_not_overclaim": (
            "offline control-gap matches are routing hypotheses, not vulnerability proof"
        ),
    }
    return _offline_result(
        output_file,
        _offline_payload("control_gap", source_files, observations),
    )


def run_tactic_match(
    source_files: list[Path],
    output_file: Path,
    timeout: int,
    **overrides: Any,
) -> dict[str, Any]:
    del timeout, overrides
    candidate_source = next(
        (
            path
            for path in source_files
            if any("candidate_queue" in part for part in path.parts)
        ),
        None,
    )
    if candidate_source is None:
        return _offline_result(
            output_file,
            _offline_payload(
                "tactic_match",
                source_files,
                {"matches": [], "matched_candidate_count": 0, "route_gap_count": 0},
                status="skipped",
                reason="no completed candidate_queue output",
            ),
        )

    candidate_payload = read_json(candidate_source)
    matches: list[dict[str, Any]] = []
    for candidate in _list(candidate_payload, "candidates"):
        matched_tactics = candidate.get("matched_tactics", [])
        if not isinstance(matched_tactics, list):
            matched_tactics = []
        missing_materials = candidate.get("missing_materials", [])
        if not isinstance(missing_materials, list):
            missing_materials = []
        route_fallback = candidate.get("route_fallback", {})
        if not isinstance(route_fallback, dict):
            route_fallback = {}
        missing_capabilities = route_fallback.get("missing_capabilities", [])
        if not isinstance(missing_capabilities, list):
            missing_capabilities = []
        matches.append(
            {
                "candidate_id": candidate.get("id"),
                "route_status": candidate.get("route_status", "route_gap"),
                "route_decision_id": candidate.get("route_decision_id"),
                "matched_tactics": matched_tactics,
                "resume_tactic_id": candidate.get("resume_tactic_id"),
                "missing_materials": sorted(
                    item for item in missing_materials if isinstance(item, str)
                ),
                "missing_capabilities": sorted(
                    item
                    for item in missing_capabilities
                    if isinstance(item, str)
                ),
                "validation_contract": candidate.get("validation_contract", {}),
            }
        )
    matches.sort(key=lambda item: str(item.get("candidate_id") or ""))
    observations = {
        "matches": matches,
        "matched_candidate_count": sum(
            1 for item in matches if item["matched_tactics"]
        ),
        "route_gap_count": sum(
            1 for item in matches if item["route_status"] == "route_gap"
        ),
        "source_schema_version": candidate_payload.get("schema_version"),
    }
    return _offline_result(
        output_file,
        _offline_payload("tactic_match", source_files, observations),
    )


def _available_capabilities(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    return _core_available_capability_ids(read_json(path))


def _available_materials(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    return _core_available_material_ids(read_json(path))


def _dynamic_route_bindings(
    source_files: list[Path],
    available_capabilities: set[str],
    available_materials: set[str],
) -> list[dict[str, Any]]:
    """Extract deterministic, executable candidate/tactic/decision bindings.

    A dynamic phase may plan against either a currently matched tactic or a
    material/capability-blocked route that explicitly names its resume tactic.
    Route gaps, policy conflicts, incomplete matches and unbound decisions are
    deliberately excluded.
    """

    payloads: list[dict[str, Any]] = []
    for source in sorted(set(source_files), key=lambda item: str(item)):
        payload = read_json(source)
        if (
            payload.get("phase_id") != "tactic_match"
            and "tactic_match" not in source.parent.name
        ):
            continue
        payloads.append(payload)
    return _core_dynamic_route_bindings(
        payloads,
        available_capabilities,
        available_materials,
    )


def run_dynamic_plan(
    source_files: list[Path],
    output_file: Path,
    timeout: int,
    *,
    phase_id: str,
    capabilities_file: Path | None = None,
    materials_file: Path | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    """Create a validation plan; never perform dynamic actions automatically."""

    del timeout, overrides
    spec = DYNAMIC_PHASE_SPECS[phase_id]
    capabilities_payload = (
        read_json(capabilities_file)
        if capabilities_file is not None and capabilities_file.is_file()
        else {}
    )
    available_capabilities = _core_available_capability_ids(
        capabilities_payload
    )
    available_materials = _available_materials(materials_file)
    required_capability = str(spec["capability"])
    required_materials = list(spec["materials"])
    missing_materials = sorted(set(required_materials) - available_materials)
    route_bindings = _dynamic_route_bindings(
        source_files,
        available_capabilities,
        available_materials,
    )
    route_binding = route_bindings[0] if route_bindings else None
    if route_binding is None:
        execution_status = "blocked_need_route"
    elif required_capability not in available_capabilities:
        execution_status = "blocked_need_capability"
    elif missing_materials:
        execution_status = "blocked_need_material"
    else:
        execution_status = "ready_for_plan_completion"

    dynamic_validation_plan = (
        _core_build_dynamic_plan_draft(
            phase_id=phase_id,
            route_binding=route_binding,
            capability_id=required_capability,
            capability_payload=capabilities_payload,
            required_materials=required_materials,
            missing_materials=missing_materials,
            safe_validation_level=str(spec["safe_validation_level"]),
            operation=str(spec["operation"]),
        )
        if route_binding is not None
        else None
    )

    all_sources = list(source_files)
    for optional_file in (capabilities_file, materials_file):
        if optional_file is not None and optional_file.is_file():
            all_sources.append(optional_file)
    observations = {
        "execution_status": execution_status,
        "execution_performed": False,
        "automatic_execution": False,
        "required_capability": required_capability,
        "capability_available": required_capability in available_capabilities,
        "required_materials": required_materials,
        "missing_materials": missing_materials,
        "route_binding": route_binding,
        "eligible_route_count": len(route_bindings),
        "safe_validation_level": spec["safe_validation_level"],
        "dynamic_validation_plan": dynamic_validation_plan,
        "next_action": (
            "complete the embedded draft, keep its candidate/tactic/"
            "RouteDecision binding, then execute the explicit adapter only "
            "after fresh capability, task, policy and material checks pass"
        ),
    }
    payload = _offline_payload(phase_id, all_sources, observations)
    payload["analysis_mode"] = "dynamic_plan_only"
    return _offline_result(output_file, payload)


# ---------------------------------------------------------------------------
# Async poller
# ---------------------------------------------------------------------------

def _poll_async(script: str, task_id: str, output_file: Path,
                async_timeout: int = ASYNC_DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Poll ``script --async-status <task_id>`` until completion or timeout.

    On success the final JSON result is copied to *output_file*.
    """
    deadline = time.monotonic() + async_timeout
    last_status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        cp = _run([script, "--async-status", task_id])
        try:
            last_status = json.loads(cp.stdout)
        except json.JSONDecodeError:
            time.sleep(ASYNC_POLL_INTERVAL)
            continue

        state = last_status.get("status", "")
        if state in ("completed", "done"):
            # Copy the final result JSON into our phase output file.
            result_path = last_status.get("result_path", "")
            if result_path and Path(result_path).is_file():
                write_json(output_file, read_json(Path(result_path)))
            return {
                "ok": True,
                "result": last_status,
                "async_task_id": task_id,
            }
        if state in ("failed", "error", "timeout"):
            return {
                "ok": False,
                "error": f"async task {task_id} ended with status '{state}'",
                "result": last_status,
                "async_task_id": task_id,
            }
        time.sleep(ASYNC_POLL_INTERVAL)

    return {
        "ok": False,
        "error": f"async task {task_id} timed out after {async_timeout}s",
        "result": last_status,
        "async_task_id": task_id,
    }


# ---------------------------------------------------------------------------
# Phase metadata
# ---------------------------------------------------------------------------

PHASE_REGISTRY: dict[str, dict[str, Any]] = {
    "subfinder": {
        "label": "子域名枚举",
        "runner": run_subfinder,
        "output_key": "domains",
        "tool": "subfinder_json.py",
    },
    "dnsx": {
        "label": "可信 DNS 基线",
        "runner": run_dnsx,
        "output_key": "dns_records",
        "tool": "dnsx_json.py",
    },
    "httpx": {
        "label": "Web 存活探测",
        "runner": run_httpx,
        "output_key": "alive_urls",
        "tool": "httpx_probe.py",
    },
    "tlsx": {
        "label": "TLS 指纹",
        "runner": run_tlsx,
        "output_key": "tls_records",
        "tool": "tlsx_json.py",
    },
    "naabu": {
        "label": "快速全端口发现",
        "runner": run_naabu,
        "output_key": "open_ports",
        "tool": "naabu_json_scan.py",
    },
    "nmap": {
        "label": "端口扫描",
        "runner": run_nmap,
        "output_key": "ports",
        "tool": "nmap_json_scan.py",
    },
    "katana": {
        "label": "Web 爬取",
        "runner": run_katana,
        "output_key": "crawled_urls",
        "tool": "katana_crawl.py",
    },
    "history": {
        "label": "历史 URL 收集",
        "runner": run_history,
        "output_key": "history_urls",
        "tool": "url_history_collect.py",
    },
    "gf": {
        "label": "GF 模式匹配",
        "runner": run_gf,
        "output_key": "gf_matches",
        "tool": "gf_pattern_match.py",
    },
    "nuclei": {
        "label": "Nuclei 漏洞扫描",
        "runner": run_nuclei,
        "output_key": "nuclei_findings",
        "tool": "nuclei_json_scan.py",
    },
    "ffuf": {
        "label": "目录 Fuzz",
        "runner": run_ffuf,
        "output_key": "ffuf_results",
        "tool": "ffuf_json.py",
    },
    "js_intel": {
        "label": "离线 JS 情报",
        "runner": run_js_intel,
        "output_key": "observations",
        "tool": "scan_pipeline:offline",
    },
    "api_contract": {
        "label": "离线 API 契约",
        "runner": run_api_contract,
        "output_key": "observations",
        "tool": "scan_pipeline:offline",
    },
    "control_gap": {
        "label": "离线控制缺口",
        "runner": run_control_gap,
        "output_key": "observations",
        "tool": "scan_pipeline:offline",
    },
    "candidate_queue": {
        "label": "赏金候选队列",
        "runner": run_candidate_queue,
        "output_key": "bounty_candidates",
        "tool": "bounty_candidate_queue.py",
    },
    "tactic_match": {
        "label": "Tactic 匹配 Sidecar",
        "runner": run_tactic_match,
        "output_key": "observations",
        "tool": "scan_pipeline:offline",
    },
    "semantic_quality_gate": {
        "label": "语义质量门禁",
        "runner": run_quality_gate,
        "output_key": "quality_gate",
        "tool": "quality_gate.py",
    },
    "quality_gate": {
        "label": "质量门禁（兼容别名）",
        "runner": run_quality_gate,
        "output_key": "quality_gate",
        "tool": "quality_gate.py",
    },
    "browser_validate": {
        "label": "浏览器验证计划",
        "runner": run_dynamic_plan,
        "output_key": "observations",
        "tool": "plan-only:browser.interactive",
    },
    "burp_replay": {
        "label": "HTTP 重放计划",
        "runner": run_dynamic_plan,
        "output_key": "observations",
        "tool": "plan-only:http.replay",
    },
    "js_runtime_validate": {
        "label": "JS 运行时验证计划",
        "runner": run_dynamic_plan,
        "output_key": "observations",
        "tool": "plan-only:js.cdp",
    },
    "oast_check": {
        "label": "OAST 验证计划",
        "runner": run_dynamic_plan,
        "output_key": "observations",
        "tool": "plan-only:oast.callback",
    },
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan pipeline orchestrator — codified recon chain."
    )
    # Target
    target_group = p.add_mutually_exclusive_group(required=False)
    target_group.add_argument("--domain", help="Root domain for subfinder enumeration.")
    target_group.add_argument("--input", help="File containing one domain/URL per line (bypasses subfinder).")

    # Mode
    p.add_argument("--mode", choices=["quick", "full", "deep"], default="quick",
                   help="Preset scan depth (default: quick).")
    p.add_argument("--phases", help="Comma-separated explicit phase list (overrides --mode).")
    p.add_argument(
        "--network-profile",
        choices=sorted(NETWORK_PROFILES),
        default="internet-web",
        help="Network target profile (default: internet-web). Only lan selects nmap lan-fast.",
    )

    # Output
    p.add_argument("--output-dir", help="Base output directory (default: /tmp/codex-scan-pipelines/<domain>-<ts>).")

    # Execution
    p.add_argument("--authorized", action="store_true", required=True,
                   help="Required acknowledgement of authorized scope.")
    p.add_argument("--timeout", type=int, default=7200,
                   help="Per-phase timeout in seconds (default: 7200 = 2h).")
    p.add_argument("--resume", help="Resume from a previous pipeline_state.json file.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print phase plan without executing.")
    p.add_argument(
        "--capabilities",
        help=(
            "Explicit capability report for optional dynamic-plan phases; "
            "the pipeline never performs runtime discovery automatically."
        ),
    )
    p.add_argument(
        "--materials",
        help=(
            "JSON manifest containing material identifiers only; values and "
            "secrets are never copied into dynamic plans."
        ),
    )

    # Tool overrides
    p.add_argument("--tool-home", help="Override PD tool HOME for subfinder/httpx/katana/nuclei.")
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

class Pipeline:
    """Manages phase execution, state persistence, and output tree."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.started_at = utc_now()

        # Resolve phases
        if args.phases:
            requested_phases = [
                s.strip() for s in args.phases.split(",") if s.strip()
            ]
        else:
            requested_phases = list(MODE_PHASES[args.mode].keys())
        self.phases = _normalize_phase_order(requested_phases)

        # Validate
        unknown = set(self.phases) - set(PHASE_REGISTRY)
        if unknown:
            raise SystemExit(f"Unknown phase(s): {', '.join(sorted(unknown))}")

        # Output directory
        if args.output_dir:
            self.output_dir = Path(args.output_dir)
        else:
            tag = args.domain or (Path(args.input).stem if args.input else "pipeline")
            self.output_dir = DEFAULT_OUTPUT_BASE / f"{tag}-{datetime.now().strftime('%Y%m%dT%H%M%S')}"

        self.state_path = self.output_dir / "pipeline_state.json"

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def load_state(self) -> dict[str, Any]:
        if self.state_path.is_file():
            state = read_json(self.state_path)
        else:
            state = {
                "state_version": "2.0",
                "started_at": self.started_at,
                "domain": self.args.domain,
                "mode": self.args.mode,
                "network_profile": self.args.network_profile,
                "capabilities_file": self.args.capabilities,
                "materials_file": self.args.materials,
                "phases_requested": self.phases,
                "phases_completed": [],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {},
                "current_phase": None,
            }
        prior_phases = state.get("phases_requested", [])
        state.setdefault("state_version", "1.0")
        state.setdefault("network_profile", getattr(self.args, "network_profile", "internet-web"))
        state.setdefault("capabilities_file", getattr(self.args, "capabilities", None))
        state.setdefault("materials_file", getattr(self.args, "materials", None))
        if not isinstance(state.get("phase_outputs"), dict):
            state["phase_outputs"] = {}
        for phase_id, details in state["phase_outputs"].items():
            if not isinstance(details, dict):
                continue
            details.setdefault("phase_id", phase_id)
            details.setdefault("input_sources", [])
            if "status" not in details:
                if details.get("ok"):
                    details["status"] = "completed"
                elif details.get("skipped"):
                    details["status"] = "skipped"
                else:
                    details["status"] = "failed"
        for key in ("phases_completed", "phases_skipped", "phases_failed"):
            values = state.get(key, [])
            state[key] = (
                list(dict.fromkeys(values))
                if isinstance(values, list)
                else []
            )
        for phase_id, details in state["phase_outputs"].items():
            if not isinstance(details, dict):
                continue
            status = details.get("status")
            if status not in {"completed", "skipped", "failed"}:
                continue
            expected = {
                "completed": "phases_completed",
                "skipped": "phases_skipped",
                "failed": "phases_failed",
            }[status]
            memberships = [
                key
                for key in (
                    "phases_completed",
                    "phases_skipped",
                    "phases_failed",
                )
                if phase_id in state[key]
            ]
            if memberships != [expected]:
                self._transition_phase_status(state, phase_id, status)
        state["phases_requested"] = list(self.phases)
        self._invalidate_early_quality_gate(state, prior_phases)
        return state

    def _invalidate_early_quality_gate(
        self, state: dict[str, Any], prior_phases: Any
    ) -> None:
        """Re-run a quality result created before its candidate dependency."""

        if not {"candidate_queue", "quality_gate"}.issubset(self.phases):
            return
        completed = state.get("phases_completed", [])
        legacy_order = (
            isinstance(prior_phases, list)
            and "candidate_queue" in prior_phases
            and "quality_gate" in prior_phases
            and prior_phases.index("quality_gate")
            < prior_phases.index("candidate_queue")
        )
        if (
            not isinstance(completed, list)
            or "quality_gate" not in completed
            or ("candidate_queue" in completed and not legacy_order)
        ):
            return

        for key in ("phases_completed", "phases_skipped", "phases_failed"):
            values = state.get(key, [])
            if isinstance(values, list):
                state[key] = [
                    phase for phase in values if phase != "quality_gate"
                ]
        state["phase_outputs"].pop("quality_gate", None)

    def save_state(self, state: dict[str, Any]) -> None:
        state["state_version"] = "2.0"
        state["network_profile"] = getattr(
            self.args, "network_profile", "internet-web"
        )
        state["capabilities_file"] = getattr(self.args, "capabilities", None)
        state["materials_file"] = getattr(self.args, "materials", None)
        state["updated_at"] = utc_now()
        write_json(self.state_path, state)

    @staticmethod
    def _transition_phase_status(
        state: dict[str, Any], phase: str, status: str
    ) -> None:
        """Move one phase atomically between completed/skipped/failed lists."""

        buckets = {
            "completed": "phases_completed",
            "skipped": "phases_skipped",
            "failed": "phases_failed",
        }
        if status not in buckets:
            raise ValueError(f"unknown phase status: {status}")
        for key in buckets.values():
            values = state.get(key, [])
            if not isinstance(values, list):
                values = []
            state[key] = [item for item in values if item != phase]
        state[buckets[status]].append(phase)

    # ------------------------------------------------------------------
    # Input resolution
    # ------------------------------------------------------------------

    def _phase_dir(self, phase: str) -> Path:
        """Return the canonical, index-independent directory for a phase."""

        return self.output_dir / f"phase_{phase}"

    def _phase_output_path(self, phase: str, state: dict[str, Any]) -> Path | None:
        """Resolve an output from state first, then canonical and legacy paths."""

        details = state.get("phase_outputs", {}).get(phase, {})
        if isinstance(details, dict) and details.get("output_file"):
            recorded = Path(str(details["output_file"]))
            candidates = (
                [recorded]
                if recorded.is_absolute()
                else [self.output_dir / recorded, recorded]
            )
            for candidate in candidates:
                if candidate.is_file():
                    return candidate

        for filename in ("result.json", "output.json"):
            canonical = self._phase_dir(phase) / filename
            if canonical.is_file():
                return canonical

        # Compatibility fallback for v1 phase_01_<name> directories.
        for legacy_dir in sorted(self.output_dir.glob(f"phase_*_{phase}")):
            for filename in ("result.json", "output.json"):
                candidate = legacy_dir / filename
                if candidate.is_file():
                    return candidate
        return None

    def _phase_dependencies(self, phase: str) -> list[str]:
        return list(PHASE_DAG.get(phase, {}).get("depends_on", []))

    def _phase_overrides(self, phase: str) -> dict[str, Any]:
        overrides = dict(MODE_PHASES.get(self.args.mode, {}).get(phase, {}))
        if phase == "nmap":
            profile_name = getattr(self.args, "network_profile", "internet-web")
            profile = NETWORK_PROFILES[profile_name]["nmap_profile"]
            overrides["profile"] = profile
        return overrides

    def _phase_source_files(
        self,
        phase: str,
        state: dict[str, Any],
    ) -> list[Path]:
        """Resolve immutable outputs from completed selected dependencies."""

        sources: list[Path] = []
        phase_outputs = state.get("phase_outputs", {})
        for dependency in self._phase_dependencies(phase):
            details = phase_outputs.get(dependency, {})
            if not isinstance(details, dict) or details.get("status") != "completed":
                continue
            source = self._phase_output_path(dependency, state)
            if source is not None:
                sources.append(source)
        return list(dict.fromkeys(sources))

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> int:
        state = self.load_state()
        already_done = set(state.get("phases_completed", []))

        if self.args.dry_run:
            self._print_plan()
            return 0

        # Persist normalized legacy/resume state even when every requested
        # phase is already complete and the execution loop performs no writes.
        self.save_state(state)

        for idx, phase in enumerate(self.phases):
            if phase in already_done:
                print(f"[skip] Phase {idx+1}/{len(self.phases)}: {PHASE_REGISTRY[phase]['label']} ({phase}) — already completed")
                continue

            state["current_phase"] = phase
            self.save_state(state)

            phase_dir = self._phase_dir(phase)
            phase_dir.mkdir(parents=True, exist_ok=True)
            output_file = phase_dir / "result.json"
            overrides = self._phase_overrides(phase)

            print(f"\n{'='*60}")
            print(f"Phase {idx+1}/{len(self.phases)}: {PHASE_REGISTRY[phase]['label']} ({phase})")
            print(f"  output: {output_file}")
            print(f"{'='*60}")

            runner = PHASE_REGISTRY[phase]["runner"]

            # --- resolve inputs from prior phases ---------------------------
            input_missing = False
            input_sources: list[str] = []
            kw: dict[str, Any] = {"output_file": output_file, "timeout": self.args.timeout}
            kw.update(overrides)

            if phase == "subfinder":
                kw["domain"] = self.args.domain
                kw["input_file"] = Path(self.args.input) if self.args.input else None
                if self.args.domain:
                    input_sources.append(f"root_domain:{self.args.domain}")
                if self.args.input:
                    input_sources.append(str(Path(self.args.input)))
                if not kw["domain"] and not kw["input_file"]:
                    result = {"ok": False, "skipped": True,
                              "reason": "no --domain or --input provided; cannot enumerate subdomains"}
                    input_missing = True

            elif phase == "dnsx":
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from subfinder or --input; nothing to resolve"}
                    input_missing = True

            elif phase == "httpx":
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from subfinder, root domain, or --input; nothing to probe"}
                    input_missing = True

            elif phase in {"tlsx", "naabu"}:
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": f"no host list from httpx; nothing to run {phase} against"}
                    input_missing = True

            elif phase == "nmap":
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["target_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from httpx; nothing to port-scan"}
                    input_missing = True

            elif phase == "katana":
                txt_input, input_sources = self._build_url_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive URLs from httpx; nothing to crawl"}
                    input_missing = True

            elif phase == "history":
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive hosts from httpx; nothing to collect historical URLs for"}
                    input_missing = True

            elif phase == "gf":
                txt_input, input_sources = self._build_combined_url_input(
                    phase_dir, state
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no URL list from katana/history; nothing to pattern-match"}
                    input_missing = True

            elif phase == "nuclei":
                txt_input, input_sources = self._build_host_input_details(
                    phase, state, phase_dir
                )
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from httpx; nothing to scan with nuclei"}
                    input_missing = True

            elif phase == "ffuf":
                alive, input_sources = self._extract_alive_urls(state)
                if alive:
                    kw["target_urls"] = alive
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive URLs from httpx; nothing to fuzz"}
                    input_missing = True

            elif phase in {"quality_gate", "semantic_quality_gate"}:
                kw["pipeline_dir"] = self.output_dir
                kw["mode"] = self.args.mode
                input_sources = [
                    str(path) for path in self._phase_source_files(phase, state)
                ]
                input_sources.append(str(self.state_path))

            elif phase == "candidate_queue":
                kw["pipeline_dir"] = self.output_dir
                input_sources = [
                    str(path) for path in self._phase_source_files(phase, state)
                ]
                input_sources.append(str(self.state_path))

            elif phase in {
                "js_intel",
                "api_contract",
                "control_gap",
                "tactic_match",
            }:
                source_files = self._phase_source_files(phase, state)
                kw["source_files"] = source_files
                input_sources = [str(path) for path in source_files]

            elif phase in DYNAMIC_PHASE_SPECS:
                source_files = self._phase_source_files(phase, state)
                capabilities_file = (
                    Path(self.args.capabilities)
                    if self.args.capabilities
                    else None
                )
                materials_file = (
                    Path(self.args.materials)
                    if self.args.materials
                    else None
                )
                kw.update(
                    {
                        "phase_id": phase,
                        "source_files": source_files,
                        "capabilities_file": capabilities_file,
                        "materials_file": materials_file,
                    }
                )
                input_sources = [str(path) for path in source_files]
                for optional_file in (capabilities_file, materials_file):
                    if optional_file is not None and optional_file.is_file():
                        input_sources.append(str(optional_file))

            if input_missing:
                pass  # result already set above
            else:
                try:
                    result = runner(**kw)
                except Exception as exc:
                    result = {"ok": False, "error": str(exc)}

            ok = result.get("ok", False)
            if not ok and _tool_missing(result):
                result["skipped"] = True
                result["reason"] = _error_message(result.get("result", {}), None) or "required binary not found"
            skipped = result.get("skipped", False)

            if ok:
                self._transition_phase_status(state, phase, "completed")
                state["phase_outputs"][phase] = {
                    "phase_id": phase,
                    "status": "completed",
                    "ok": True,
                    "output_file": str(output_file),
                    "output_sha256": (
                        _sha256_file(output_file) if output_file.is_file() else None
                    ),
                    "input_sources": list(dict.fromkeys(input_sources)),
                    "summary": _summarize_phase(phase, result),
                }
                print(f"  ✓ {phase} completed{'(skipped)' if skipped else ''}")
            else:
                if skipped:
                    self._transition_phase_status(state, phase, "skipped")
                else:
                    self._transition_phase_status(state, phase, "failed")
                state["phase_outputs"][phase] = {
                    "phase_id": phase,
                    "status": "skipped" if skipped else "failed",
                    "ok": False,
                    "error": result.get("reason", result.get("error", "unknown")),
                    "skipped": skipped,
                    "output_file": str(output_file),
                    "output_sha256": (
                        _sha256_file(output_file) if output_file.is_file() else None
                    ),
                    "input_sources": list(dict.fromkeys(input_sources)),
                }
                if skipped:
                    print(f"  ⊝ {phase} skipped: {result.get('reason', result.get('error', ''))}")
                else:
                    print(f"  ✗ {phase} failed: {result.get('error', 'unknown')}")

            self.save_state(state)

        # --- final summary ----------------------------------------------------
        self._write_summary(state)
        print(f"\n{'='*60}")
        print(f"Pipeline complete.")
        print(f"  completed: {len(state.get('phases_completed', []))}/{len(self.phases)}")
        if state.get("phases_skipped"):
            print(f"  skipped phases: {', '.join(state['phases_skipped'])}")
        print(f"  output dir: {self.output_dir}")
        print(f"  state file: {self.state_path}")
        if state.get("phases_failed"):
            print(f"  failed phases: {', '.join(state['phases_failed'])}")
        print(f"{'='*60}")

        return 0 if not state.get("phases_failed") else 1

    # ------------------------------------------------------------------
    # Input builders
    # ------------------------------------------------------------------

    def _build_host_input_details(
        self, phase: str, state: dict[str, Any], phase_dir: Path
    ) -> tuple[Path | None, list[str]]:
        """Build a de-duplicated host input and report every source used."""

        hosts: set[str] = set()
        sources: list[str] = []
        for dependency in self._phase_dependencies(phase):
            result_path = self._phase_output_path(dependency, state)
            if result_path is None:
                continue
            hosts.update(
                _extract_hosts(
                    read_json(result_path),
                    PHASE_REGISTRY[dependency]["output_key"],
                )
            )
            sources.append(str(result_path))

        fallback_inputs = PHASE_DAG.get(phase, {}).get("fallback_inputs", [])
        if "root_domain" in fallback_inputs and self.args.domain:
            hosts.add(self.args.domain.strip())
            sources.append(f"root_domain:{self.args.domain.strip()}")
        if "input_file" in fallback_inputs and self.args.input:
            input_path = Path(self.args.input)
            hosts.update(read_lines(input_path))
            sources.append(str(input_path))

        hosts.discard("")
        if not hosts:
            return None, list(dict.fromkeys(sources))
        phase_dir.mkdir(parents=True, exist_ok=True)
        host_file = phase_dir / "input_hosts.txt"
        host_file.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")
        return host_file, list(dict.fromkeys(sources))

    def _build_host_input(
        self, phase: str, state: dict[str, Any], phase_dir: Path
    ) -> Path | None:
        """Compatibility wrapper returning only the generated host file."""

        return self._build_host_input_details(phase, state, phase_dir)[0]

    def _build_url_input_details(
        self, phase: str, state: dict[str, Any], phase_dir: Path
    ) -> tuple[Path | None, list[str]]:
        urls: set[str] = set()
        sources: list[str] = []
        for dependency in self._phase_dependencies(phase):
            result_path = self._phase_output_path(dependency, state)
            if result_path is None:
                continue
            urls.update(
                _extract_urls(
                    read_json(result_path),
                    PHASE_REGISTRY[dependency]["output_key"],
                )
            )
            sources.append(str(result_path))
        if not urls:
            return None, sources
        phase_dir.mkdir(parents=True, exist_ok=True)
        url_file = phase_dir / "input_urls.txt"
        url_file.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
        return url_file, list(dict.fromkeys(sources))

    def _build_url_input(
        self, phase: str, state: dict[str, Any], phase_dir: Path
    ) -> Path | None:
        return self._build_url_input_details(phase, state, phase_dir)[0]

    def _build_combined_url_input(
        self, phase_dir: Path, state: dict[str, Any]
    ) -> tuple[Path | None, list[str]]:
        """Merge URL-producing DAG dependencies for GF classification."""

        urls: set[str] = set()
        sources: list[str] = []
        for dependency in self._phase_dependencies("gf"):
            result_path = self._phase_output_path(dependency, state)
            if result_path is None:
                continue
            urls.update(
                _extract_urls(
                    read_json(result_path),
                    PHASE_REGISTRY[dependency]["output_key"],
                )
            )
            sources.append(str(result_path))
        if not urls:
            return None, sources
        sorted_urls = sorted(urls)
        phase_dir.mkdir(parents=True, exist_ok=True)
        url_file = phase_dir / "all_urls_dedup.txt"
        url_file.write_text("\n".join(sorted_urls) + "\n", encoding="utf-8")
        urls_dir = self.output_dir / "urls"
        urls_dir.mkdir(parents=True, exist_ok=True)
        (urls_dir / "all-urls-dedup.txt").write_text(
            "\n".join(sorted_urls) + "\n", encoding="utf-8"
        )
        return url_file, list(dict.fromkeys(sources))

    def _extract_alive_urls(
        self, state: dict[str, Any]
    ) -> tuple[list[str], list[str]]:
        """Get alive URLs from the explicitly recorded httpx output."""

        result_path = self._phase_output_path("httpx", state)
        if result_path is None:
            return [], []
        return _extract_alive_urls(read_json(result_path)), [str(result_path)]

    # ------------------------------------------------------------------
    # Dry-run / summary
    # ------------------------------------------------------------------

    def _print_plan(self) -> None:
        print(f"\nPipeline plan — mode={self.args.mode}, domain={self.args.domain or self.args.input}")
        print(f"Network profile: {self.args.network_profile}")
        print(f"Output dir: {self.output_dir}")
        print(f"{'Phase':<4} {'Name':<12} {'Tool':<25} {'Async':<8} {'Profile':<12}")
        print("-" * 70)
        for i, p in enumerate(self.phases):
            meta = PHASE_REGISTRY[p]
            overrides = self._phase_overrides(p)
            is_async = "async" if _phase_is_async(p, overrides) else "sync"
            profile = str(overrides.get("profile", "-"))
            print(f"{i+1:<4} {p:<12} {meta['tool']:<25} {is_async:<8} {profile:<12}")
        print()

    def _write_summary(self, state: dict[str, Any]) -> None:
        summary_path = self.output_dir / "summary.json"
        lines: list[str] = []
        for p in self.phases:
            po = state.get("phase_outputs", {}).get(p, {})
            ok = "✓" if po.get("ok") else ("⊝" if po.get("skipped") else "✗")
            lines.append(f"{ok} {p}: {po.get('summary', po.get('error', '-'))}")
        summary = {
            "ok": len(state.get("phases_failed", [])) == 0,
            "tool": "scan_pipeline",
            "started_at": state.get("started_at"),
            "finished_at": utc_now(),
            "mode": self.args.mode,
            "network_profile": self.args.network_profile,
            "phases_requested": self.phases,
            "phases_completed": state.get("phases_completed", []),
            "phases_skipped": state.get("phases_skipped", []),
            "phases_failed": state.get("phases_failed", []),
            "phase_details": state.get("phase_outputs", {}),
            "one_liner": " | ".join(lines),
            "output_dir": str(self.output_dir),
            "state_file": str(self.state_path),
        }
        write_json(summary_path, summary)
        print(f"\n  summary → {summary_path}")


# ---------------------------------------------------------------------------
# Output extraction helpers
# ---------------------------------------------------------------------------

def _extract_hosts(data: dict[str, Any], key: str) -> list[str]:
    """Pull host/domain strings from the normalized JSON output of a prior phase."""
    hosts: list[str] = []

    # subfinder output: {"ok": true, "subdomains": [{"host": "x.sto.cn"}, ...]}
    if key == "domains":
        for item in _list(data, "subdomains"):
            h = item.get("host", "") or item.get("subdomain", "")
            if h:
                hosts.append(h)
        # Also check "results"
        for item in _list(data, "results"):
            h = item.get("host", "") or item.get("subdomain", "")
            if h:
                hosts.append(h)
        return sorted(set(hosts))

    # httpx output: {"ok": true, "results": [{"url": "https://...", "host": "..."}, ...]}
    # Fall back to anything with a 'host' or 'url' field.
    for item in _list(data, "results"):
        h = item.get("host", "") or item.get("input", "") or item.get("name", "")
        if h and not h.startswith("http"):
            hosts.append(h)
        for ip_key in ("ip", "address"):
            ip_value = item.get(ip_key, "")
            if ip_value:
                hosts.append(str(ip_value))
        url = item.get("url", "")
        if url and "://" in url:
            # extract host from URL
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.hostname:
                    hosts.append(parsed.hostname)
            except Exception:
                pass
    return sorted(set(hosts))


def _extract_urls(data: dict[str, Any], key: str) -> list[str]:
    """Pull full URL strings from a prior phase's normalized JSON."""
    urls: set[str] = set()

    # katana output: {"ok": true, "results": [{"request_url": "..."}, ...]}
    for item in _list(data, "results"):
        for url_key in ("request_url", "url", "URL"):
            u = item.get(url_key, "")
            if u and "://" in u:
                urls.add(u)

    # gf output: {"ok": true, "patterns": [{"matched_urls": [...]}, ...]}
    for pat in _list(data, "patterns"):
        for u in _list(pat, "matched_urls"):
            if isinstance(u, str) and "://" in u:
                urls.add(u)

    # nuclei output — usually findings, not raw URLs; skip for URL pipeline.
    return sorted(urls)


def _extract_alive_urls(data: dict[str, Any]) -> list[str]:
    """From httpx output, extract URLs that returned HTTP 200/30x."""
    urls: list[str] = []
    for item in _list(data, "results"):
        url = item.get("url", "")
        if url and "://" in url:
            urls.append(url)
    return urls


def _list(data: dict[str, Any], key: str) -> list[Any]:
    val = data.get(key, [])
    return val if isinstance(val, list) else []


def _summarize_phase(phase: str, result: dict[str, Any]) -> str:
    """Produce a one-line summary for the final report."""
    r = result.get("result", {})
    if phase == "subfinder":
        count = len(_list(r, "subdomains") or _list(r, "results"))
        return f"{count} subdomains"
    if phase == "httpx":
        count = len(_list(r, "results"))
        return f"{count} HTTP responses"
    if phase == "dnsx":
        count = len(_list(r, "results"))
        flagged = sum(1 for item in _list(r, "results") if item.get("codex_dns_flags", {}).get("fake_ip"))
        return f"{count} DNS records" + (f", {flagged} fake-ip flagged" if flagged else "")
    if phase == "tlsx":
        count = len(_list(r, "results"))
        return f"{count} TLS records"
    if phase == "naabu":
        count = len(_list(r, "results"))
        return f"{count} open-port candidates"
    if phase == "nmap":
        hosts = r.get("hosts_scanned", "?")
        return f"{hosts} hosts scanned"
    if phase == "katana":
        count = len(_list(r, "results"))
        return f"{count} URLs crawled"
    if phase == "gf":
        count = r.get("total_matched_urls", "?")
        return f"{count} total matches"
    if phase == "history":
        count = len(_list(r, "results"))
        return f"{count} historical URLs"
    if phase == "nuclei":
        findings = len(_list(r, "results") or _list(r, "findings"))
        return f"{findings} findings"
    if phase == "ffuf":
        ok = r.get("targets_ok", 0)
        total = r.get("targets_scanned", 0)
        return f"{ok}/{total} targets with results"
    if phase in {"quality_gate", "semantic_quality_gate"}:
        return f"{r.get('status', 'UNKNOWN')}: {r.get('conclusion', '')}"
    if phase == "candidate_queue":
        summary = r.get("queue_summary", {})
        return (
            f"{r.get('candidate_count', 0)} candidates "
            f"(P0={summary.get('P0', 0)}, P1={summary.get('P1', 0)}, "
            f"P2={summary.get('P2', 0)}, P3={summary.get('P3', 0)})"
        )
    if phase == "js_intel":
        counts = r.get("observations", {}).get("counts", {})
        return (
            f"{counts.get('javascript_assets', 0)} JS assets, "
            f"{counts.get('api_references', 0)} API references"
        )
    if phase == "api_contract":
        count = r.get("observations", {}).get("endpoint_count", 0)
        return f"{count} normalized API endpoints"
    if phase == "control_gap":
        count = r.get("observations", {}).get("gap_count", 0)
        return f"{count} control-gap hypotheses"
    if phase == "tactic_match":
        observations = r.get("observations", {})
        return (
            f"{observations.get('matched_candidate_count', 0)} matched, "
            f"{observations.get('route_gap_count', 0)} route gaps"
        )
    if phase in DYNAMIC_PHASE_SPECS:
        status = r.get("observations", {}).get("execution_status", "planned")
        return f"{status}; no automatic dynamic execution"
    return "ok"


def _phase_is_async(phase: str, overrides: dict[str, Any]) -> bool:
    if phase == "katana":
        return overrides.get("headless", False) or overrides.get("depth", 3) >= 3
    if phase == "nuclei":
        return True
    if phase == "nmap":
        return False  # we use sync by default; --async-start is an option
    return False


# ---------------------------------------------------------------------------
# entry
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.resume:
        if not Path(args.resume).is_file():
            print(f"Error: state file not found: {args.resume}", file=sys.stderr)
            return 2
        # Reconstruct minimal args from state
        state = read_json(Path(args.resume))
        args.mode = state.get("mode", "full")
        args.domain = state.get("domain")
        args.network_profile = state.get("network_profile", args.network_profile)
        args.capabilities = state.get("capabilities_file", args.capabilities)
        args.materials = state.get("materials_file", args.materials)
        args.output_dir = str(Path(args.resume).parent)
        args.phases = ",".join(state.get("phases_requested", []))

    if not args.domain and not args.input and not args.resume:
        print("Error: --domain or --input or --resume is required.", file=sys.stderr)
        return 2

    pipeline = Pipeline(args)
    return pipeline.run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
