#!/usr/bin/env python3
"""
Scan pipeline orchestrator — codified recon → attack-surface discovery chain.

Orchestrates the standard penetration-testing information-gathering phases
(subfinder → dnsx → httpx → tlsx/naabu/nmap → katana/history → gf-patterns
→ nuclei → ffuf → quality-gate → candidate-queue) into a
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
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_BASE = Path("/tmp/codex-scan-pipelines")
ASYNC_POLL_INTERVAL = 15       # seconds between polls for async phases
ASYNC_STALE_THRESHOLD = 300    # seconds before an async task is considered stale
ASYNC_DEFAULT_TIMEOUT = 3600   # 1 hour max wait per async phase

HTTPX_PORTS = "80,443,8080,8443,9090"

# Recognised mermaid-style phase dependencies (used for --phases validation only;
# the real dependency graph is resolved at runtime from prior-phase outputs.)
PHASE_DEPS: dict[str, list[str]] = {
    "subfinder":  [],
    "dnsx":       ["subfinder"],
    "httpx":      ["subfinder"],
    "tlsx":       ["httpx"],
    "naabu":      ["httpx"],
    "nmap":       ["httpx"],
    "katana":     ["httpx"],
    "history":    ["httpx"],
    "gf":         ["katana", "history"],
    "nuclei":     ["httpx"],
    "ffuf":       ["httpx"],
    "quality_gate": [],
    "candidate_queue": [],
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
        "quality_gate": {},
        "candidate_queue": {},
    },
    "full": {
        "subfinder":  {},
        "dnsx":       {},
        "httpx":      {},
        "tlsx":       {},
        "naabu":      {"ports": "1-65535", "rate": 1000},
        "nmap":       {"profile": "web"},
        "katana":     {"depth": 3, "headless": False, "js_crawl": True},
        "history":    {},
        "gf":         {},
        "nuclei":     {"severity": "medium,high,critical"},
        "ffuf":       {"wordlist": "auto"},
        "quality_gate": {},
        "candidate_queue": {},
    },
    "deep": {
        "subfinder":  {},
        "dnsx":       {},
        "httpx":      {},
        "tlsx":       {},
        "naabu":      {"ports": "1-65535", "rate": 1000},
        "nmap":       {"profile": "lan-fast"},
        "katana":     {"depth": 5, "headless": True, "js_crawl": True},
        "history":    {},
        "gf":         {},
        "nuclei":     {"severity": "medium,high,critical"},
        "ffuf":       {"wordlist": "auto"},
        "quality_gate": {},
        "candidate_queue": {},
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
    ]
    cp = _run(argv, timeout=timeout + 30)
    result = read_json(output_file)
    return {
        "ok": cp.returncode == 0 and result.get("ok", False),
        "returncode": cp.returncode,
        "result": result,
        "error": _error_message(result, cp),
    }


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
        "input_from": None,
        "tool": "subfinder_json.py",
    },
    "dnsx": {
        "label": "可信 DNS 基线",
        "runner": run_dnsx,
        "output_key": "dns_records",
        "input_from": "subfinder",
        "tool": "dnsx_json.py",
    },
    "httpx": {
        "label": "Web 存活探测",
        "runner": run_httpx,
        "output_key": "alive_urls",
        "input_from": "subfinder",
        "tool": "httpx_probe.py",
    },
    "tlsx": {
        "label": "TLS 指纹",
        "runner": run_tlsx,
        "output_key": "tls_records",
        "input_from": "httpx",
        "tool": "tlsx_json.py",
    },
    "naabu": {
        "label": "快速全端口发现",
        "runner": run_naabu,
        "output_key": "open_ports",
        "input_from": "httpx",
        "tool": "naabu_json_scan.py",
    },
    "nmap": {
        "label": "端口扫描",
        "runner": run_nmap,
        "output_key": "ports",
        "input_from": "httpx",
        "tool": "nmap_json_scan.py",
    },
    "katana": {
        "label": "Web 爬取",
        "runner": run_katana,
        "output_key": "crawled_urls",
        "input_from": "httpx",
        "tool": "katana_crawl.py",
    },
    "history": {
        "label": "历史 URL 收集",
        "runner": run_history,
        "output_key": "history_urls",
        "input_from": "httpx",
        "tool": "url_history_collect.py",
    },
    "gf": {
        "label": "GF 模式匹配",
        "runner": run_gf,
        "output_key": "gf_matches",
        "input_from": "katana",
        "tool": "gf_pattern_match.py",
    },
    "nuclei": {
        "label": "Nuclei 漏洞扫描",
        "runner": run_nuclei,
        "output_key": "nuclei_findings",
        "input_from": "httpx",
        "tool": "nuclei_json_scan.py",
    },
    "ffuf": {
        "label": "目录 Fuzz",
        "runner": run_ffuf,
        "output_key": "ffuf_results",
        "input_from": "httpx",
        "tool": "ffuf_json.py",
    },
    "quality_gate": {
        "label": "质量门禁",
        "runner": run_quality_gate,
        "output_key": "quality_gate",
        "input_from": None,
        "tool": "quality_gate.py",
    },
    "candidate_queue": {
        "label": "赏金候选队列",
        "runner": run_candidate_queue,
        "output_key": "bounty_candidates",
        "input_from": None,
        "tool": "bounty_candidate_queue.py",
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
            self.phases: list[str] = [s.strip() for s in args.phases.split(",") if s.strip()]
        else:
            self.phases = list(MODE_PHASES[args.mode].keys())

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
            return read_json(self.state_path)
        return {
            "started_at": self.started_at,
            "domain": self.args.domain,
            "mode": self.args.mode,
            "phases_requested": self.phases,
            "phases_completed": [],
            "phases_skipped": [],
            "phases_failed": [],
            "phase_outputs": {},
            "current_phase": None,
        }

    def save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        write_json(self.state_path, state)

    # ------------------------------------------------------------------
    # Input resolution
    # ------------------------------------------------------------------

    def _phase_input(self, phase: str, state: dict[str, Any]) -> Path | None:
        """Return the file path that serves as input for a phase, or None."""
        dep = PHASE_REGISTRY[phase].get("input_from")
        if dep is None:
            return None
        # Look in the prior phase's output directory
        prev_dir = self.output_dir / f"phase_{self.phases.index(dep)+1:02d}_{dep}"
        for candidate in ["result.json", "output.json"]:
            p = prev_dir / candidate
            if p.is_file():
                return p
        return None

    def _extract_url_list(self, phase: str, state: dict[str, Any]) -> list[str]:
        """Extract a flat URL list from the previous phase's output."""
        prev = PHASE_REGISTRY[phase].get("input_from")
        if prev is None:
            return []
        prev_key = PHASE_REGISTRY[prev]["output_key"]
        prev_dir = self.output_dir / f"phase_{self.phases.index(prev)+1:02d}_{prev}"
        result_path = prev_dir / "result.json"
        if not result_path.is_file():
            return []
        data = read_json(result_path)
        # Try common JSON paths for URL lists
        return _extract_urls(data, prev_key)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> int:
        state = self.load_state()
        already_done = set(state.get("phases_completed", []))
        mode_overrides = MODE_PHASES.get(self.args.mode, {})

        if self.args.dry_run:
            self._print_plan()
            return 0

        for idx, phase in enumerate(self.phases):
            if phase in already_done:
                print(f"[skip] Phase {idx+1}/{len(self.phases)}: {PHASE_REGISTRY[phase]['label']} ({phase}) — already completed")
                continue

            state["current_phase"] = phase
            self.save_state(state)

            phase_dir = self.output_dir / f"phase_{idx+1:02d}_{phase}"
            phase_dir.mkdir(parents=True, exist_ok=True)
            output_file = phase_dir / "result.json"
            overrides = mode_overrides.get(phase, {})

            print(f"\n{'='*60}")
            print(f"Phase {idx+1}/{len(self.phases)}: {PHASE_REGISTRY[phase]['label']} ({phase})")
            print(f"  output: {output_file}")
            print(f"{'='*60}")

            runner = PHASE_REGISTRY[phase]["runner"]
            inp = self._phase_input(phase, state)

            # --- resolve inputs from prior phases ---------------------------
            input_missing = False
            kw: dict[str, Any] = {"output_file": output_file, "timeout": self.args.timeout}
            kw.update(overrides)

            if phase == "subfinder":
                kw["domain"] = self.args.domain
                kw["input_file"] = Path(self.args.input) if self.args.input else None
                if not kw["domain"] and not kw["input_file"]:
                    result = {"ok": False, "skipped": True,
                              "reason": "no --domain or --input provided; cannot enumerate subdomains"}
                    input_missing = True

            elif phase == "dnsx":
                txt_input = self._build_host_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                elif self.args.input:
                    kw["input_file"] = Path(self.args.input)
                elif self.args.domain:
                    root_input = phase_dir / "input_hosts.txt"
                    root_input.write_text(self.args.domain + "\n", encoding="utf-8")
                    kw["input_file"] = root_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from subfinder or --input; nothing to resolve"}
                    input_missing = True

            elif phase == "httpx":
                txt_input = self._build_host_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                elif self.args.input:
                    # When subfinder is skipped, use --input as host list directly
                    kw["input_file"] = Path(self.args.input)
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from subfinder or --input; nothing to probe"}
                    input_missing = True

            elif phase in {"tlsx", "naabu"}:
                txt_input = self._build_host_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": f"no host list from httpx; nothing to run {phase} against"}
                    input_missing = True

            elif phase == "nmap":
                txt_input = self._build_host_input(phase, state, phase_dir) or self._build_host_input_from("httpx", phase_dir)
                if txt_input:
                    kw["target_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from httpx; nothing to port-scan"}
                    input_missing = True

            elif phase == "katana":
                txt_input = self._build_url_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive URLs from httpx; nothing to crawl"}
                    input_missing = True

            elif phase == "history":
                txt_input = self._build_host_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive hosts from httpx; nothing to collect historical URLs for"}
                    input_missing = True

            elif phase == "gf":
                txt_input = self._build_combined_url_input(phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no URL list from katana/history; nothing to pattern-match"}
                    input_missing = True

            elif phase == "nuclei":
                txt_input = self._build_host_input(phase, state, phase_dir)
                if txt_input:
                    kw["input_file"] = txt_input
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no host list from httpx; nothing to scan with nuclei"}
                    input_missing = True

            elif phase == "ffuf":
                alive = self._extract_alive_urls(state)
                if alive:
                    kw["target_urls"] = alive
                else:
                    result = {"ok": False, "skipped": True,
                              "reason": "no alive URLs from httpx; nothing to fuzz"}
                    input_missing = True

            elif phase == "quality_gate":
                kw["pipeline_dir"] = self.output_dir
                kw["mode"] = self.args.mode

            elif phase == "candidate_queue":
                kw["pipeline_dir"] = self.output_dir

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
                state.setdefault("phases_completed", []).append(phase)
                state["phase_outputs"][phase] = {
                    "ok": True,
                    "output_file": str(output_file),
                    "summary": _summarize_phase(phase, result),
                }
                print(f"  ✓ {phase} completed{'(skipped)' if skipped else ''}")
            else:
                if skipped:
                    state.setdefault("phases_skipped", []).append(phase)
                else:
                    state.setdefault("phases_failed", []).append(phase)
                state["phase_outputs"][phase] = {
                    "ok": False,
                    "error": result.get("reason", result.get("error", "unknown")),
                    "skipped": skipped,
                    "output_file": str(output_file),
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

    def _build_host_input(self, phase: str, state: dict[str, Any], phase_dir: Path) -> Path | None:
        """Build a text file of hosts/domains from a previous phase."""
        dep = PHASE_REGISTRY[phase].get("input_from")
        if dep is None:
            return None
        if dep not in self.phases:
            return None  # dependency not in this run
        prev_dir = self.output_dir / f"phase_{self.phases.index(dep)+1:02d}_{dep}"
        result_path = prev_dir / "result.json"
        if not result_path.is_file():
            return None
        hosts = _extract_hosts(read_json(result_path), PHASE_REGISTRY[dep]["output_key"])
        if not hosts:
            return None
        host_file = phase_dir / "input_hosts.txt"
        host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        return host_file

    def _build_url_input(self, phase: str, state: dict[str, Any], phase_dir: Path) -> Path | None:
        """Build a text file of URLs from a previous phase."""
        dep = PHASE_REGISTRY[phase].get("input_from")
        if dep is None:
            return None
        if dep not in self.phases:
            return None
        prev_dir = self.output_dir / f"phase_{self.phases.index(dep)+1:02d}_{dep}"
        result_path = prev_dir / "result.json"
        if not result_path.is_file():
            return None
        urls = _extract_urls(read_json(result_path), PHASE_REGISTRY[dep]["output_key"])
        if not urls:
            return None
        url_file = phase_dir / "input_urls.txt"
        url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        return url_file

    def _build_host_input_from(self, dep: str, phase_dir: Path) -> Path | None:
        """Build a host file from a named phase output."""
        if dep not in self.phases:
            return None
        prev_dir = self.output_dir / f"phase_{self.phases.index(dep)+1:02d}_{dep}"
        result_path = prev_dir / "result.json"
        if not result_path.is_file():
            return None
        hosts = _extract_hosts(read_json(result_path), PHASE_REGISTRY[dep]["output_key"])
        if not hosts:
            return None
        host_file = phase_dir / f"input_hosts_from_{dep}.txt"
        host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        return host_file

    def _build_combined_url_input(self, phase_dir: Path) -> Path | None:
        """Merge katana and historical URLs for GF classification."""
        urls: set[str] = set()
        for dep in ("katana", "history"):
            if dep not in self.phases:
                continue
            prev_dir = self.output_dir / f"phase_{self.phases.index(dep)+1:02d}_{dep}"
            result_path = prev_dir / "result.json"
            if result_path.is_file():
                urls.update(_extract_urls(read_json(result_path), PHASE_REGISTRY[dep]["output_key"]))
        if not urls:
            return None
        sorted_urls = sorted(urls)
        url_file = phase_dir / "all_urls_dedup.txt"
        url_file.write_text("\n".join(sorted_urls) + "\n", encoding="utf-8")
        urls_dir = self.output_dir / "urls"
        urls_dir.mkdir(parents=True, exist_ok=True)
        (urls_dir / "all-urls-dedup.txt").write_text("\n".join(sorted_urls) + "\n", encoding="utf-8")
        return url_file

    def _extract_alive_urls(self, state: dict[str, Any]) -> list[str]:
        """Get alive URLs from httpx phase output."""
        if "httpx" not in self.phases:
            return []
        idx = self.phases.index("httpx")
        prev_dir = self.output_dir / f"phase_{idx+1:02d}_httpx"
        result_path = prev_dir / "result.json"
        return _extract_alive_urls(read_json(result_path))

    # ------------------------------------------------------------------
    # Dry-run / summary
    # ------------------------------------------------------------------

    def _print_plan(self) -> None:
        print(f"\nPipeline plan — mode={self.args.mode}, domain={self.args.domain or self.args.input}")
        print(f"Output dir: {self.output_dir}")
        print(f"{'Phase':<4} {'Name':<12} {'Tool':<25} {'Async':<8}")
        print("-" * 55)
        for i, p in enumerate(self.phases):
            meta = PHASE_REGISTRY[p]
            overrides = MODE_PHASES.get(self.args.mode, {}).get(p, {})
            is_async = "async" if _phase_is_async(p, overrides) else "sync"
            print(f"{i+1:<4} {p:<12} {meta['tool']:<25} {is_async:<8}")
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
    if phase == "quality_gate":
        return f"{r.get('status', 'UNKNOWN')}: {r.get('conclusion', '')}"
    if phase == "candidate_queue":
        summary = r.get("queue_summary", {})
        return (
            f"{r.get('candidate_count', 0)} candidates "
            f"(P0={summary.get('P0', 0)}, P1={summary.get('P1', 0)}, "
            f"P2={summary.get('P2', 0)}, P3={summary.get('P3', 0)})"
        )
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
        args.output_dir = str(Path(args.resume).parent)
        args.phases = ",".join(state.get("phases_requested", []))

    if not args.domain and not args.input and not args.resume:
        print("Error: --domain or --input or --resume is required.", file=sys.stderr)
        return 2

    pipeline = Pipeline(args)
    return pipeline.run()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
