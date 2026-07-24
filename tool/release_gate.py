#!/usr/bin/env python3
"""Run Cybertest's offline release checks in a fixed, auditable order."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECK_COMMANDS = (
    (
        "unit_tests",
        (
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_*.py",
        ),
    ),
    (
        "markdown_links",
        (
            sys.executable,
            "tool/check_markdown_links.py",
            "--dry-run",
            "--fail-on-broken",
        ),
    ),
    (
        "case_index",
        (
            sys.executable,
            "tool/build_case_index.py",
            "--check",
        ),
    ),
    (
        "reusable_knowledge",
        (
            sys.executable,
            "tool/scan_reusable_knowledge_leaks.py",
            "--dry-run",
            "--fail-severity",
            "medium",
            "--fail-on-findings",
        ),
    ),
    (
        "pipeline_dry_run",
        (
            sys.executable,
            "tool/scan_pipeline.py",
            "--authorized",
            "--domain",
            "example.com",
            "--mode",
            "full",
            "--dry-run",
        ),
    ),
)


def canonical_json(document: Any) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _run_command(
    command: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        completed = runner(
            list(command),
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "ERROR", "returncode": 2}
    return {
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
    }


def _repository_hygiene(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    try:
        completed = runner(
            ["git", "ls-files"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {"status": "ERROR", "returncode": 2}
    if completed.returncode != 0:
        return {"status": "FAIL", "returncode": completed.returncode}
    tracked_caches = [
        path
        for path in completed.stdout.splitlines()
        if "/__pycache__/" in f"/{path}"
        or path.endswith((".pyc", ".pyo", ".pyd"))
    ]
    return {
        "status": "PASS" if not tracked_caches else "FAIL",
        "returncode": 0 if not tracked_caches else 1,
        "tracked_cache_count": len(tracked_caches),
    }


def run_checks(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}
    for check_id, command in CHECK_COMMANDS[:4]:
        checks[check_id] = _run_command(command, runner=runner)
    checks["repository_hygiene"] = _repository_hygiene(runner=runner)
    check_id, command = CHECK_COMMANDS[4]
    checks[check_id] = _run_command(command, runner=runner)
    ok = all(item["status"] == "PASS" for item in checks.values())
    return {
        "schema_version": "1.0",
        "tool": "release_gate",
        "ok": ok,
        "checks": checks,
    }


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description=(
            "Run unittest, Markdown links, case index, strict reusable-"
            "knowledge, repository hygiene and pipeline dry-run gates."
        )
    )


def main(argv: list[str] | None = None) -> int:
    _build_parser().parse_args(argv)
    report = run_checks()
    sys.stdout.write(canonical_json(report))
    if any(
        item["status"] == "ERROR"
        for item in report["checks"].values()
    ):
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
