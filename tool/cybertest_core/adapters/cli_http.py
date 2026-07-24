"""Explicit curl-backed HTTP fallback adapter."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .base import (
    AdapterExecutionResult,
    CapabilityProbeResult,
    DynamicAdapter,
    _execution_record,
)


class CLIHttpAdapter(DynamicAdapter):
    capability_id = "cli.http"
    allowed_operations = frozenset({"http_request"})

    def __init__(
        self,
        *,
        task_dir: Path | None = None,
        command: str = "curl",
        which: Callable[[str], str | None] = shutil.which,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.task_dir = task_dir.resolve() if task_dir else None
        self.command = command
        self.which = which
        self.runner = runner

    def probe(self, context: Mapping[str, Any]) -> CapabilityProbeResult:
        permitted = context.get("permitted") is True
        material_ready = context.get("material_ready") is True
        installed = self.which(self.command) is not None
        if not installed:
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
                summary="curl command is not installed",
            )
        try:
            completed = self.runner(
                [self.command, "--version"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            completed = None
        healthy = completed is not None and completed.returncode == 0
        return CapabilityProbeResult(
            capability_id=self.capability_id,
            installed=True,
            configured=True,
            reachable=healthy,
            healthy=healthy,
            permitted=permitted,
            material_ready=material_ready,
            available=healthy and permitted and material_ready,
            health="ok" if healthy else "degraded",
            provider=self.command,
            error_category=None if healthy else "environment",
            summary=(
                "curl executable probe succeeded"
                if healthy
                else "curl executable probe failed"
            ),
        )

    def validate_plan(self, plan: Mapping[str, Any]) -> list[str]:
        errors = super().validate_plan(plan)
        for action in plan.get("actions", []):
            if not isinstance(action, dict):
                continue
            action_id = action.get("action_id")
            parameters = action.get("parameters", {})
            if not isinstance(parameters, dict):
                continue
            url = parameters.get("url")
            if (
                not isinstance(url, str)
                or urlsplit(url).scheme not in {"http", "https"}
                or not urlsplit(url).netloc
            ):
                errors.append(f"invalid_url:{action_id}")
            method = parameters.get("method", "GET")
            if method not in {
                "GET",
                "HEAD",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
            }:
                errors.append(f"invalid_method:{action_id}")
            for reference_name in (
                "body_evidence_ref",
                "header_evidence_ref",
            ):
                reference = parameters.get(reference_name)
                if (
                    not isinstance(reference, str)
                    or not reference.startswith("evidence/restricted/")
                ):
                    errors.append(f"missing_{reference_name}:{action_id}")
                elif reference not in action.get("evidence_refs", []):
                    errors.append(
                        f"unbound_{reference_name}:{action_id}"
                    )
            for optional_reference in (
                "request_body_file_ref",
                "request_header_file_ref",
            ):
                reference = parameters.get(optional_reference)
                if reference is not None and (
                    not isinstance(reference, str)
                    or not reference.startswith("evidence/restricted/")
                ):
                    errors.append(
                        f"invalid_{optional_reference}:{action_id}"
                    )
        return list(dict.fromkeys(errors))

    def _task_path(self, reference: str) -> Path:
        if self.task_dir is None:
            raise ValueError("task directory is required")
        path = (self.task_dir / reference).resolve()
        try:
            path.relative_to(self.task_dir)
        except ValueError as exc:
            raise ValueError("task-relative evidence path is required") from exc
        return path

    def _request_command(
        self,
        parameters: Mapping[str, Any],
        body_path: Path,
        header_path: Path,
    ) -> tuple[list[str], int]:
        timeout = parameters.get("timeout", 30)
        if not isinstance(timeout, int) or not 1 <= timeout <= 300:
            raise ValueError("timeout must be between 1 and 300 seconds")
        command = [
            self.command,
            "--silent",
            "--show-error",
            "--request",
            str(parameters.get("method", "GET")),
            "--max-time",
            str(timeout),
            "--output",
            str(body_path),
            "--dump-header",
            str(header_path),
            "--write-out",
            "%{http_code}\\t%{size_download}\\t%{content_type}",
        ]
        if parameters.get("verify_tls", True) is False:
            command.append("--insecure")
        header_ref = parameters.get("request_header_file_ref")
        if isinstance(header_ref, str):
            command.extend(["--header", f"@{self._task_path(header_ref)}"])
        body_ref = parameters.get("request_body_file_ref")
        if isinstance(body_ref, str):
            command.extend(["--data-binary", f"@{self._task_path(body_ref)}"])
        command.append(str(parameters["url"]))
        return command, timeout

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
        if self.task_dir is None or not self.task_dir.is_dir():
            return AdapterExecutionResult(
                capability_id=self.capability_id,
                ok=False,
                status="rejected",
                error_category="environment",
                error="task directory is unavailable",
            )

        records: list[dict[str, Any]] = []
        for action in plan["actions"]:
            parameters = action["parameters"]
            try:
                body_path = self._task_path(parameters["body_evidence_ref"])
                header_path = self._task_path(parameters["header_evidence_ref"])
                body_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                header_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                command, timeout = self._request_command(
                    parameters,
                    body_path,
                    header_path,
                )
                completed = self.runner(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=timeout + 5,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_timeout",
                    records=records,
                    error_category="provider",
                    error="curl request timed out",
                )
            except (OSError, ValueError, subprocess.SubprocessError):
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_error",
                    records=records,
                    error_category="provider",
                    error="curl request could not be executed",
                )
            if completed.returncode != 0:
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_error",
                    records=records,
                    error_category="provider",
                    error=f"curl returned {completed.returncode}",
                )
            missing_evidence = [
                path.name
                for path in (body_path, header_path)
                if not path.is_file()
            ]
            if missing_evidence:
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_output_rejected",
                    records=records,
                    error_category="provider",
                    error=(
                        "curl did not create required restricted evidence files"
                    ),
                )
            try:
                status_raw, size_raw, content_type = completed.stdout.split(
                    "\t",
                    2,
                )
                status_code = int(status_raw)
                content_length = int(float(size_raw))
            except (TypeError, ValueError):
                return AdapterExecutionResult(
                    capability_id=self.capability_id,
                    ok=False,
                    status="provider_error",
                    records=records,
                    error_category="provider",
                    error="curl returned an invalid metadata summary",
                )
            for evidence_path in (body_path, header_path):
                if evidence_path.exists():
                    evidence_path.chmod(0o600)
            observation = {
                "fact": "http-request-completed",
                "status_code": status_code,
                "content_length": content_length,
                "content_type": content_type or "unknown",
                "response_class": f"{status_code // 100}xx",
            }
            response = {
                "observation": observation,
                "rollback_status": action.get(
                    "rollback_status",
                    "not-required",
                ),
                "hypothesis_outcome": "inconclusive",
            }
            records.append(
                _execution_record(plan, action, response, observation)
            )
        return AdapterExecutionResult(
            capability_id=self.capability_id,
            ok=True,
            status="completed",
            records=records,
        )
