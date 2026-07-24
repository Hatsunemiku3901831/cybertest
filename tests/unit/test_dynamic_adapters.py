from __future__ import annotations

import copy
import io
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tool import run_dynamic_validation
from tool.cybertest_core.adapters import (
    BurpReplayAdapter,
    CLIHttpAdapter,
    JSCDPAdapter,
    OASTCallbackAdapter,
    PacketCaptureAdapter,
    PlaywrightAdapter,
)
from tool.cybertest_core.schema_validation import assert_valid, load_json_document


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SCHEMA = (
    ROOT / "agent" / "schemas" / "evidence-envelope.schema.json"
)
PLAN_SCHEMA = (
    ROOT / "agent" / "schemas" / "dynamic-validation-plan.schema.json"
)


class FakeTransport:
    provider_name = "fake-provider"

    def __init__(
        self,
        *,
        probe_response: dict[str, object] | None = None,
        execute_response: dict[str, object] | None = None,
        exception: BaseException | None = None,
        probe_exception: BaseException | None = None,
        execute_exception: BaseException | None = None,
    ) -> None:
        self.probe_response = probe_response or {
            "reachable": True,
            "healthy": True,
        }
        self.execute_response = execute_response or {
            "observation": {"fact": "synthetic-provider-observation"},
            "hypothesis_outcome": "inconclusive",
        }
        self.probe_exception = probe_exception or exception
        self.execute_exception = execute_exception or exception
        self.probe_calls = 0
        self.execute_calls = 0

    def probe(self, capability_id, context):
        del capability_id, context
        self.probe_calls += 1
        if self.probe_exception:
            raise self.probe_exception
        return self.probe_response

    def execute(self, capability_id, action):
        del capability_id, action
        self.execute_calls += 1
        if self.execute_exception:
            raise self.execute_exception
        return copy.deepcopy(self.execute_response)


def make_plan(
    capability: str,
    operation: str,
    *,
    evidence_id: str = "EV-DYNAMIC-001",
    control_variant: str = "candidate-probe",
) -> dict[str, object]:
    parameters: dict[str, object] = {"synthetic": True}
    evidence_refs = [f"evidence/envelopes/{evidence_id}.json"]
    if capability == "cli.http":
        parameters = {
            "url": "https://example.com/resource",
            "method": "GET",
            "timeout": 10,
            "verify_tls": True,
            "body_evidence_ref": (
                f"evidence/restricted/http/{evidence_id}-body.bin"
            ),
            "header_evidence_ref": (
                f"evidence/restricted/http/{evidence_id}-headers.txt"
            ),
        }
        evidence_refs.extend(
            [
                parameters["body_evidence_ref"],
                parameters["header_evidence_ref"],
            ]
        )
    elif capability == "http.replay":
        parameters = {
            "synthetic": True,
            "method": "GET",
        }
    return {
        "schema_version": "1.0",
        "plan_status": "ready",
        "plan_id": f"DVP-{evidence_id}",
        "candidate_id": "BC-DYNAMIC-001",
        "candidate_file": "outputs/candidates.json",
        "tactic_id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
        "route_decision_id": "RD-DYNAMIC-001",
        "route_status": "matched",
        "provider_capability": capability,
        "capability_state": {
            "installed": True,
            "configured": True,
            "reachable": True,
            "healthy": True,
            "permitted": True,
            "material_ready": True,
            "available": True,
            "health": "ok",
        },
        "material_ready": True,
        "missing_materials": [],
        "policy": {
            "permitted": True,
            "safe_validation_level": "readonly",
        },
        "controlled_test_object": True,
        "actions": [
            {
                "action_id": f"ACTION-{evidence_id}",
                "evidence_id": evidence_id,
                "operation": operation,
                "control_variant": control_variant,
                "request_id": "REQ-DYNAMIC-001",
                "auth_context": "controlled-user-a",
                "browser_context": "controlled-browser-a",
                "parameters": parameters,
                "invariants_checked": ["same-controlled-object"],
                "rollback_status": "not-required",
                "evidence_refs": evidence_refs,
                "state_change": False,
            }
        ],
        "stop_conditions": ["single successful observation"],
        "rollback_plan": {"required": False, "steps": []},
    }


def candidate_document() -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "candidates": [
            {
                "schema_version": "2.0",
                "id": "BC-DYNAMIC-001",
                "asset": "example.com",
                "candidate_type": "authorization",
                "priority_score": 50,
                "evidence_confidence": "weak",
                "reachability_stage": "route",
                "impact_stage": "hypothesis",
                "status": "plan_ready",
                "route_decision_id": "RD-DYNAMIC-001",
                "matched_tactics": [
                    {
                        "id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                        "score": 80,
                    }
                ],
            }
        ],
    }


class DynamicProviderAdapterTests(unittest.TestCase):
    def test_transport_adapters_probe_execute_and_normalize_evidence(self) -> None:
        schema = load_json_document(EVIDENCE_SCHEMA)
        plan_schema = load_json_document(PLAN_SCHEMA)
        cases = (
            (PlaywrightAdapter, "browser.interactive", "navigate"),
            (BurpReplayAdapter, "http.replay", "replay"),
            (JSCDPAdapter, "js.cdp", "observe_runtime"),
            (PacketCaptureAdapter, "http.capture", "capture"),
            (OASTCallbackAdapter, "oast.callback", "observe_callback"),
        )
        for index, (adapter_type, capability, operation) in enumerate(
            cases,
            start=1,
        ):
            with self.subTest(capability=capability):
                transport = FakeTransport()
                adapter = adapter_type(transport)
                probe = adapter.probe(
                    {"permitted": True, "material_ready": True}
                )
                self.assertTrue(probe.available)
                plan = make_plan(
                    capability,
                    operation,
                    evidence_id=f"EV-ADAPTER-{index:03d}",
                )
                assert_valid(plan, plan_schema, f"{capability} plan")
                result = adapter.execute(plan)
                self.assertTrue(result.ok, result)
                envelopes = adapter.normalize_evidence(result)
                self.assertEqual(len(envelopes), 1)
                assert_valid(
                    envelopes[0],
                    schema,
                    envelopes[0]["evidence_id"],
                )
                self.assertEqual(
                    envelopes[0]["candidate_id"],
                    plan["candidate_id"],
                )

    def test_transport_adapters_normalize_probe_failure_and_degradation(
        self,
    ) -> None:
        adapter_types = (
            PlaywrightAdapter,
            BurpReplayAdapter,
            JSCDPAdapter,
            PacketCaptureAdapter,
        )
        for adapter_type in adapter_types:
            with self.subTest(adapter=adapter_type.__name__):
                degraded = adapter_type(
                    FakeTransport(
                        probe_response={
                            "reachable": True,
                            "healthy": False,
                        }
                    )
                ).probe({"permitted": True, "material_ready": True})
                self.assertFalse(degraded.available)
                self.assertEqual(degraded.health, "reachable")

                failed = adapter_type(
                    FakeTransport(exception=RuntimeError("synthetic failure"))
                ).probe({"permitted": True, "material_ready": True})
                self.assertFalse(failed.available)
                self.assertEqual(failed.error_category, "provider")
                self.assertNotIn("synthetic failure", failed.summary)

    def test_provider_timeout_is_not_reported_as_target_absence(self) -> None:
        transport = FakeTransport(exception=TimeoutError())
        adapter = BurpReplayAdapter(transport)
        result = adapter.execute(make_plan("http.replay", "replay"))

        self.assertFalse(result.ok)
        self.assertEqual(result.status, "provider_timeout")
        self.assertEqual(result.error_category, "provider")
        self.assertEqual(result.fallback_capability, "cli.http")
        self.assertNotIn("target", result.error or "")

    def test_sensitive_provider_output_is_rejected_before_portable_evidence(
        self,
    ) -> None:
        adapter = PlaywrightAdapter(
            FakeTransport(
                execute_response={
                    "observation": {
                        "fact": "synthetic",
                        "authorization": "Bearer replayable-value",
                    }
                }
            )
        )
        result = adapter.execute(
            make_plan("browser.interactive", "navigate")
        )
        with self.assertRaisesRegex(ValueError, "restricted evidence"):
            adapter.normalize_evidence(result)

    def test_missing_route_binding_is_rejected_without_provider_call(self) -> None:
        transport = FakeTransport()
        adapter = JSCDPAdapter(transport)
        plan = make_plan("js.cdp", "observe_runtime")
        del plan["route_decision_id"]

        result = adapter.execute(plan)

        self.assertFalse(result.ok)
        self.assertEqual(result.error_category, "plan")
        self.assertEqual(transport.execute_calls, 0)

    def test_cli_http_probe_execution_and_output_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = Path(temporary)
            commands: list[list[str]] = []

            def fake_runner(command, **kwargs):
                del kwargs
                commands.append(command)
                if "--version" in command:
                    return subprocess.CompletedProcess(command, 0, "curl 9", "")
                Path(command[command.index("--output") + 1]).write_bytes(b"")
                Path(
                    command[command.index("--dump-header") + 1]
                ).write_text("HTTP/1.1 204 No Content\r\n\r\n", encoding="utf-8")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "204\t0\tapplication/json",
                    "",
                )

            adapter = CLIHttpAdapter(
                task_dir=task_dir,
                which=lambda _command: "/synthetic/bin/curl",
                runner=fake_runner,
            )
            probe = adapter.probe(
                {"permitted": True, "material_ready": True}
            )
            self.assertTrue(probe.available)
            plan = make_plan("cli.http", "http_request")
            result = adapter.execute(plan)
            self.assertTrue(result.ok, result)
            envelopes = adapter.normalize_evidence(result)

        self.assertEqual(envelopes[0]["observation"]["status_code"], 204)
        serialized = json.dumps(envelopes)
        self.assertNotIn("/synthetic/bin", serialized)
        self.assertFalse(
            any("Authorization:" in argument for argument in commands[-1])
        )

    def test_cli_http_probe_failure_and_timeout_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = Path(temporary)

            def failing_probe(command, **kwargs):
                del kwargs
                return subprocess.CompletedProcess(command, 1, "", "failed")

            degraded = CLIHttpAdapter(
                task_dir=task_dir,
                which=lambda _command: "/synthetic/curl",
                runner=failing_probe,
            ).probe({"permitted": True, "material_ready": True})
            self.assertFalse(degraded.available)
            self.assertEqual(degraded.health, "degraded")

            def timeout_runner(command, **kwargs):
                del kwargs
                raise subprocess.TimeoutExpired(command, 10)

            result = CLIHttpAdapter(
                task_dir=task_dir,
                which=lambda _command: "/synthetic/curl",
                runner=timeout_runner,
            ).execute(make_plan("cli.http", "http_request"))

        self.assertFalse(result.ok)
        self.assertEqual(result.status, "provider_timeout")
        self.assertEqual(result.error_category, "provider")


class DynamicValidationRunnerTests(unittest.TestCase):
    def _task(self, root: Path) -> Path:
        task_dir = root / "task"
        (task_dir / "outputs").mkdir(parents=True)
        (task_dir / "outputs" / "candidates.json").write_text(
            json.dumps(candidate_document()),
            encoding="utf-8",
        )
        return task_dir

    def test_plan_schema_and_plan_only_mode_have_no_side_effects(self) -> None:
        plan = make_plan("browser.interactive", "navigate")
        assert_valid(plan, load_json_document(PLAN_SCHEMA), "dynamic plan")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            before = sorted(path.relative_to(root) for path in root.rglob("*"))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = run_dynamic_validation.main(
                    ["--authorized", "--plan", str(plan_path)]
                )
            after = sorted(path.relative_to(root) for path in root.rglob("*"))

        self.assertEqual(return_code, 0)
        self.assertEqual(before, after)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["mode"], "plan_only")
        self.assertFalse(report["execution_performed"])

    def test_unhealthy_capability_blocks_before_adapter_execution(self) -> None:
        plan = make_plan("browser.interactive", "navigate")
        plan["capability_state"]["available"] = False
        plan["capability_state"]["healthy"] = False
        plan["capability_state"]["health"] = "installed_only"
        transport = FakeTransport()
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, _ = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=PlaywrightAdapter(transport),
            )

        self.assertEqual(report["status"], "blocked_need_capability")
        self.assertFalse(report["execution_performed"])
        self.assertEqual(transport.execute_calls, 0)

    def test_inconsistent_capability_state_is_rejected_before_probe(self) -> None:
        plan = make_plan("browser.interactive", "navigate")
        plan["capability_state"].update(
            {
                "installed": False,
                "configured": False,
                "reachable": False,
                "healthy": True,
                "available": True,
                "health": "ok",
            }
        )
        transport = FakeTransport()
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=PlaywrightAdapter(transport),
            )

        self.assertEqual(report["status"], "invalid_plan")
        self.assertFalse(report["execution_performed"])
        self.assertIsNone(updated)
        self.assertEqual(transport.probe_calls, 0)
        self.assertEqual(transport.execute_calls, 0)

    def test_fresh_probe_failure_blocks_stale_healthy_plan(self) -> None:
        plan = make_plan("browser.interactive", "navigate")
        transport = FakeTransport(
            probe_exception=RuntimeError("synthetic stale provider")
        )
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=PlaywrightAdapter(transport),
            )

        self.assertEqual(report["status"], "blocked_need_capability")
        self.assertFalse(report["execution_performed"])
        self.assertIsNone(updated)
        self.assertEqual(transport.probe_calls, 1)
        self.assertEqual(transport.execute_calls, 0)

    def test_readonly_policy_cannot_hide_delete_as_readonly(self) -> None:
        plan = make_plan("cli.http", "http_request")
        plan["actions"][0]["parameters"]["method"] = "DELETE"
        plan["actions"][0]["state_change"] = False
        calls: list[list[str]] = []

        def forbidden_runner(command, **kwargs):
            del kwargs
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "curl 9", "")

        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=CLIHttpAdapter(
                    task_dir=task_dir,
                    which=lambda _command: "/synthetic/curl",
                    runner=forbidden_runner,
                ),
            )

        self.assertEqual(report["status"], "invalid_plan")
        self.assertFalse(report["execution_performed"])
        self.assertIsNone(updated)
        self.assertEqual(calls, [])

    def test_material_policy_and_rollback_gates_prevent_execution(self) -> None:
        cases = []
        missing_material = make_plan("browser.interactive", "navigate")
        missing_material["material_ready"] = False
        missing_material["missing_materials"] = ["controlled-account"]
        missing_material["capability_state"]["material_ready"] = False
        missing_material["capability_state"]["available"] = False
        cases.append((missing_material, "blocked_need_material"))

        denied = make_plan("browser.interactive", "navigate")
        denied["policy"]["permitted"] = False
        denied["capability_state"]["permitted"] = False
        denied["capability_state"]["available"] = False
        cases.append((denied, "policy_conflict"))

        invalid_rollback = make_plan("browser.interactive", "navigate")
        invalid_rollback["policy"]["safe_validation_level"] = "test_object"
        invalid_rollback["actions"][0]["state_change"] = True
        invalid_rollback["actions"][0]["rollback_status"] = "pending"
        cases.append((invalid_rollback, "invalid_plan"))

        for plan, expected_status in cases:
            with self.subTest(status=expected_status):
                transport = FakeTransport()
                with tempfile.TemporaryDirectory() as temporary:
                    task_dir = self._task(Path(temporary))
                    report, _ = run_dynamic_validation.execute_plan(
                        plan,
                        task_dir=task_dir,
                        adapter=PlaywrightAdapter(transport),
                    )
                self.assertEqual(report["status"], expected_status)
                self.assertEqual(transport.execute_calls, 0)

    def test_execute_mode_without_task_dir_refuses_without_writes(self) -> None:
        plan = make_plan("browser.interactive", "navigate")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            before = sorted(path.relative_to(root) for path in root.rglob("*"))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = run_dynamic_validation.main(
                    [
                        "--authorized",
                        "--plan",
                        str(plan_path),
                        "--execute",
                    ]
                )
            after = sorted(path.relative_to(root) for path in root.rglob("*"))

        self.assertEqual(return_code, 1)
        self.assertEqual(before, after)
        self.assertEqual(
            json.loads(stdout.getvalue())["status"],
            "blocked_need_task_dir",
        )

    def test_provider_failure_does_not_change_candidate_or_claim_absence(
        self,
    ) -> None:
        plan = make_plan("http.replay", "replay")
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            candidate_path = task_dir / "outputs" / "candidates.json"
            before = candidate_path.read_bytes()
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=BurpReplayAdapter(
                    FakeTransport(
                        execute_exception=RuntimeError("provider failed")
                    )
                ),
            )
            after = candidate_path.read_bytes()

        self.assertFalse(report["ok"])
        self.assertEqual(report["error_category"], "provider")
        self.assertNotIn("target", report["error"])
        self.assertIsNone(updated)
        self.assertEqual(before, after)

    def test_partial_timeout_persists_completed_evidence_and_history(
        self,
    ) -> None:
        class PartialThenTimeout(FakeTransport):
            def execute(self, capability_id, action):
                del capability_id, action
                self.execute_calls += 1
                if self.execute_calls == 1:
                    return {
                        "observation": {"fact": "first-action-completed"},
                        "hypothesis_outcome": "inconclusive",
                    }
                raise TimeoutError()

        plan = make_plan(
            "http.replay",
            "replay",
            evidence_id="EV-PARTIAL-001",
        )
        second = copy.deepcopy(plan["actions"][0])
        second["action_id"] = "ACTION-EV-PARTIAL-002"
        second["evidence_id"] = "EV-PARTIAL-002"
        second["evidence_refs"] = [
            "evidence/envelopes/EV-PARTIAL-002.json"
        ]
        plan["actions"].append(second)

        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=BurpReplayAdapter(PartialThenTimeout()),
            )
            envelope_exists = (
                task_dir
                / "evidence"
                / "envelopes"
                / "EV-PARTIAL-001.json"
            ).is_file()
            persisted = json.loads(
                (task_dir / "outputs" / "candidates.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "provider_timeout")
        self.assertTrue(report["partial_execution"])
        self.assertTrue(envelope_exists)
        self.assertEqual(
            report["evidence_refs"],
            ["evidence/envelopes/EV-PARTIAL-001.json"],
        )
        candidate = persisted["candidates"][0]
        self.assertEqual(candidate["status"], "verifying")
        self.assertEqual(
            candidate["dynamic_validation_history"][-1][
                "execution_status"
            ],
            "provider_timeout",
        )
        self.assertEqual(updated, persisted)

    def test_missing_restricted_response_files_rejects_provider_output(
        self,
    ) -> None:
        plan = make_plan("cli.http", "http_request")

        def metadata_without_files(command, **kwargs):
            del kwargs
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, "curl 9", "")
            return subprocess.CompletedProcess(
                command,
                0,
                "204\t0\ttext/plain",
                "",
            )

        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=CLIHttpAdapter(
                    task_dir=task_dir,
                    which=lambda _command: "/synthetic/curl",
                    runner=metadata_without_files,
                ),
            )

        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "provider_output_rejected")
        self.assertIsNone(updated)

    def test_execution_writes_envelope_and_updates_only_bound_candidate(
        self,
    ) -> None:
        plan = make_plan("browser.interactive", "navigate")
        transport = FakeTransport(
            execute_response={
                "observation": {"fact": "single-controlled-impact"},
                "hypothesis_outcome": "supported",
                "stop": True,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=PlaywrightAdapter(transport),
            )
            envelope_path = (
                task_dir / "evidence" / "envelopes" / "EV-DYNAMIC-001.json"
            )
            envelope_exists = envelope_path.is_file()
            persisted = json.loads(
                (task_dir / "outputs" / "candidates.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertTrue(report["ok"], report)
        self.assertTrue(envelope_exists)
        self.assertEqual(report["outcome"], "supported")
        self.assertTrue(report["stopped"])
        candidate = persisted["candidates"][0]
        self.assertEqual(candidate["status"], "observed")
        self.assertEqual(
            candidate["evidence_envelopes"][0]["candidate_id"],
            plan["candidate_id"],
        )
        self.assertEqual(updated, persisted)

    def test_negative_control_rejection_excludes_tactic_and_requests_reroute(
        self,
    ) -> None:
        plan = make_plan(
            "http.replay",
            "replay",
            control_variant="negative-control",
        )
        transport = FakeTransport(
            execute_response={
                "observation": {"fact": "negative-control-matched-probe"},
                "hypothesis_outcome": "rejected",
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            report, updated = run_dynamic_validation.execute_plan(
                plan,
                task_dir=task_dir,
                adapter=BurpReplayAdapter(transport),
            )

        candidate = updated["candidates"][0]
        self.assertEqual(candidate["status"], "false_positive")
        self.assertTrue(report["reroute_required"])
        self.assertIn(plan["tactic_id"], candidate["excluded_routes"])

    def test_browser_replay_and_cli_envelopes_correlate_to_one_candidate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task_dir = self._task(Path(temporary))
            browser_plan = make_plan(
                "browser.interactive",
                "navigate",
                evidence_id="EV-BROWSER-JOINT-001",
            )
            replay_plan = make_plan(
                "http.replay",
                "replay",
                evidence_id="EV-REPLAY-JOINT-001",
            )
            cli_plan = make_plan(
                "cli.http",
                "http_request",
                evidence_id="EV-CLI-JOINT-001",
            )
            run_dynamic_validation.execute_plan(
                browser_plan,
                task_dir=task_dir,
                adapter=PlaywrightAdapter(FakeTransport()),
            )
            run_dynamic_validation.execute_plan(
                replay_plan,
                task_dir=task_dir,
                adapter=BurpReplayAdapter(FakeTransport()),
            )

            def fake_curl(command, **kwargs):
                del kwargs
                if "--version" not in command:
                    Path(command[command.index("--output") + 1]).write_text(
                        "synthetic",
                        encoding="utf-8",
                    )
                    Path(
                        command[command.index("--dump-header") + 1]
                    ).write_text(
                        "HTTP/1.1 200 OK\r\n\r\n",
                        encoding="utf-8",
                    )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "200\t12\ttext/plain",
                    "",
                )

            run_dynamic_validation.execute_plan(
                cli_plan,
                task_dir=task_dir,
                adapter=CLIHttpAdapter(
                    task_dir=task_dir,
                    which=lambda _command: "/synthetic/curl",
                    runner=fake_curl,
                ),
            )
            persisted = json.loads(
                (task_dir / "outputs" / "candidates.json").read_text(
                    encoding="utf-8"
                )
            )

        envelopes = persisted["candidates"][0]["evidence_envelopes"]
        self.assertEqual(len(envelopes), 3)
        self.assertEqual(
            {item["candidate_id"] for item in envelopes},
            {"BC-DYNAMIC-001"},
        )
        self.assertEqual(
            {
                item["observation"]["provider_capability"]
                for item in envelopes
            },
            {"browser.interactive", "http.replay", "cli.http"},
        )

    @unittest.skipUnless(shutil.which("curl"), "curl is not installed")
    def test_cli_http_local_synthetic_end_to_end(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"synthetic-local-response"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *args):
                del args

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            self.skipTest("local loopback bind is not permitted")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            plan = make_plan(
                "cli.http",
                "http_request",
                evidence_id="EV-CLI-LOCAL-001",
            )
            plan["actions"][0]["parameters"]["url"] = (
                f"http://127.0.0.1:{server.server_port}/synthetic"
            )
            with tempfile.TemporaryDirectory() as temporary:
                task_dir = self._task(Path(temporary))
                report, updated = run_dynamic_validation.execute_plan(
                    plan,
                    task_dir=task_dir,
                    adapter=CLIHttpAdapter(task_dir=task_dir),
                )
                body_path = (
                    task_dir
                    / "evidence"
                    / "restricted"
                    / "http"
                    / "EV-CLI-LOCAL-001-body.bin"
                )
                headers_path = (
                    task_dir
                    / "evidence"
                    / "restricted"
                    / "http"
                    / "EV-CLI-LOCAL-001-headers.txt"
                )
                body_exists = body_path.is_file()
                headers_exist = headers_path.is_file()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertTrue(report["ok"], report)
        self.assertTrue(body_exists)
        self.assertTrue(headers_exist)
        self.assertEqual(
            updated["candidates"][0]["evidence_envelopes"][0][
                "observation"
            ]["status_code"],
            200,
        )


if __name__ == "__main__":
    unittest.main()
