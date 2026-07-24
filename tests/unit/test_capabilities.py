from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tool import detect_capabilities
from tool.cybertest_core.evidence import build_evidence_envelope
from tool.cybertest_core.schema_validation import assert_valid, load_json_document


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "agent" / "capabilities" / "manifest.yaml"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "capabilities"
EVIDENCE_FIXTURE = (
    REPO_ROOT / "tests" / "fixtures" / "evidence" / "unified-providers.json"
)
EVIDENCE_SCHEMA = (
    REPO_ROOT / "agent" / "schemas" / "evidence-envelope.schema.json"
)
CAPABILITY_REPORT_SCHEMA = (
    REPO_ROOT / "agent" / "schemas" / "capability-report.schema.json"
)
CHECKED_AT = "2026-07-24T00:00:00Z"


class CapabilityManifestTests(unittest.TestCase):
    def test_manifest_is_json_compatible_and_complete(self) -> None:
        manifest = detect_capabilities.load_manifest(MANIFEST)
        self.assertEqual(manifest["schema_version"], "2.0")
        capabilities = manifest["capabilities"]
        ids = {item["id"] for item in capabilities}

        self.assertEqual(
            ids,
            {
                "browser.interactive",
                "http.replay",
                "js.cdp",
                "http.capture",
                "oast.callback",
                "cli.http",
            },
        )
        for item in capabilities:
            self.assertTrue(item["provides"])
            self.assertIsInstance(item["fallbacks"], list)
            self.assertTrue(item["availability_requires"])

    def test_runtime_input_precedes_path_and_supports_aliases(self) -> None:
        report = detect_capabilities.build_report(
            MANIFEST,
            FIXTURES / "runtime-input.json",
            environ={},
            which=lambda _command: "/opt/example/bin/tool",
            checked_at=CHECKED_AT,
        )
        by_id = {item["capability"]: item for item in report["capabilities"]}

        self.assertTrue(by_id["browser.interactive"]["available"])
        self.assertEqual(by_id["browser.interactive"]["source"], "input")
        self.assertEqual(
            by_id["browser.interactive"]["source_compatibility"],
            "v1",
        )
        self.assertFalse(by_id["http.replay"]["available"])
        self.assertEqual(by_id["http.replay"]["source"], "input")
        self.assertTrue(by_id["oast.callback"]["available"])
        self.assertEqual(by_id["oast.callback"]["provider"], "interactsh-client")
        self.assertEqual(by_id["oast.callback"]["health"], "degraded")

    def test_path_detection_never_emits_resolved_absolute_path(self) -> None:
        report = detect_capabilities.build_report(
            MANIFEST,
            environ={},
            which=lambda command: f"/opt/example/bin/{command}" if command == "curl" else None,
            checked_at=CHECKED_AT,
        )
        cli_http = next(
            item
            for item in report["capabilities"]
            if item["capability"] == "cli.http"
        )

        self.assertEqual(cli_http["provider"], "curl")
        self.assertEqual(cli_http["path"], "curl")
        self.assertTrue(cli_http["installed"])
        self.assertFalse(cli_http["healthy"])
        self.assertFalse(cli_http["available"])
        self.assertEqual(cli_http["health"], "installed_only")
        serialized = json.dumps(report)
        self.assertNotIn("/opt/example", serialized)

    def test_environment_value_is_reduced_to_safe_provider_name(self) -> None:
        report = detect_capabilities.build_report(
            MANIFEST,
            environ={"CYBERTEST_JS_CDP_PROVIDER": "/opt/example/bin/js-provider"},
            which=lambda _command: None,
            checked_at=CHECKED_AT,
        )
        js_cdp = next(
            item
            for item in report["capabilities"]
            if item["capability"] == "js.cdp"
        )

        self.assertTrue(js_cdp["installed"])
        self.assertTrue(js_cdp["configured"])
        self.assertFalse(js_cdp["reachable"])
        self.assertFalse(js_cdp["healthy"])
        self.assertFalse(js_cdp["available"])
        self.assertEqual(js_cdp["health"], "configured")
        self.assertEqual(js_cdp["provider"], "js-provider")
        self.assertIsNone(js_cdp["path"])
        self.assertNotIn("/opt/example", json.dumps(report))

    def test_invalid_optional_input_is_rejected(self) -> None:
        with self.assertRaises(detect_capabilities.CapabilityError):
            detect_capabilities.build_report(
                MANIFEST,
                FIXTURES / "invalid-input.json",
                environ={},
                which=lambda _command: None,
                checked_at=CHECKED_AT,
            )

    def test_v2_runtime_state_is_derived_and_schema_valid(self) -> None:
        report = detect_capabilities.build_report(
            MANIFEST,
            FIXTURES / "runtime-input-v2.json",
            environ={},
            which=lambda _command: None,
            checked_at=CHECKED_AT,
        )
        schema = load_json_document(CAPABILITY_REPORT_SCHEMA)
        assert_valid(report, schema, "capability report")
        by_id = {item["capability"]: item for item in report["capabilities"]}

        self.assertTrue(by_id["browser.interactive"]["available"])
        self.assertEqual(
            by_id["browser.interactive"]["source_compatibility"],
            "v2",
        )
        self.assertFalse(by_id["http.replay"]["available"])
        self.assertEqual(by_id["http.replay"]["health"], "degraded")
        self.assertTrue(by_id["cli.http"]["available"])
        self.assertEqual(report["schema_version"], "2.0")

    def test_same_detection_inputs_are_stable_except_generated_time(self) -> None:
        first = detect_capabilities.build_report(
            MANIFEST,
            FIXTURES / "runtime-input-v2.json",
            environ={},
            which=lambda _command: None,
            checked_at=CHECKED_AT,
        )
        second = detect_capabilities.build_report(
            MANIFEST,
            FIXTURES / "runtime-input-v2.json",
            environ={},
            which=lambda _command: None,
            checked_at=CHECKED_AT,
        )

        self.assertEqual(first, second)

    def test_v2_available_cannot_override_unhealthy_state(self) -> None:
        record = {
            "browser.interactive": {
                "installed": True,
                "configured": True,
                "reachable": False,
                "healthy": False,
                "permitted": True,
                "material_ready": True,
                "available": True,
                "health": "degraded",
            }
        }
        with self.assertRaisesRegex(
            detect_capabilities.CapabilityError,
            "derived capability state",
        ):
            detect_capabilities.detect_one(
                detect_capabilities.load_manifest(MANIFEST)["capabilities"][0],
                record,
                {},
                lambda _command: None,
                CHECKED_AT,
            )

    def test_v2_runtime_state_rejects_impossible_health_chain(self) -> None:
        record = {
            "browser.interactive": {
                "installed": True,
                "configured": True,
                "reachable": False,
                "healthy": True,
                "permitted": True,
                "material_ready": True,
                "available": False,
                "health": "ok",
            }
        }
        with self.assertRaisesRegex(
            detect_capabilities.CapabilityError,
            "requires reachable=true",
        ):
            detect_capabilities.detect_one(
                detect_capabilities.load_manifest(MANIFEST)["capabilities"][0],
                record,
                {},
                lambda _command: None,
                CHECKED_AT,
            )

    def test_dynamic_providers_share_one_schema_valid_evidence_experiment(self) -> None:
        manifest = detect_capabilities.load_manifest(MANIFEST)
        capability_ids = {
            item["id"]
            for item in manifest["capabilities"]
        }
        fixture = load_json_document(EVIDENCE_FIXTURE)
        schema = load_json_document(EVIDENCE_SCHEMA)
        envelopes = fixture["envelopes"]

        for envelope in envelopes:
            with self.subTest(evidence=envelope["evidence_id"]):
                assert_valid(envelope, schema, envelope["evidence_id"])
                self.assertEqual(
                    envelope["candidate_id"],
                    fixture["candidate_id"],
                )
                self.assertIn(
                    envelope["request_id"],
                    {"self", "cross", "invalid"},
                )
                self.assertIn(
                    envelope["observation"]["provider_capability"],
                    capability_ids,
                )

        self.assertEqual(
            {
                envelope["observation"]["provider_capability"]
                for envelope in envelopes
            },
            {
                "browser.interactive",
                "http.replay",
                "js.cdp",
                "http.capture",
                "cli.http",
            },
        )

    def test_provider_adapter_builds_correlated_schema_valid_envelopes(self) -> None:
        schema = load_json_document(EVIDENCE_SCHEMA)
        providers = (
            "browser.interactive",
            "http.replay",
            "js.cdp",
            "http.capture",
            "oast.callback",
            "cli.http",
        )
        envelopes = [
            build_evidence_envelope(
                provider_capability=provider,
                evidence_id=f"EV-ADAPTER-{index:03d}",
                candidate_id="BC-ANON-ADAPTER-001",
                tactic_id="INTEGRATION-BLIND-SSRF-MEDIA-001",
                request_id="REQ-ANON-ADAPTER-001",
                auth_context="controlled-user-a",
                control_variant=(
                    "negative-control" if provider == "cli.http"
                    else "candidate-probe"
                ),
                observation={"fact": f"synthetic-{index}"},
                rollback_status="not-required",
                evidence_refs=[
                    f"evidence/envelopes/EV-ADAPTER-{index:03d}.json"
                ],
                invariants_checked=["same-request-id"],
            )
            for index, provider in enumerate(providers, start=1)
        ]

        for envelope in envelopes:
            assert_valid(envelope, schema, envelope["evidence_id"])
            self.assertEqual(
                envelope["request_id"],
                "REQ-ANON-ADAPTER-001",
            )
        self.assertEqual(
            {
                envelope["observation"]["provider_capability"]
                for envelope in envelopes
            },
            set(providers),
        )

    def test_provider_adapter_rejects_absolute_evidence_reference(self) -> None:
        with self.assertRaisesRegex(ValueError, "task-relative"):
            build_evidence_envelope(
                provider_capability="cli.http",
                evidence_id="EV-ADAPTER-INVALID-001",
                candidate_id="BC-ANON-ADAPTER-001",
                tactic_id="AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                control_variant="negative-control",
                observation={"fact": "synthetic"},
                rollback_status="not-required",
                evidence_refs=["/tmp/raw-response.json"],
                invariants_checked=["same-route"],
            )

    def test_provider_adapter_rejects_replayable_material_in_envelope(self) -> None:
        with self.assertRaisesRegex(ValueError, "restricted evidence"):
            build_evidence_envelope(
                provider_capability="http.replay",
                evidence_id="EV-ADAPTER-INVALID-002",
                candidate_id="BC-ANON-ADAPTER-001",
                tactic_id="AUTH-JWT-ACCEPTANCE-MATRIX-001",
                control_variant="candidate-probe",
                observation={
                    "authorization": "Bearer synthetic-but-replayable-value"
                },
                rollback_status="not-required",
                evidence_refs=["evidence/restricted/request.json"],
                invariants_checked=["same-route"],
            )


class CapabilityCliTests(unittest.TestCase):
    def test_default_mode_prints_without_writing_cache(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            return_code = detect_capabilities.main(
                ["--manifest", str(MANIFEST), "--dry-run"],
            )

        self.assertEqual(return_code, 0)
        report = json.loads(stdout.getvalue())
        self.assertTrue(report["dry_run"])
        self.assertNotIn("would_write", report)

    def test_dry_run_with_output_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "capabilities.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = detect_capabilities.main(
                    [
                        "--manifest",
                        str(MANIFEST),
                        "--input",
                        str(FIXTURES / "runtime-input.json"),
                        "--output",
                        str(output),
                        "--dry-run",
                    ],
                )

            self.assertEqual(return_code, 0)
            self.assertFalse(output.exists())
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["would_write"], "capabilities.json")

    def test_explicit_output_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "capabilities.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = detect_capabilities.main(
                    [
                        "--manifest",
                        str(MANIFEST),
                        "--input",
                        str(FIXTURES / "runtime-input.json"),
                        "--output",
                        str(output),
                    ],
                )

            self.assertEqual(return_code, 0)
            self.assertTrue(output.is_file())
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(written["schema_version"], "2.0")
            self.assertNotIn(str(Path(tmpdir).resolve()), json.dumps(written))

    def test_cli_reports_invalid_input_without_path_leak(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = detect_capabilities.main(
                [
                    "--manifest",
                    str(MANIFEST),
                    "--input",
                    str(FIXTURES / "invalid-input.json"),
                ],
            )

        self.assertEqual(return_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        error = json.loads(stderr.getvalue())
        self.assertFalse(error["ok"])
        self.assertNotIn(str(FIXTURES.resolve()), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
