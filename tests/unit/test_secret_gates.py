from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tool import scan_reusable_knowledge_leaks
from tool.cybertest_core.evidence import build_evidence_envelope
from tool.cybertest_core.schema_validation import assert_valid, load_json_document


ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER_FIXTURE = (
    ROOT / "tests" / "fixtures" / "knowledge" / "allowed-placeholders.txt"
)
EVIDENCE_FIXTURE = (
    ROOT / "tests" / "fixtures" / "evidence" / "unified-providers.json"
)
EVIDENCE_SCHEMA = (
    ROOT / "agent" / "schemas" / "evidence-envelope.schema.json"
)
ALLOWLIST = (
    ROOT / "agent" / "policies" / "reusable-knowledge-allowlist.json"
)
ALLOWLIST_SCHEMA = (
    ROOT
    / "agent"
    / "schemas"
    / "reusable-knowledge-allowlist.schema.json"
)


def _secret(suffix: str) -> str:
    return "Qx7Vp2Lm9_Nr4Ks8Yw6Bc3Hd5Fj1Za" + suffix


def _build(observation: dict[str, object]) -> dict[str, object]:
    return build_evidence_envelope(
        provider_capability="http.replay",
        evidence_id="EV-SECRET-GATE-001",
        candidate_id="BC-ANON-SECRET-GATE-001",
        tactic_id="AUTH-JWT-ACCEPTANCE-MATRIX-001",
        control_variant="candidate-probe",
        observation=observation,
        rollback_status="not-required",
        evidence_refs=["evidence/restricted/secret-gate.json"],
        invariants_checked=["same-route"],
    )


class ReusableKnowledgeSecretGateTests(unittest.TestCase):
    def test_repository_allowlist_is_schema_valid_exact_and_fully_used(
        self,
    ) -> None:
        allowlist = load_json_document(ALLOWLIST)
        schema = load_json_document(ALLOWLIST_SCHEMA)
        assert_valid(allowlist, schema, "reusable knowledge allowlist")

        entries = allowlist["entries"]
        entry_ids = {entry["id"] for entry in entries}
        self.assertEqual(len(entry_ids), len(entries))
        for entry in entries:
            with self.subTest(entry=entry["id"]):
                self.assertNotRegex(entry["value"], r"[*?\[\]]")
                self.assertTrue(
                    all(
                        not Path(scope).is_absolute()
                        and ".." not in Path(scope).parts
                        for scope in entry["scope"]
                    )
                )

        report = scan_reusable_knowledge_leaks.scan_paths(
            scan_reusable_knowledge_leaks.DEFAULT_ROOTS,
            fail_severity="medium",
        )
        used_ids = {
            finding["allowlist_id"]
            for finding in report["findings"]
            if finding.get("allowlist_id")
        }
        self.assertEqual(entry_ids, used_ids)
        self.assertEqual(report["active_finding_count"], 0, report)
        self.assertEqual(report["status"], "PASS", report)

    def test_allowlist_is_exact_and_path_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "knowledge.md"
            target.write_text(
                "reviewed.vendor.dev\nother.reviewed.vendor.dev\n",
                encoding="utf-8",
            )
            allowlist = root / "allowlist.json"
            allowlist.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "entries": [
                            {
                                "id": "ALLOW-EXACT-SCOPE-001",
                                "match_type": "exact_domain",
                                "value": "reviewed.vendor.dev",
                                "scope": ["knowledge.md"],
                                "reason": "Synthetic exact-scope unit test entry.",
                                "source": "unit test fixture",
                                "reviewed_at": "2026-07-24",
                                "expires_at": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = scan_reusable_knowledge_leaks.scan_paths(
                [target],
                repo_root=root,
                fail_severity="medium",
                allowlist_path=allowlist,
            )

        self.assertEqual(report["suppressed_finding_count"], 1, report)
        self.assertEqual(report["blocking_finding_count"], 1, report)
        self.assertEqual(
            {
                finding["disposition"]
                for finding in report["findings"]
            },
            {"blocking", "suppressed"},
        )

    def test_fail_severity_changes_status_but_exit_requires_explicit_flag(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "unreviewed.md"
            target.write_text("https://unreviewed-reference.dev/path\n", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status_only = scan_reusable_knowledge_leaks.main(
                    [
                        str(target),
                        "--dry-run",
                        "--fail-severity",
                        "medium",
                    ]
                )
            report = json.loads(stdout.getvalue())

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                fail_closed = scan_reusable_knowledge_leaks.main(
                    [
                        str(target),
                        "--dry-run",
                        "--fail-severity",
                        "medium",
                        "--fail-on-findings",
                    ]
                )

        self.assertEqual(status_only, 0)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["blocking_finding_count"], 1)
        self.assertEqual(fail_closed, 1)

    def test_cli_tool_error_returns_two(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = scan_reusable_knowledge_leaks.main(
                ["missing-synthetic-scan-target"]
            )

        self.assertEqual(return_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(json.loads(stderr.getvalue())["ok"])

    def test_quoted_json_yaml_sensitive_keys_are_detected_without_echo(self) -> None:
        assignments = [
            ('"access_token": "', _secret("A"), '"'),
            ("'client_secret': '", _secret("B"), "'"),
            ('"apiKey": "', _secret("C"), '"'),
            ("password: '", _secret("D"), "'"),
            ('"credential": "', _secret("E"), '"'),
            ('"authorization": "Bearer ', _secret("F"), '"'),
            ('"authorization_header": "Basic ', _secret("G"), '"'),
            ('"app-secret": "', _secret("H"), '"'),
            ('"token": "', "Qx7Contest9_Nr4Ks8Yw6Bc3Hd5Fj1Za", '"'),
        ]
        raw_values = [prefix + value + suffix for prefix, value, suffix in assignments]
        report = scan_reusable_knowledge_leaks.scan_text(
            "\n".join(raw_values),
            path="synthetic-secrets.yaml",
        )

        secret_findings = [
            finding
            for finding in report
            if finding["kind"] == "high_confidence_token"
        ]
        self.assertEqual(len(secret_findings), len(assignments), report)
        serialized = json.dumps(report)
        for _, value, _ in assignments:
            self.assertNotIn(value, serialized)

    def test_placeholder_assignments_and_existing_fixture_are_allowed(self) -> None:
        placeholders = "\n".join(
            [
                '"access_token": "{REDACTED_ACCESS_TOKEN_VALUE}"',
                "'client_secret': 'placeholder-client-secret-value'",
                "api_key: ${API_KEY_PLACEHOLDER_VALUE}",
                'authorization: "Bearer {REDACTED_CREDENTIAL}"',
            ]
        )
        findings = scan_reusable_knowledge_leaks.scan_text(placeholders)
        self.assertFalse(
            any(
                finding["kind"] == "high_confidence_token"
                for finding in findings
            ),
            findings,
        )

        fixture_report = scan_reusable_knowledge_leaks.scan_paths(
            [PLACEHOLDER_FIXTURE],
            repo_root=ROOT,
        )
        self.assertEqual(fixture_report["status"], "PASS", fixture_report)


class EvidenceSecretGateTests(unittest.TestCase):
    def test_nested_sensitive_key_variants_are_rejected_without_echo(self) -> None:
        sensitive_keys = (
            "accessToken",
            "client-secret",
            "credential_value",
            "authorizationHeader",
            "app_secret",
            "APIKey",
            "passwordDigest",
            "session_token",
            "rawPayload",
        )
        for index, key in enumerate(sensitive_keys):
            secret = _secret(str(index))
            with self.subTest(key=key):
                with self.assertRaises(ValueError) as raised:
                    _build(
                        {
                            "fact": "controlled-observation",
                            "nested": [{"deeper": {key: secret}}],
                        }
                    )
                message = str(raised.exception)
                self.assertIn("restricted evidence", message)
                self.assertNotIn(secret, message)

    def test_safe_token_type_metadata_is_narrowly_allowed(self) -> None:
        envelope = _build(
            {
                "fact": "controlled-observation",
                "token_type": "opaque",
                "placeholder_fact": "Bearer {REDACTED_TOKEN}",
            }
        )
        self.assertEqual(envelope["observation"]["token_type"], "opaque")

        secret = _secret("metadata")
        with self.assertRaises(ValueError) as raised:
            _build({"fact": "controlled-observation", "token_type": secret})
        self.assertIn("controlled metadata descriptor", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_replayable_secret_in_generic_value_is_rejected_without_echo(
        self,
    ) -> None:
        replayable_values = (
            "Bearer Qx7Vp2Lm",
            "Basic " + _secret("basic"),
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            (
                "eyJ" + "headerValue12"
                + "."
                + "eyJ" + "payloadValue12"
                + "."
                + "SignatureValue123"
            ),
        )
        for replayable in replayable_values:
            with self.subTest(kind=replayable.split(" ", 1)[0]):
                with self.assertRaises(ValueError) as raised:
                    _build({"fact": replayable})
                self.assertIn("evidence reference", str(raised.exception))
                self.assertNotIn(replayable, str(raised.exception))

    def test_existing_provider_fixture_remains_schema_valid(self) -> None:
        fixture = load_json_document(EVIDENCE_FIXTURE)
        schema = load_json_document(EVIDENCE_SCHEMA)
        for envelope in fixture["envelopes"]:
            with self.subTest(evidence_id=envelope["evidence_id"]):
                assert_valid(envelope, schema, envelope["evidence_id"])


if __name__ == "__main__":
    unittest.main()
