from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = REPO_ROOT / "tool"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "candidate"
sys.path.insert(0, str(TOOL_DIR))

import bounty_candidate_queue as queue  # noqa: E402
from cybertest_core import schema_validation  # noqa: E402


class CandidateQueueTest(unittest.TestCase):
    def signals(self, name: str) -> list[queue.RawSignal]:
        return queue.collect_signals([FIXTURE_DIR / name])

    def url_signal(self, name: str) -> queue.RawSignal:
        return next(signal for signal in self.signals(name) if signal.value.startswith("https://"))

    def test_static_2xx_is_hint_not_unauthorized_fact(self) -> None:
        signal = self.url_signal("static_200.json")
        candidate = queue.classify_signal(
            signal,
            "Swagger/OpenAPI/Actuator",
        )
        no_status_candidate = queue.classify_signal(
            queue.RawSignal(
                value=signal.value,
                source=signal.source,
                source_file=signal.source_file,
                record={},
            ),
            "Swagger/OpenAPI/Actuator",
        )

        self.assertTrue(candidate.anonymous_hint)
        self.assertIsNone(candidate.observed_without_auth)
        self.assertFalse(candidate.unauth_reachable)
        self.assertEqual(candidate.score, no_status_candidate.score)
        self.assertNotIn("未认证", " ".join(candidate.score_reasons))

        output = queue.candidate_to_dict(1, candidate)
        self.assertTrue(output["anonymous_hint"])
        self.assertIsNone(output["observed_without_auth"])
        self.assertFalse(output["unauth_reachable"])

    def test_explicit_auth_matrix_can_prove_unauthorized_reachability(self) -> None:
        candidate = queue.classify_signal(
            self.url_signal("explicit_auth_matrix.json"),
            "Swagger/OpenAPI/Actuator",
        )

        self.assertTrue(candidate.anonymous_hint)
        self.assertTrue(candidate.observed_without_auth)
        self.assertTrue(candidate.unauth_reachable)
        self.assertEqual(candidate.evidence_confidence, "differential")
        self.assertIn("明确认证矩阵证明未认证可达", candidate.score_reasons)

    def test_incomplete_auth_matrix_remains_unknown(self) -> None:
        candidate = queue.classify_signal(
            queue.RawSignal(
                value="https://api.example.invalid/admin/records",
                source="httpx",
                source_file="incomplete-auth-matrix.json",
                record={
                    "status_code": 200,
                    "auth_experiment": {
                        "missing_auth": 200,
                    },
                },
            ),
            "Admin/Management",
        )

        self.assertIsNone(candidate.observed_without_auth)
        self.assertFalse(candidate.unauth_reachable)
        self.assertEqual(candidate.evidence_confidence, "weak")

    def test_auth_matrix_is_normalized_before_v2_schema_output(self) -> None:
        candidate = queue.classify_signal(
            queue.RawSignal(
                value="https://api.example.invalid/admin/records",
                source="httpx",
                source_file="synthetic-auth-matrix.json",
                record={
                    "status_code": 200,
                    "auth_experiment": {
                        "missing_auth": 200,
                        "fixed_invalid_auth": 401,
                        "controlled_auth": 200,
                        "raw_authorization": "must-not-enter-reusable-output",
                    },
                },
            ),
            "Admin/Management",
        )
        output = queue.candidate_to_dict(1, candidate, enable_tactics=True)
        schema = schema_validation.load_json_document(
            REPO_ROOT / "agent" / "schemas" / "candidate.schema.json"
        )

        self.assertEqual(
            output["auth_experiment"],
            {
                "missing_auth": "200",
                "fixed_invalid_auth": "401",
                "controlled_auth": "200",
            },
        )
        schema_validation.assert_valid(output, schema, output["id"])

    def test_v2_schema_keeps_non_url_signals_with_explicit_unknown_asset(self) -> None:
        candidate = queue.classify_signal(
            queue.RawSignal(
                value="/admin/users/export",
                source="text",
                source_file="synthetic-routes.txt",
                record={},
            ),
            "Admin/Management",
        )
        output = queue.candidate_to_dict(1, candidate, enable_tactics=True)
        schema = schema_validation.load_json_document(
            REPO_ROOT / "agent" / "schemas" / "candidate.schema.json"
        )

        self.assertEqual(output["asset"], "unknown")
        schema_validation.assert_valid(output, schema, output["id"])

    def test_pipeline_retry_does_not_ingest_its_own_candidate_or_gate_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            upstream = pipeline_dir / "phase_httpx"
            candidate_dir = pipeline_dir / "phase_candidate_queue"
            gate_dir = pipeline_dir / "phase_99_quality_gate"
            upstream.mkdir()
            candidate_dir.mkdir()
            gate_dir.mkdir()
            (upstream / "result.json").write_text("{}", encoding="utf-8")
            (candidate_dir / "result.json").write_text("{}", encoding="utf-8")
            (candidate_dir / "result.md").write_text("# old", encoding="utf-8")
            (gate_dir / "result.json").write_text("{}", encoding="utf-8")
            (pipeline_dir / "pipeline_state.json").write_text("{}", encoding="utf-8")
            args = queue.parse_args(["--pipeline-dir", str(pipeline_dir)])

            inputs = {
                path.relative_to(pipeline_dir).as_posix()
                for path in queue.gather_input_paths(args)
            }

        self.assertEqual(inputs, {"phase_httpx/result.json"})

    def test_stable_key_omits_query_values_and_random_ids(self) -> None:
        candidates = [
            queue.classify_signal(signal, "IDOR/BOLA")
            for signal in self.signals("stable_key_variants.json")
            if signal.value.startswith("https://")
        ]

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].key, candidates[1].key)
        self.assertNotIn("123456", candidates[0].key)
        self.assertNotIn("654321", candidates[0].key)
        self.assertNotIn("synthetic-token-alpha", candidates[0].key)
        self.assertNotIn("synthetic-token-beta", candidates[0].key)
        self.assertEqual(len(queue.merge_candidates(candidates)), 1)

    def test_default_output_keeps_v1_fields_without_v2_schema(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = queue.main(["--input", str(FIXTURE_DIR / "static_200.json")])

        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        self.assertNotIn("schema_version", payload)
        candidate = payload["candidates"][0]
        for field in ("id", "candidate_type", "queue", "score", "unauth_reachable"):
            self.assertIn(field, candidate)
        self.assertNotIn("priority_score", candidate)

    def test_enable_tactics_emits_v2_fields_and_top_three_matches(self) -> None:
        load_tactics = mock.Mock(return_value=[{"id": "TACTIC-ANON-001"}])
        rank_tactics = mock.Mock(
            return_value=[
                {"id": "TACTIC-ANON-001", "score": 90},
                {"id": "TACTIC-ANON-002", "score": 80},
                {"id": "TACTIC-ANON-003", "score": 70},
                {"id": "TACTIC-ANON-004", "score": 60},
            ]
        )
        stdout = io.StringIO()
        with (
            mock.patch.object(
                queue,
                "resolve_tactic_router",
                return_value=(load_tactics, rank_tactics),
            ),
            contextlib.redirect_stdout(stdout),
        ):
            result = queue.main(
                [
                    "--input",
                    str(FIXTURE_DIR / "static_200.json"),
                    "--enable-tactics",
                ]
            )

        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], "2.0")
        candidate = payload["candidates"][0]
        expected_fields = {
            "priority_score",
            "evidence_confidence",
            "reachability_stage",
            "impact_stage",
            "business_object",
            "business_capability",
            "operation_type",
            "trust_boundary",
            "auth_experiment",
            "safe_validation_level",
            "matched_tactics",
            "validation_contract",
            "negative_controls",
            "evidence_invariants",
            "stop_conditions",
            "rollback_plan",
            "root_cause_family",
            "affected_instance_key",
            "reopen_conditions",
            "missing_materials",
            "blocked_reason",
            "recovery_first_action",
            "resume_tactic_id",
            "do_not_overclaim",
        }
        self.assertTrue(expected_fields.issubset(candidate))
        self.assertEqual(candidate["priority_score"], candidate["score"])
        self.assertEqual(len(candidate["matched_tactics"]), 3)
        load_tactics.assert_called_once_with()
        _, kwargs = rank_tactics.call_args
        self.assertEqual(kwargs["top_k"], 3)

    def test_enable_tactics_reports_missing_router(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                queue,
                "resolve_tactic_router",
                side_effect=queue.TacticRoutingUnavailable("router is absent"),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = queue.main(
                [
                    "--input",
                    str(FIXTURE_DIR / "static_200.json"),
                    "--enable-tactics",
                ]
            )

        self.assertEqual(result, 2)
        self.assertIn("Tactic routing unavailable", stderr.getvalue())
        self.assertIn("router is absent", stderr.getvalue())

    def test_actual_v2_candidates_validate_schema_and_match_tactic(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = queue.main(
                [
                    "--input",
                    str(FIXTURE_DIR / "tactic_match.json"),
                    "--enable-tactics",
                ]
            )

        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        schema = schema_validation.load_json_document(
            REPO_ROOT / "agent" / "schemas" / "candidate.schema.json"
        )
        for candidate in payload["candidates"]:
            schema_validation.assert_valid(candidate, schema, candidate["id"])

        self.assertTrue(
            any(candidate["matched_tactics"] for candidate in payload["candidates"])
        )
        admin_candidate = next(
            candidate
            for candidate in payload["candidates"]
            if candidate["candidate_type"] == "Admin/Management"
        )
        self.assertEqual(
            admin_candidate["matched_tactics"][0]["id"],
            "AUTHZ-MASS-ASSIGNMENT-001",
        )
        self.assertNotEqual(
            admin_candidate["matched_tactics"][0]["id"],
            "AUTH-JWT-ACCEPTANCE-MATRIX-001",
        )
        self.assertEqual(
            admin_candidate["negative_controls"],
            [
                item["id"]
                for item in admin_candidate["validation_contract"]["request_matrix"]
                if item["role"] == "negative_control"
            ],
        )
        self.assertEqual(
            admin_candidate["negative_controls"],
            admin_candidate["validation_contract"]["negative_controls"],
        )
        self.assertEqual(
            admin_candidate["validation_contract"]["execution_mode"],
            "capability_fallback",
        )
        self.assertEqual(
            admin_candidate["evidence_invariants"],
            admin_candidate["validation_contract"]["evidence_invariants"],
        )
        self.assertEqual(
            admin_candidate["rollback_plan"]["required"],
            admin_candidate["validation_contract"]["rollback"]["required"],
        )
        self.assertEqual(admin_candidate["status"], "triaged")
        self.assertEqual(admin_candidate["impact_stage"], "hypothesis")
        self.assertEqual(admin_candidate["safe_validation_level"], "test_object")

    def test_generic_admin_update_prefers_route_gap_over_wrong_tactic(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = queue.main(
                [
                    "--input",
                    str(FIXTURE_DIR / "generic_admin_update.json"),
                    "--enable-tactics",
                ]
            )

        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        for candidate in payload["candidates"]:
            with self.subTest(candidate=candidate["candidate_type"]):
                self.assertEqual(candidate["matched_tactics"], [])
                self.assertEqual(candidate["route_status"], "route_gap")
                self.assertEqual(candidate["validation_contract"], {})
                self.assertNotEqual(
                    candidate["status"],
                    "blocked_need_material",
                )

    def test_material_block_records_complete_resume_contract(self) -> None:
        signal = self.url_signal("tactic_match.json")
        record = copy.deepcopy(signal.record)
        record["available_materials"] = ["controlled_test_account"]
        candidate = queue.classify_signal(
            queue.RawSignal(
                value=signal.value,
                source=signal.source,
                source_file=signal.source_file,
                record=record,
            ),
            "Admin/Management",
        )

        queue.attach_tactics([candidate])
        output = queue.candidate_to_dict(1, candidate, enable_tactics=True)
        schema = schema_validation.load_json_document(
            REPO_ROOT / "agent" / "schemas" / "candidate.schema.json"
        )

        self.assertEqual(output["status"], "blocked_need_material")
        self.assertEqual(
            output["missing_materials"],
            ["reversible_test_object"],
        )
        self.assertTrue(output["blocked_reason"])
        self.assertTrue(output["recovery_first_action"])
        self.assertEqual(
            output["resume_tactic_id"],
            "AUTHZ-MASS-ASSIGNMENT-001",
        )
        self.assertTrue(output["reopen_conditions"])
        schema_validation.assert_valid(output, schema, output["id"])


if __name__ == "__main__":
    unittest.main()
