from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = REPO_ROOT / "tool"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "quality_gate"
EVIDENCE_FIXTURE = (
    REPO_ROOT / "tests" / "fixtures" / "evidence" / "unified-providers.json"
)
sys.path.insert(0, str(TOOL_DIR))

import quality_gate as gate  # noqa: E402
from cybertest_core.schema_validation import (  # noqa: E402
    assert_valid,
    load_json_document,
)


class QualityGateTest(unittest.TestCase):
    def fixture(self, name: str) -> dict:
        return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))

    def evaluate(self, name: str) -> dict[str, list[dict]]:
        bundle = self.fixture(name)
        required = gate.MODE_REQUIREMENTS[bundle["state"]["mode"]]
        return gate.evaluate_semantics(
            bundle["state"],
            bundle["documents"],
            required,
        )

    def test_healthy_baseline_passes_semantic_checks(self) -> None:
        semantics = self.evaluate("healthy_baseline.json")
        self.assertTrue(semantics["semantic_checks"])
        self.assertTrue(
            all(item["status"] == "PASS" for item in semantics["semantic_checks"])
        )

    def test_empty_ok_required_outputs_block_complete_coverage(self) -> None:
        semantics = self.evaluate("empty_ok.json")
        failed = {
            item["id"]
            for item in semantics["coverage"]
            if item["status"] == "FAIL"
        }
        self.assertIn("coverage.output.dnsx", failed)
        self.assertIn("coverage.output.httpx", failed)

    def test_spa_fallback_and_duplicate_body_hash_are_blocking_noise(self) -> None:
        semantics = self.evaluate("spa_fallback.json")
        failed = {
            item["id"]
            for item in semantics["noise"]
            if item["status"] == "FAIL"
        }
        self.assertIn("noise.http.spa_fallback", failed)
        self.assertIn("noise.http.body_hash", failed)

    def test_missing_semantic_fields_warn_without_unconditional_failure(self) -> None:
        state = {
            "domain": "example.invalid",
            "phase_outputs": {
                "dnsx": {"ok": True},
                "httpx": {"ok": True},
            },
        }
        semantics = gate.evaluate_semantics(
            state,
            {"dnsx": {}, "httpx": {}, "candidate_queue": None},
            ["dnsx", "httpx"],
        )
        statuses = {item["status"] for item in semantics["semantic_checks"]}
        self.assertIn("WARN", statuses)
        self.assertNotIn("FAIL", statuses)

    def test_fake_ip_without_external_recheck_fails(self) -> None:
        checks = gate.fake_ip_checks(
            {
                "results": [
                    {
                        "host": "example.invalid",
                        "codex_dns_flags": {"fake_ip": True},
                    }
                ]
            }
        )
        self.assertEqual(checks[0]["status"], "FAIL")

    def test_nmap_explicit_all_open_fails(self) -> None:
        checks = gate.nmap_noise_checks(
            {
                "nmap": {
                    "hosts": [
                        {
                            "all_open": True,
                            "ports": [{"service": {"name": "tcpwrapped"}}],
                        }
                    ]
                }
            }
        )
        self.assertEqual(checks[0]["status"], "FAIL")

    def test_candidate_closure_detects_missing_contracts_and_reopen_state(self) -> None:
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": "BC-ANON-001",
                        "schema_version": "2.0",
                        "queue": "P0",
                        "status": "confirmed",
                        "automatic_rating": "high",
                    },
                    {
                        "id": "BC-ANON-002",
                        "status": "blocked_need_material",
                    },
                ]
            }
        )
        by_id = {item["id"]: item["status"] for item in checks}
        self.assertEqual(
            by_id["candidate_closure.confirmed.BC-ANON-001"],
            "FAIL",
        )
        self.assertEqual(
            by_id["candidate_closure.rating.BC-ANON-001"],
            "FAIL",
        )
        self.assertEqual(
            by_id["candidate_closure.tactic.BC-ANON-001"],
            "FAIL",
        )
        self.assertEqual(
            by_id["candidate_closure.reopen.BC-ANON-002"],
            "FAIL",
        )

    def test_v2_p0_discovered_and_route_gap_do_not_pass_closure(self) -> None:
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": "BC-ANON-003",
                        "schema_version": "2.0",
                        "queue": "P0",
                        "status": "discovered",
                        "matched_tactics": [],
                    }
                ]
            }
        )
        by_id = {item["id"]: item["status"] for item in checks}
        self.assertEqual(
            by_id["candidate_closure.p0_triage.BC-ANON-003"],
            "FAIL",
        )
        self.assertEqual(
            by_id["candidate_closure.tactic.BC-ANON-003"],
            "WARN",
        )
        self.assertEqual(
            by_id["candidate_closure.route_status.BC-ANON-003"],
            "FAIL",
        )

    def test_v2_route_gap_is_explicit_but_still_needs_tactic_resolution(self) -> None:
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": "BC-ANON-ROUTE-GAP",
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "triaged",
                        "matched_tactics": [],
                        "route_status": "route_gap",
                    }
                ]
            }
        )
        by_id = {item["id"]: item["status"] for item in checks}
        self.assertNotIn(
            "candidate_closure.route_status.BC-ANON-ROUTE-GAP",
            by_id,
        )
        self.assertEqual(
            by_id["candidate_closure.tactic.BC-ANON-ROUTE-GAP"],
            "WARN",
        )

    def test_complete_blocked_candidate_preserves_resume_contract(self) -> None:
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": "BC-ANON-BLOCKED",
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "blocked_need_material",
                        "route_status": "blocked_need_material",
                        "matched_tactics": [],
                        "missing_materials": ["controlled_account"],
                        "blocked_reason": "No controlled identity is available for a differential request.",
                        "recovery_first_action": "Replay the fixed three-way authorization matrix.",
                        "resume_tactic_id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                        "reopen_conditions": ["A controlled account becomes available."],
                    }
                ]
            }
        )
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["id"], "candidate_closure.complete")
        self.assertEqual(checks[0]["status"], "PASS")

    def test_attack_surface_uses_explicit_coverage_and_observed_urls(self) -> None:
        checks = gate.evaluate_attack_surface(
            {
                "attack_surface": {
                    "coverage": {
                        "js_chunks": {"checked": False},
                        "source_maps": {"checked": True},
                    }
                },
                "katana": {
                    "results": [
                        {
                            "request_url": "https://api.example.invalid/swagger/openapi.json"
                        }
                    ]
                },
            }
        )
        by_id = {item["id"]: item["status"] for item in checks}
        self.assertEqual(by_id["attack_surface.js_chunks"], "FAIL")
        self.assertEqual(by_id["attack_surface.source_maps"], "PASS")
        self.assertEqual(by_id["attack_surface.api_base"], "PASS")
        self.assertEqual(by_id["attack_surface.api_docs"], "PASS")
        self.assertEqual(by_id["attack_surface.history_urls"], "WARN")

    def test_report_consistency_accepts_separated_and_matching_data(self) -> None:
        review = {"conclusion": "medium after evidence review"}
        boundary = "Do not claim access beyond the single controlled object."
        checks = gate.evaluate_report_consistency(
            {
                "vulnerability_archive": {
                    "totals": {"total": 1},
                    "vulnerabilities": [
                        {
                            "id": "V-ANON-001",
                            "severity": "medium",
                            "rating_review": review,
                            "do_not_overclaim": boundary,
                        }
                    ],
                },
                "report": {
                    "entity_counts": {
                        "server_declared_total": 50,
                        "sample_rows": 10,
                        "unique_entities": 8,
                    },
                    "vulnerabilities": [
                        {
                            "id": "V-ANON-001",
                            "severity": "medium",
                            "rating_review": review,
                            "do_not_overclaim": boundary,
                        }
                    ],
                },
            }
        )
        self.assertTrue(all(item["status"] == "PASS" for item in checks))

    def test_archive_fixture_is_schema_valid_and_totals_consistent(self) -> None:
        fixture = self.fixture("vulnerability_archive_consistent.json")
        schema = load_json_document(
            REPO_ROOT / "agent" / "schemas" / "vulnerability.schema.json"
        )
        for container_name in ("vulnerability_archive", "report"):
            for entry in fixture[container_name]["vulnerabilities"]:
                assert_valid(entry, schema, entry["id"])

        checks = gate.evaluate_report_consistency(fixture)

        self.assertTrue(all(item["status"] == "PASS" for item in checks))

    def test_report_consistency_rejects_count_review_and_boundary_conflicts(self) -> None:
        checks = gate.evaluate_report_consistency(
            {
                "vulnerability_archive": {
                    "totals": {"total": 2},
                    "vulnerabilities": [
                        {
                            "id": "V-ANON-002",
                            "severity": "high",
                            "rating_review": {"conclusion": "high"},
                            "do_not_overclaim": "Only one controlled record was observed.",
                        }
                    ],
                },
                "report": {
                    "entity_counts": {
                        "server_declared_total": 2,
                        "sample_rows": 3,
                        "unique_entities": 4,
                    },
                    "vulnerabilities": [
                        {
                            "id": "V-ANON-002",
                            "severity": "high",
                            "rating_review": {"conclusion": "critical"},
                            "do_not_overclaim": "All records are affected.",
                        }
                    ],
                },
            }
        )
        by_id = {item["id"]: item["status"] for item in checks}
        self.assertEqual(by_id["report_consistency.entity_counts"], "FAIL")
        self.assertEqual(by_id["report_consistency.archive_totals"], "FAIL")
        self.assertEqual(by_id["report_consistency.rating_review"], "FAIL")
        self.assertEqual(by_id["report_consistency.do_not_overclaim"], "FAIL")

    def test_report_consistency_without_applicable_documents_warns(self) -> None:
        checks = gate.evaluate_report_consistency({})
        self.assertTrue(all(item["status"] == "WARN" for item in checks))

    def test_confirmed_plan_without_executed_envelopes_is_rejected(self) -> None:
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": "BC-ANON-PLAN-ONLY",
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "confirmed",
                        "safe_validation_level": "readonly",
                        "matched_tactics": [
                            {
                                "id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                                "score": 90,
                            }
                        ],
                        "validation_contract": {
                            "request_matrix": [
                                {"id": "self", "role": "baseline"},
                                {"id": "invalid", "role": "negative_control"},
                                {"id": "cross", "role": "candidate_probe"},
                            ]
                        },
                        "negative_controls": ["fixed-invalid-object"],
                        "evidence_invariants": ["same-method-route-and-session"],
                        "stop_conditions": ["first-bounded-impact"],
                    }
                ]
            }
        )

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "FAIL")
        self.assertIn("evidence_envelopes", checks[0]["message"])

    def test_confirmed_candidate_requires_and_accepts_executed_envelopes(self) -> None:
        evidence = json.loads(EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": evidence["candidate_id"],
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "confirmed",
                        "safe_validation_level": "readonly",
                        "matched_tactics": [
                            {
                                "id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                                "score": 90,
                            }
                        ],
                        "validation_contract": {
                            "request_matrix": [
                                {"id": "self", "role": "baseline"},
                                {"id": "invalid", "role": "negative_control"},
                                {"id": "cross", "role": "candidate_probe"},
                            ]
                        },
                        "negative_controls": ["synthetic-nonexistent-object"],
                        "evidence_invariants": [
                            "same-method-route-and-session",
                        ],
                        "stop_conditions": ["first-bounded-impact"],
                        "evidence_envelopes": evidence["envelopes"],
                    }
                ]
            }
        )

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "PASS")
        self.assertEqual(checks[0]["id"], "candidate_closure.complete")

    def test_confirmed_candidate_rejects_three_empty_observations(self) -> None:
        evidence = json.loads(EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        selected = [
            evidence["envelopes"][0],
            evidence["envelopes"][1],
            evidence["envelopes"][4],
        ]
        for envelope in selected:
            envelope["observation"] = {}

        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": evidence["candidate_id"],
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "confirmed",
                        "safe_validation_level": "readonly",
                        "matched_tactics": [
                            {
                                "id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                                "score": 90,
                            }
                        ],
                        "validation_contract": {
                            "request_matrix": [
                                {"id": "self", "role": "baseline"},
                                {"id": "invalid", "role": "negative_control"},
                                {"id": "cross", "role": "candidate_probe"},
                            ]
                        },
                        "negative_controls": ["invalid"],
                        "evidence_invariants": [
                            "same-method-route-and-session",
                        ],
                        "stop_conditions": ["first-bounded-impact"],
                        "evidence_envelopes": selected,
                    }
                ]
            }
        )

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "FAIL")
        self.assertIn("evidence_envelopes[0].schema", checks[0]["message"])
        self.assertIn("evidence_envelopes[1].schema", checks[0]["message"])
        self.assertIn("evidence_envelopes[2].schema", checks[0]["message"])

    def test_confirmed_candidate_rejects_unbound_and_reused_evidence(self) -> None:
        evidence = json.loads(EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        envelopes = [
            evidence["envelopes"][0],
            evidence["envelopes"][1],
            evidence["envelopes"][4],
        ]
        envelopes[1]["request_id"] = "not-in-request-matrix"
        envelopes[1]["observation"].pop("matrix_request_id", None)
        envelopes[2]["evidence_refs"] = envelopes[0]["evidence_refs"]

        gaps = gate.confirmed_evidence_gaps(
            {
                "matched_tactics": [
                    {"id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001", "score": 90}
                ],
                "validation_contract": {
                    "request_matrix": [
                        {"id": "self", "role": "baseline"},
                        {"id": "invalid", "role": "negative_control"},
                        {"id": "cross", "role": "candidate_probe"},
                    ]
                },
                "evidence_invariants": ["same-method-route-and-session"],
                "evidence_envelopes": envelopes,
                "safe_validation_level": "readonly",
            },
            evidence["candidate_id"],
        )

        self.assertIn("evidence_envelopes[1].matrix_binding", gaps)
        self.assertIn(
            "evidence_envelopes.cross_role_evidence_ref_reuse",
            gaps,
        )
        self.assertIn("executed_candidate_probe", gaps)

    def test_confirmed_candidate_requires_observed_invariant_result(self) -> None:
        evidence = json.loads(EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        evidence["envelopes"][1]["observation"].pop("invariant_results")

        gaps = gate.confirmed_evidence_gaps(
            {
                "matched_tactics": [
                    {"id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001", "score": 90}
                ],
                "validation_contract": {
                    "request_matrix": [
                        {"id": "self", "role": "baseline"},
                        {"id": "invalid", "role": "negative_control"},
                        {"id": "cross", "role": "candidate_probe"},
                    ]
                },
                "evidence_invariants": ["same-method-route-and-session"],
                "evidence_envelopes": evidence["envelopes"],
                "safe_validation_level": "readonly",
            },
            evidence["candidate_id"],
        )

        self.assertIn("evidence_envelopes[1].invariant_observation", gaps)
        self.assertIn("executed_evidence_invariants", gaps)

    def test_confirmed_state_change_requires_readback_and_completed_rollback(self) -> None:
        evidence = json.loads(EVIDENCE_FIXTURE.read_text(encoding="utf-8"))
        checks = gate.evaluate_candidate_closure(
            {
                "candidates": [
                    {
                        "id": evidence["candidate_id"],
                        "schema_version": "2.0",
                        "queue": "P1",
                        "status": "confirmed",
                        "safe_validation_level": "test_object",
                        "matched_tactics": [
                            {
                                "id": "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                                "score": 90,
                            }
                        ],
                        "validation_contract": {
                            "request_matrix": [
                                {"id": "self", "role": "baseline"},
                                {"id": "invalid", "role": "negative_control"},
                                {"id": "cross", "role": "candidate_probe"},
                            ]
                        },
                        "negative_controls": ["synthetic-nonexistent-object"],
                        "evidence_invariants": [
                            "same-method-route-and-session",
                        ],
                        "stop_conditions": ["first-bounded-impact"],
                        "rollback_plan": {
                            "required": True,
                            "status": "planned",
                        },
                        "evidence_envelopes": evidence["envelopes"],
                    }
                ]
            }
        )

        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["status"], "FAIL")
        self.assertIn("executed_readback", checks[0]["message"])
        self.assertIn("executed_rollback", checks[0]["message"])
        self.assertIn("rollback_plan.completed", checks[0]["message"])

    def test_semantic_gate_hard_fails_missing_offline_chain(self) -> None:
        bundle = self.fixture("healthy_baseline.json")
        state = dict(bundle["state"])
        state["phase_outputs"] = {
            key: value
            for key, value in state["phase_outputs"].items()
            if key not in gate.OFFLINE_SEMANTIC_PHASES
        }
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            (pipeline_dir / "pipeline_state.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    gate,
                    "load_phase_documents",
                    return_value=bundle["documents"],
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main(["--pipeline-dir", str(pipeline_dir)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 1)
        self.assertEqual(payload["status"], "FAIL")
        failed = {
            item["phase"]
            for item in payload["checks"]
            if item["status"] == "FAIL"
        }
        self.assertTrue(set(gate.OFFLINE_SEMANTIC_PHASES).issubset(failed))

    def test_semantic_gate_hard_fails_unparseable_or_incomplete_offline_output(
        self,
    ) -> None:
        bundle = self.fixture("healthy_baseline.json")
        state = bundle["state"]
        documents = dict(bundle["documents"])
        documents["js_intel"] = None
        state["phase_outputs"]["api_contract"]["status"] = "skipped"
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            (pipeline_dir / "pipeline_state.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    gate,
                    "load_phase_documents",
                    return_value=documents,
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main(["--pipeline-dir", str(pipeline_dir)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 1)
        failed = {
            item["phase"]: item["message"]
            for item in payload["checks"]
            if item["status"] == "FAIL"
        }
        self.assertIn("not parseable", failed["js_intel"])
        self.assertIn("not completed", failed["api_contract"])

    def test_legacy_quality_gate_alias_warns_without_new_offline_chain(self) -> None:
        bundle = self.fixture("healthy_baseline.json")
        state = dict(bundle["state"])
        state["phases_requested"] = ["quality_gate"]
        state["phase_outputs"] = {
            key: value
            for key, value in state["phase_outputs"].items()
            if key not in gate.OFFLINE_SEMANTIC_PHASES
        }
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            (pipeline_dir / "pipeline_state.json").write_text(
                json.dumps(state),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    gate,
                    "load_phase_documents",
                    return_value=bundle["documents"],
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main(["--pipeline-dir", str(pipeline_dir)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["status"], "WARN")
        self.assertTrue(
            any(
                item["phase"] == "quality_gate"
                and "migrate to semantic_quality_gate" in item["message"]
                for item in payload["warnings"]
            )
        )
        self.assertFalse(
            any(
                item["phase"] in gate.OFFLINE_SEMANTIC_PHASES
                for item in payload["checks"]
            )
        )

    def test_cli_report_and_archive_inputs_reach_consistency_checks(self) -> None:
        bundle = self.fixture("healthy_baseline.json")
        inconsistent = {
            "vulnerability_archive": {
                "totals": {"total": 2},
                "vulnerabilities": [],
            },
            "report": {
                "entity_counts": {
                    "server_declared_total": 1,
                    "sample_rows": 2,
                    "unique_entities": 3,
                },
                "vulnerabilities": [],
            },
        }
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            report_path = pipeline_dir / "report.json"
            archive_path = pipeline_dir / "archive.json"
            (pipeline_dir / "pipeline_state.json").write_text(
                json.dumps(bundle["state"]),
                encoding="utf-8",
            )
            report_path.write_text(
                json.dumps(inconsistent["report"]),
                encoding="utf-8",
            )
            archive_path.write_text(
                json.dumps(inconsistent["vulnerability_archive"]),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    gate,
                    "load_phase_documents",
                    return_value=dict(bundle["documents"]),
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main(
                    [
                        "--pipeline-dir",
                        str(pipeline_dir),
                        "--report",
                        str(report_path),
                        "--vulnerability-archive",
                        str(archive_path),
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(result, 1)
        by_id = {
            item["id"]: item["status"]
            for item in payload["report_consistency"]
        }
        self.assertEqual(by_id["report_consistency.input.report"], "PASS")
        self.assertEqual(
            by_id["report_consistency.input.vulnerability_archive"],
            "PASS",
        )
        self.assertEqual(
            by_id["report_consistency.entity_counts"],
            "FAIL",
        )
        self.assertEqual(
            by_id["report_consistency.archive_totals"],
            "FAIL",
        )

    def test_main_keeps_execution_checks_and_adds_semantic_sections(self) -> None:
        bundle = self.fixture("healthy_baseline.json")
        with tempfile.TemporaryDirectory() as raw_dir:
            pipeline_dir = Path(raw_dir)
            (pipeline_dir / "pipeline_state.json").write_text(
                json.dumps(bundle["state"]),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(
                    gate,
                    "load_phase_documents",
                    return_value=bundle["documents"],
                ),
                contextlib.redirect_stdout(stdout),
            ):
                result = gate.main(["--pipeline-dir", str(pipeline_dir)])

        self.assertEqual(result, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "PASS")
        self.assertIn("checks", payload)
        for field in (
            "semantic_checks",
            "coverage",
            "noise",
            "attack_surface",
            "candidate_closure",
            "report_consistency",
        ):
            self.assertIn(field, payload)


if __name__ == "__main__":
    unittest.main()
