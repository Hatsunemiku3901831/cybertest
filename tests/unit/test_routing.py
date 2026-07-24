from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tool.cybertest_core.routing import load_tactics, rank_tactics
from tool.cybertest_core.schema_validation import (
    load_json_document,
    validate_instance,
)


ROOT = Path(__file__).resolve().parents[2]
GOLDEN_ROOT = ROOT / "tests" / "golden" / "routing"
SCHEMA_ROOT = ROOT / "agent" / "schemas"


class RoutingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tactics = load_tactics(ROOT)
        cls.context_schema = load_json_document(
            SCHEMA_ROOT / "route-context.schema.json"
        )
        cls.decision_schema = load_json_document(
            SCHEMA_ROOT / "route-decision.schema.json"
        )

    def test_registry_loads_ten_schema_valid_tactics(self) -> None:
        self.assertEqual(
            [item["id"] for item in self.tactics],
            [
                "AUTH-CUSTOMER-JWT-TO-ADMIN-001",
                "AUTH-JWT-ACCEPTANCE-MATRIX-001",
                "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
                "AUTHZ-EXPORT-LOG-FIELD-BOUNDARY-001",
                "AUTHZ-MASS-ASSIGNMENT-001",
                "FILE-GUEST-UPLOAD-TICKET-001",
                "INJECTION-ORDER-BY-BOOLEAN-ORACLE-001",
                "INTEGRATION-BLIND-SSRF-MEDIA-001",
                "INTEGRATION-THIRD-PARTY-SECRET-VALIDATION-001",
                "INTEGRATION-WEBSOCKET-PATH-IDENTITY-001",
            ],
        )

    def test_golden_route_decisions(self) -> None:
        for fixture_path in sorted(GOLDEN_ROOT.glob("*.json")):
            with self.subTest(fixture=fixture_path.name):
                fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
                context = fixture["context"]
                expected = fixture["expected"]
                self.assertEqual(
                    validate_instance(context, self.context_schema),
                    [],
                    fixture_path.name,
                )

                decision = rank_tactics(
                    context,
                    tactics=self.tactics,
                    policy=fixture.get("policy"),
                )
                self.assertEqual(
                    validate_instance(decision, self.decision_schema),
                    [],
                    fixture_path.name,
                )
                self.assertEqual(decision["route_status"], expected["route_status"])
                top1 = (
                    decision["matched_tactics"][0]["id"]
                    if decision["matched_tactics"]
                    else None
                )
                self.assertEqual(top1, expected.get("top1"))
                self.assertEqual(
                    decision["resume_tactic_id"],
                    expected.get("resume_tactic_id"),
                )
                if decision["matched_tactics"]:
                    self.assertEqual(
                        decision["matched_tactics"][0]["load_mode"], "full"
                    )
                    self.assertTrue(
                        all(
                            item["load_mode"] == "summary"
                            for item in decision["matched_tactics"][1:]
                        )
                    )

                excluded_tactic = expected.get("excluded_tactic")
                if excluded_tactic:
                    self.assertNotIn(
                        excluded_tactic,
                        [item["id"] for item in decision["matched_tactics"]],
                    )
                    matching_trace = [
                        item
                        for item in decision["trace"]
                        if item.get("tactic_id") == excluded_tactic
                    ]
                    self.assertTrue(matching_trace)
                    codes = {
                        reason["code"]
                        for item in matching_trace
                        for reason in item.get("reasons", [])
                        if isinstance(reason, dict) and "code" in reason
                    }
                    self.assertIn(expected["excluded_code"], codes)

    def test_same_context_produces_stable_decision(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "jwt-acceptance.json")
        first = rank_tactics(
            fixture["context"], tactics=self.tactics, policy=fixture["policy"]
        )
        second = rank_tactics(
            fixture["context"], tactics=self.tactics, policy=fixture["policy"]
        )
        self.assertEqual(first, second)
        self.assertEqual(first["decision_id"], second["decision_id"])

    def test_stable_tie_break_and_attention_budget(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "jwt-acceptance.json")
        base = next(
            tactic
            for tactic in self.tactics
            if tactic["id"] == "AUTH-JWT-ACCEPTANCE-MATRIX-001"
        )
        tactics = []
        for tactic_id in ("TEST-TIE-002", "TEST-TIE-001", "TEST-TIE-003", "TEST-TIE-004"):
            tactic = copy.deepcopy(base)
            tactic["id"] = tactic_id
            tactic["title"] = tactic_id
            tactics.append(tactic)

        decision = rank_tactics(
            fixture["context"],
            tactics=tactics,
            top_k=99,
            policy=fixture["policy"],
        )
        self.assertEqual(
            [item["id"] for item in decision["matched_tactics"]],
            ["TEST-TIE-001", "TEST-TIE-002", "TEST-TIE-003"],
        )
        self.assertEqual(
            [item["load_mode"] for item in decision["matched_tactics"]],
            ["full", "summary", "summary"],
        )
        self.assertEqual(
            [item["id"] for item in decision["deferred_tactics"]],
            ["TEST-TIE-004"],
        )

    def test_invalid_tactic_is_rejected_by_schema(self) -> None:
        schema = load_json_document(SCHEMA_ROOT / "tactic.schema.json")
        invalid = {"schema_version": "1.0", "id": "INVALID-001"}
        errors = validate_instance(invalid, schema)
        self.assertTrue(errors)
        self.assertTrue(any("missing required property" in item for item in errors))

    def test_generic_dimensions_without_semantic_anchor_return_route_gap(self) -> None:
        context = {
            "schema_version": "1.0",
            "task_kind": "security-testing",
            "phase": "triage",
            "category": "authorization",
            "target_types": ["api", "admin"],
            "technologies": [],
            "business_objects": ["user"],
            "operation_types": ["write"],
            "trust_boundaries": ["user_to_admin"],
            "observed_signals": ["Admin/Management", "anonymous_hint"],
            "suspected_control_gaps": [],
            "auth_contexts": [],
            "evidence_stage": "route",
            "available_materials": [],
            "available_capabilities": ["cli.http"],
            "excluded_routes": [],
            "previous_route_decisions": [],
        }

        decision = rank_tactics(context, tactics=self.tactics)

        self.assertEqual(decision["route_status"], "route_gap")
        self.assertEqual(decision["matched_tactics"], [])
        self.assertTrue(
            any(
                item["outcome"] == "insufficient_semantic_anchor"
                for item in decision["trace"]
            )
        )

    def test_policy_cannot_downgrade_write_tactic_without_readonly_contract(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "mass-assignment.json")
        context = copy.deepcopy(fixture["context"])
        policy = copy.deepcopy(fixture["policy"])
        policy["max_safe_validation_level"] = "readonly"

        decision = rank_tactics(
            context,
            tactics=self.tactics,
            policy=policy,
        )

        self.assertEqual(decision["route_status"], "policy_conflict")
        self.assertEqual(decision["matched_tactics"], [])
        self.assertEqual(decision["validation_contract"], {})

    def test_blocked_material_route_records_exact_resume_contract(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "material-missing.json")

        decision = rank_tactics(
            fixture["context"],
            tactics=self.tactics,
            policy=fixture["policy"],
        )

        self.assertEqual(decision["route_status"], "blocked_need_material")
        self.assertEqual(
            decision["resume_tactic_id"],
            "AUTHZ-MASS-ASSIGNMENT-001",
        )
        self.assertEqual(
            decision["fallback"]["missing_materials"],
            ["reversible_test_object"],
        )
        self.assertEqual(
            decision["validation_contract"]["tactic_id"],
            decision["resume_tactic_id"],
        )
        self.assertTrue(decision["next_discriminating_action"])

    def test_capability_fallback_is_not_mislabeled_readonly(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "mass-assignment.json")

        decision = rank_tactics(
            fixture["context"],
            tactics=self.tactics,
            policy=fixture["policy"],
        )

        self.assertEqual(decision["route_status"], "matched_with_fallback")
        self.assertEqual(
            decision["validation_contract"]["execution_mode"],
            "capability_fallback",
        )
        self.assertEqual(
            decision["validation_contract"]["safe_validation_level"],
            "test_object",
        )

    def test_unhealthy_v2_capability_does_not_unblock_route(self) -> None:
        fixture = load_json_document(GOLDEN_ROOT / "capability-missing.json")
        context = copy.deepcopy(fixture["context"])
        capability = {
            "capability": "browser.interactive",
            "installed": True,
            "configured": True,
            "reachable": True,
            "healthy": False,
            "permitted": True,
            "material_ready": True,
            "available": False,
            "health": "degraded",
            "source_compatibility": "v2",
        }
        http_replay = {
            "capability": "http.replay",
            "installed": True,
            "configured": True,
            "reachable": True,
            "healthy": True,
            "permitted": True,
            "material_ready": True,
            "available": True,
            "health": "ok",
            "source_compatibility": "v2",
        }
        context["available_capabilities"] = [capability, http_replay]
        self.assertEqual(
            validate_instance(context, self.context_schema),
            [],
        )

        blocked = rank_tactics(
            context,
            tactics=self.tactics,
            policy=fixture["policy"],
        )
        self.assertEqual(blocked["route_status"], "blocked_need_capability")

        capability["healthy"] = True
        capability["available"] = True
        capability["health"] = "ok"
        matched = rank_tactics(
            context,
            tactics=self.tactics,
            policy=fixture["policy"],
        )
        self.assertEqual(matched["route_status"], "matched")


if __name__ == "__main__":
    unittest.main()
