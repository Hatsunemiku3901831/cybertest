from __future__ import annotations

import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = REPO_ROOT / "tool"
sys.path.insert(0, str(TOOL_DIR))

import bounty_candidate_queue as queue  # noqa: E402
from cybertest_core.candidate_scoring import priority_score  # noqa: E402
from cybertest_core.models import Candidate, RawSignal  # noqa: E402
from cybertest_core.url_normalization import (  # noqa: E402
    normalize_host,
    normalize_route_template,
    normalized_asset_for,
    stable_instance_key,
)


class CandidateCoreTest(unittest.TestCase):
    def test_scheme_host_and_default_port_normalization(self) -> None:
        self.assertEqual(normalize_host("API.Example.Test."), "api.example.test")
        self.assertEqual(
            normalized_asset_for("HTTPS://API.Example.Test:443/v1/users"),
            "https://api.example.test",
        )
        self.assertEqual(
            normalized_asset_for("http://API.Example.Test:8080/v1/users"),
            "http://api.example.test:8080",
        )
        self.assertEqual(normalize_host("2001:DB8::1"), "[2001:db8::1]")

    def test_route_and_instance_ignore_random_ids_and_query_values(self) -> None:
        first = (
            "https://api.example.test:443/v1/orders/123456/"
            "550e8400-e29b-41d4-a716-446655440000"
            "?token=synthetic-token-alpha&page=1"
        )
        second = (
            "HTTPS://API.EXAMPLE.TEST/v1/orders/654321/"
            "123e4567-e89b-42d3-a456-426614174000"
            "?page=2&token=synthetic-token-beta"
        )

        self.assertEqual(
            normalize_route_template(first),
            "/v1/orders/{id}/{id}?page&token",
        )
        self.assertEqual(
            normalize_route_template(first),
            normalize_route_template(second),
        )
        first_key = stable_instance_key(
            first,
            "get",
            "order",
            "read",
            "object_authorization",
        )
        second_key = stable_instance_key(
            second,
            "GET",
            "order",
            "read",
            "object_authorization",
        )
        self.assertEqual(first_key, second_key)
        self.assertNotIn("synthetic-token", first_key)
        self.assertNotIn("123456", first_key)

    def test_different_root_causes_do_not_merge(self) -> None:
        url = "https://api.example.test/v1/resources/123?token=synthetic"
        object_key = stable_instance_key(
            url,
            "GET",
            "endpoint",
            "read",
            "object_authorization",
        )
        function_key = stable_instance_key(
            url,
            "GET",
            "endpoint",
            "read",
            "function_authorization",
        )
        candidates = [
            Candidate(
                key=object_key,
                name="object boundary",
                asset="https://api.example.test",
                url_or_endpoint="/v1/resources/123",
                candidate_type="IDOR/BOLA",
                score=60,
                priority_score=60,
            ),
            Candidate(
                key=function_key,
                name="function boundary",
                asset="https://api.example.test",
                url_or_endpoint="/v1/resources/123",
                candidate_type="Admin/Management",
                score=60,
                priority_score=60,
            ),
        ]

        self.assertNotEqual(object_key, function_key)
        self.assertEqual(len(queue.merge_candidates(candidates)), 2)

    def test_priority_and_evidence_confidence_are_independent(self) -> None:
        value = "https://api.synthetic.invalid/v1/admin/users"
        weak = queue.classify_signal(
            RawSignal(value, "httpx", "anonymous-httpx.json", {"status": 200}),
            "Admin/Management",
        )
        differential_negative = queue.classify_signal(
            RawSignal(
                value,
                "httpx",
                "anonymous-httpx.json",
                {
                    "status": 200,
                    "auth_experiment": {
                        "missing_auth": 200,
                        "fixed_invalid_auth": 401,
                        "controlled_auth": 500,
                    },
                },
            ),
            "Admin/Management",
        )

        self.assertEqual(weak.priority_score, differential_negative.priority_score)
        self.assertEqual(weak.evidence_confidence, "weak")
        self.assertEqual(
            differential_negative.evidence_confidence,
            "differential",
        )
        self.assertFalse(differential_negative.unauth_reachable)

        direct_score, _, _ = priority_score(
            "Admin/Management",
            core_business=True,
            has_test_environment=False,
            has_edge_surface=True,
            source="httpx",
            auth_proven=False,
            status=200,
            health_only=False,
        )
        self.assertEqual(direct_score, weak.priority_score)


if __name__ == "__main__":
    unittest.main()
