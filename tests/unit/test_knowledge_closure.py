from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tool import (
    build_case_index,
    promote_memory,
    scan_reusable_knowledge_leaks,
)
from tool.cybertest_core.routing import load_tactics


ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = ROOT / "agent" / "cases"
CASE_SCHEMA = ROOT / "agent" / "schemas" / "case.schema.json"
CASE_INDEX = CASES_DIR / "index.json"
CASE_INDEX_MD = CASES_DIR / "index.md"
KNOWLEDGE_FIXTURES = ROOT / "tests" / "fixtures" / "knowledge"
INITIAL_CASE_IDS = {
    "CASE-AUTH-CUSTOMER-JWT-ADMIN-001",
    "CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
    "CASE-AUTHZ-MASS-ASSIGNMENT-001",
}
INITIAL_TACTIC_IDS = {
    "AUTH-CUSTOMER-JWT-TO-ADMIN-001",
    "AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
    "AUTHZ-MASS-ASSIGNMENT-001",
}
PATTERN_MEMORY = (
    ROOT
    / "agent"
    / "memory"
    / "pattern"
    / "pattern-memory-2026-07-24-case-evidence-contracts.md"
)
TACTIC_MEMORY = (
    ROOT
    / "agent"
    / "memory"
    / "tactic"
    / "tactic-memory-2026-07-24-evidence-contracts.md"
)
FULL_MEMORY = (
    ROOT
    / "agent"
    / "memory"
    / "full"
    / "full-distillation-2026-07-24-knowledge-closure.md"
)
MEMORY_QUEUE = ROOT / "agent" / "memory" / "queue.md"


class CaseIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = build_case_index.collect_cases(
            CASES_DIR,
            CASE_SCHEMA,
            repo_root=ROOT,
            verify_sources=True,
        )
        cls.generated = build_case_index.build_index(
            cls.records,
            repo_root=ROOT,
        )

    def test_repository_has_schema_valid_anonymized_cases(self) -> None:
        case_ids = {
            document["id"]
            for _path, document in self.records
        }
        self.assertGreaterEqual(len(self.records), len(INITIAL_CASE_IDS))
        self.assertTrue(INITIAL_CASE_IDS.issubset(case_ids))
        for _path, document in self.records:
            with self.subTest(case=document["id"]):
                self.assertEqual(
                    document["anonymization_check"]["status"],
                    "passed",
                )
                self.assertTrue(document["effective_paths"])
                self.assertTrue(document["ineffective_paths"])
                self.assertGreaterEqual(len(document["request_matrix"]), 3)
                self.assertTrue(document["false_positive_filters"])
                self.assertTrue(document["evidence_invariants"])
                self.assertTrue(document["stop_conditions"])
                self.assertTrue(document["sources"])

    def test_index_separates_stable_source_identity_from_content_hash(self) -> None:
        for case in self.generated["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["source_hashes"])
                self.assertTrue(case["source_identities"])
                self.assertTrue(
                    all(
                        set(identity) == {"source_alias", "relative_path"}
                        for identity in case["source_identities"]
                    )
                )
        identity_sets = {
            tuple(
                (
                    identity["source_alias"],
                    identity["relative_path"],
                )
                for identity in case["source_identities"]
            )
            for case in self.generated["cases"]
            if case["id"] in INITIAL_CASE_IDS
        }
        self.assertEqual(
            len(identity_sets),
            1,
            "共享同一来源文件的首批 case 必须保持同一稳定来源身份集合",
        )

    def test_duplicate_source_identity_is_rejected(self) -> None:
        _path, document = self.records[0]
        duplicate = copy.deepcopy(document)
        duplicate["sources"].append(copy.deepcopy(duplicate["sources"][0]))
        schema = build_case_index.load_json_document(CASE_SCHEMA)
        with self.assertRaisesRegex(
            build_case_index.CaseIndexError,
            "duplicate identity in sources",
        ):
            build_case_index.validate_case(
                duplicate,
                schema,
                label="duplicate-source-case",
                repo_root=ROOT,
                verify_sources=False,
            )

    def test_generated_json_is_fact_source_and_markdown_is_deterministic(self) -> None:
        stored_index = json.loads(CASE_INDEX.read_text(encoding="utf-8"))
        self.assertEqual(self.generated, stored_index)
        self.assertEqual(
            build_case_index.render_markdown(self.generated),
            CASE_INDEX_MD.read_text(encoding="utf-8"),
        )

    def test_all_required_search_dimensions_are_populated(self) -> None:
        self.assertEqual(
            set(self.generated["dimensions"]),
            set(build_case_index.DIMENSIONS),
        )
        for dimension, values in self.generated["dimensions"].items():
            with self.subTest(dimension=dimension):
                self.assertTrue(values)
                self.assertTrue(all(case_ids for case_ids in values.values()))
        self.assertIn(
            "CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001",
            self.generated["dimensions"]["trust_boundary"][
                "account-to-business-object"
            ],
        )
        self.assertIn(
            "CASE-AUTHZ-MASS-ASSIGNMENT-001",
            self.generated["dimensions"]["root_cause_family"][
                "mass_assignment"
            ],
        )

    def test_case_and_tactic_links_are_bidirectional(self) -> None:
        cases = {
            document["id"]: document
            for _path, document in self.records
        }
        tactics = {
            tactic["id"]: tactic
            for tactic in load_tactics(ROOT)
        }
        for case_id, case in cases.items():
            for tactic_id in case["matched_tactics"]:
                with self.subTest(case=case_id, tactic=tactic_id):
                    self.assertIn(tactic_id, tactics)
                    self.assertIn(
                        case_id,
                        tactics[tactic_id].get("source_cases", []),
                    )
        for tactic_id, tactic in tactics.items():
            for case_id in tactic.get("source_cases", []):
                with self.subTest(tactic=tactic_id, case=case_id):
                    self.assertIn(case_id, cases)
                    self.assertIn(
                        tactic_id,
                        cases[case_id]["matched_tactics"],
                    )
            source_signatures = {
                tuple(
                    sorted(
                        (
                            source["source_alias"],
                            Path(source["relative_path"]).as_posix(),
                        )
                        for source in cases[case_id]["sources"]
                    )
                )
                for case_id in tactic.get("source_cases", [])
                if case_id in cases
            }
            if tactic.get("source_cases") and len(source_signatures) < 2:
                with self.subTest(tactic=tactic_id, metric="history-count"):
                    self.assertEqual(
                        tactic.get("historical_validation_count"),
                        0,
                        "单一迁移来源不得获得跨任务历史验证加分",
                    )

    def test_check_cli_is_read_only_and_current(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            return_code = build_case_index.main(
                ["--verify-sources", "--check"],
            )
        self.assertEqual(return_code, 0)
        self.assertTrue(json.loads(stdout.getvalue())["ok"])


class PromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = json.loads(CASE_INDEX.read_text(encoding="utf-8"))

    def test_single_case_families_remain_draft_suggestions(self) -> None:
        report = promote_memory.build_recommendations(self.index)
        self.assertEqual(report["automatic_skill_writes"], 0)
        expected_groups = set(
            self.index["dimensions"]["matched_tactics"]
        )
        actual_groups = {
            recommendation["group_key"]
            for recommendation in report["recommendations"]
        }
        self.assertEqual(report["recommendation_count"], len(expected_groups))
        self.assertEqual(actual_groups, expected_groups)
        initial_recommendations = [
            recommendation
            for recommendation in report["recommendations"]
            if recommendation["group_key"] in INITIAL_TACTIC_IDS
        ]
        self.assertEqual(len(initial_recommendations), len(INITIAL_TACTIC_IDS))
        for recommendation in initial_recommendations:
            with self.subTest(group=recommendation["group_key"]):
                self.assertEqual(
                    recommendation["recommended_stage"],
                    "draft_pattern",
                )
                self.assertTrue(recommendation["requires_human_approval"])
                self.assertFalse(recommendation["writes_stable_skill"])
                self.assertTrue(recommendation["source_hashes"])
                self.assertTrue(recommendation["source_identities"])
                self.assertEqual(
                    recommendation["independence_basis"],
                    "source_identity",
                )
                self.assertTrue(recommendation["blockers"])

    def test_hash_drift_from_same_source_does_not_create_independence(self) -> None:
        candidate = copy.deepcopy(self.index["cases"][0])
        candidate["id"] = "CASE-SYNTHETIC-SAME-SOURCE-002"
        candidate["source_hashes"] = ["f" * 64]
        candidate["scene"] = "second-independent-scene"
        synthetic_index = copy.deepcopy(self.index)
        synthetic_index["cases"].append(candidate)

        report = promote_memory.build_recommendations(synthetic_index)
        matching = next(
            item
            for item in report["recommendations"]
            if item["group_key"] == candidate["matched_tactics"][0]
        )
        self.assertEqual(matching["recommended_stage"], "draft_pattern")
        self.assertEqual(matching["independent_source_set_count"], 1)
        self.assertIn(
            "独立 case 的稳定来源身份集合少于 2 组",
            matching["blockers"],
        )

    def test_repeated_independent_case_only_proposes_active_pattern(self) -> None:
        candidate = copy.deepcopy(self.index["cases"][0])
        candidate["id"] = "CASE-SYNTHETIC-INDEPENDENT-002"
        candidate["source_hashes"] = ["f" * 64]
        candidate["source_identities"] = [
            {
                "source_alias": "independent-retrospective",
                "relative_path": "agent/retrospectives/independent-task.md",
            }
        ]
        candidate["scene"] = "second-independent-scene"
        synthetic_index = copy.deepcopy(self.index)
        synthetic_index["cases"].append(candidate)

        report = promote_memory.build_recommendations(synthetic_index)
        matching = next(
            item
            for item in report["recommendations"]
            if item["group_key"] == candidate["matched_tactics"][0]
        )
        self.assertEqual(matching["recommended_stage"], "active_pattern")
        self.assertEqual(matching["independent_source_set_count"], 2)
        self.assertFalse(matching["writes_stable_skill"])

    def test_missing_source_identity_fails_closed(self) -> None:
        invalid_index = copy.deepcopy(self.index)
        invalid_index["cases"][0].pop("source_identities")
        with self.assertRaisesRegex(
            promote_memory.PromotionError,
            "missing source identities",
        ):
            promote_memory.build_recommendations(invalid_index)

    def test_cli_dry_run_does_not_write_suggestion_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "promotion.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = promote_memory.main(
                    [
                        "--case-index",
                        str(CASE_INDEX),
                        "--output",
                        str(output),
                        "--dry-run",
                    ]
                )
            self.assertEqual(return_code, 0)
            self.assertFalse(output.exists())
            report = json.loads(stdout.getvalue())
            self.assertTrue(report["dry_run"])
            self.assertEqual(report["automatic_skill_writes"], 0)


class MemoryQueueTests(unittest.TestCase):
    def test_completed_batches_are_counted_and_auditable(self) -> None:
        queue = MEMORY_QUEUE.read_text(encoding="utf-8")
        self.assertIn("- completed_pattern_batches: 2", queue)
        self.assertIn("- completed_tactic_batches: 1", queue)
        self.assertIn("- completed_full_batches: 1", queue)
        self.assertIn(
            "batch_id: pattern-memory-2026-07-24-case-evidence-contracts",
            queue,
        )
        self.assertIn(
            "batch_id: tactic-memory-2026-07-24-evidence-contracts",
            queue,
        )
        self.assertIn(
            "batch_id: full-distillation-2026-07-24-knowledge-closure",
            queue,
        )

    def test_new_pattern_is_draft_and_scoped_to_initial_case_window(self) -> None:
        pattern_memory = PATTERN_MEMORY.read_text(encoding="utf-8")
        self.assertIn(
            "- batch_id：`pattern-memory-2026-07-24-case-evidence-contracts`",
            pattern_memory,
        )
        self.assertIn("- selection_rule：", pattern_memory)
        self.assertIn("- 适用范围：", pattern_memory)
        self.assertIn("- 不适用范围：", pattern_memory)
        self.assertIn("- 状态：draft", pattern_memory)
        self.assertIn("- 跨任务历史验证数：0", pattern_memory)
        self.assertIn("不据此声称跨任务复现", pattern_memory)
        for case_id in INITIAL_CASE_IDS:
            with self.subTest(case=case_id):
                self.assertIn(case_id, pattern_memory)

        memory_index = (
            ROOT / "agent" / "memory" / "index.md"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "pattern/pattern-memory-2026-07-24-case-evidence-contracts.md",
            memory_index,
        )
        self.assertIn(
            "| medium | draft | 2026-07-24 |",
            memory_index,
        )

    def test_memory_provenance_hash_chain_is_current(self) -> None:
        case_index_hash = hashlib.sha256(CASE_INDEX.read_bytes()).hexdigest()
        pattern_memory = PATTERN_MEMORY.read_text(encoding="utf-8")
        self.assertIn(
            f"`agent/cases/index.json`：`{case_index_hash}`",
            pattern_memory,
        )

        pattern_memory_hash = hashlib.sha256(
            PATTERN_MEMORY.read_bytes()
        ).hexdigest()
        tactic_memory = TACTIC_MEMORY.read_text(encoding="utf-8")
        self.assertIn(
            f"`agent/cases/index.json`：`{case_index_hash}`",
            tactic_memory,
        )
        self.assertIn(
            (
                "`agent/memory/pattern/"
                "pattern-memory-2026-07-24-case-evidence-contracts.md`："
                f"`{pattern_memory_hash}`"
            ),
            tactic_memory,
        )

        tactic_memory_hash = hashlib.sha256(
            TACTIC_MEMORY.read_bytes()
        ).hexdigest()
        full_memory = FULL_MEMORY.read_text(encoding="utf-8")
        self.assertIn(
            f"`agent/cases/index.json`：`{case_index_hash}`",
            full_memory,
        )
        self.assertIn(
            (
                "`agent/memory/pattern/"
                "pattern-memory-2026-07-24-case-evidence-contracts.md`："
                f"`{pattern_memory_hash}`"
            ),
            full_memory,
        )
        self.assertIn(
            (
                "`agent/memory/tactic/"
                "tactic-memory-2026-07-24-evidence-contracts.md`："
                f"`{tactic_memory_hash}`"
            ),
            full_memory,
        )


class ReusableKnowledgeLeakTests(unittest.TestCase):
    def test_new_reusable_knowledge_and_placeholders_are_clean(self) -> None:
        report = scan_reusable_knowledge_leaks.scan_paths(
            scan_reusable_knowledge_leaks.DEFAULT_ROOTS,
            repo_root=ROOT,
        )
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["blocking_finding_count"], 0)
        self.assertGreater(report["scanned_file_count"], 100)
        self.assertEqual(
            set(scan_reusable_knowledge_leaks.DEFAULT_ROOTS),
            {
                ROOT / "agent" / "cases",
                ROOT / "agent" / "memory",
                ROOT / "agent" / "tactics",
                ROOT / "agent" / "skills",
                ROOT / "agent" / "references",
                ROOT / "tests" / "fixtures",
                ROOT / "tests" / "golden",
            },
        )

    def test_detector_finds_all_high_value_classes_without_echoing_values(
        self,
    ) -> None:
        personal_path = "/" + "Users/" + "analyst/workspace"
        private_key = "-----BEGIN " + "PRIVATE KEY-----"
        jwt_value = (
            "eyJ" + "headerValue12"
            + "."
            + "eyJ" + "payloadValue12"
            + "."
            + "SignatureValue123"
        )
        token_value = "Aq9_zP4+Lm2-Ks8/Tx5=Vn7.Rc3"
        email_value = "analyst@" + "corp-prod.cn"
        domain_value = "api." + "corp-prod.cn"
        ip_value = "10." + "23.45.67"
        ipv6_value = "fd12:" + "3456:789a::10"
        content = "\n".join(
            [
                personal_path,
                private_key,
                jwt_value,
                "secret=" + token_value,
                email_value,
                domain_value,
                ip_value,
                ipv6_value,
            ]
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "synthetic.txt"
            sample.write_text(content, encoding="utf-8")
            report = scan_reusable_knowledge_leaks.scan_paths(
                [sample],
                repo_root=ROOT,
            )

        kinds = {finding["kind"] for finding in report["findings"]}
        self.assertEqual(
            kinds,
            {
                "domain",
                "email",
                "high_confidence_token",
                "ip_address",
                "jwt",
                "personal_absolute_path",
                "private_key",
            },
        )
        serialized = json.dumps(report)
        for raw_value in (
            personal_path,
            private_key,
            jwt_value,
            token_value,
            email_value,
            domain_value,
            ip_value,
            ipv6_value,
        ):
            self.assertNotIn(raw_value, serialized)

    def test_default_scan_cli_dry_run_never_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "leaks.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                return_code = scan_reusable_knowledge_leaks.main(
                    [
                        "--output",
                        str(output),
                        "--dry-run",
                        "--fail-on-findings",
                    ]
                )
            self.assertEqual(return_code, 0, stderr.getvalue())
            self.assertFalse(output.exists())
            report = json.loads(stdout.getvalue())
            self.assertTrue(report["dry_run"])
            self.assertEqual(report["blocking_finding_count"], 0)
            self.assertIn(report["status"], {"PASS", "REVIEW"})

    def test_medium_review_findings_can_be_promoted_to_strict_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "synthetic.txt"
            sample.write_text("target.corp-prod.cn\n", encoding="utf-8")
            default_report = scan_reusable_knowledge_leaks.scan_paths(
                [sample],
                repo_root=ROOT,
            )
            strict_report = scan_reusable_knowledge_leaks.scan_paths(
                [sample],
                repo_root=ROOT,
                fail_severity="medium",
            )

        self.assertEqual(default_report["status"], "REVIEW")
        self.assertTrue(default_report["ok"])
        self.assertEqual(default_report["review_finding_count"], 1)
        self.assertEqual(strict_report["status"], "FAIL")
        self.assertFalse(strict_report["ok"])
        self.assertEqual(strict_report["blocking_finding_count"], 1)


class MemoryGovernanceTests(unittest.TestCase):
    def test_tactic_and_full_memory_are_nonempty_and_auditable(self) -> None:
        for path in (TACTIC_MEMORY, FULL_MEMORY):
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                self.assertIn("selection_rule", content)
                self.assertIn("来源 SHA-256", content)
                self.assertIn("晋升", content)
                self.assertGreater(len(content), 1000)
        tactic_content = TACTIC_MEMORY.read_text(encoding="utf-8")
        self.assertIn("命中率", tactic_content)
        self.assertIn("噪声率", tactic_content)
        full_content = FULL_MEMORY.read_text(encoding="utf-8")
        self.assertIn("自动 skill 写入", full_content)
        self.assertIn("0", full_content)


if __name__ == "__main__":
    unittest.main()
