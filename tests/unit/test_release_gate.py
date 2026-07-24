from __future__ import annotations

import subprocess
import unittest

from tool import release_gate


class ReleaseGateTest(unittest.TestCase):
    def test_pass_report_uses_fixed_order_and_stable_json_shape(self) -> None:
        calls: list[list[str]] = []

        def fake_runner(command, **kwargs):
            del kwargs
            calls.append(list(command))
            stdout = "README.md\ntool/release_gate.py\n" if command[:2] == ["git", "ls-files"] else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")

        report = release_gate.run_checks(runner=fake_runner)

        self.assertTrue(report["ok"])
        self.assertEqual(
            list(report["checks"]),
            [
                "unit_tests",
                "markdown_links",
                "case_index",
                "reusable_knowledge",
                "repository_hygiene",
                "pipeline_dry_run",
            ],
        )
        self.assertEqual(len(calls), 6)
        self.assertEqual(calls[4], ["git", "ls-files"])
        self.assertTrue(
            all(item["status"] == "PASS" for item in report["checks"].values())
        )

    def test_failed_required_check_returns_failed_report(self) -> None:
        def fake_runner(command, **kwargs):
            del kwargs
            return_code = (
                1
                if any(
                    item.endswith("scan_reusable_knowledge_leaks.py")
                    for item in command
                )
                else 0
            )
            return subprocess.CompletedProcess(command, return_code, "", "")

        report = release_gate.run_checks(runner=fake_runner)

        self.assertFalse(report["ok"])
        self.assertEqual(
            report["checks"]["reusable_knowledge"]["status"],
            "FAIL",
        )

    def test_tracked_python_cache_fails_repository_hygiene(self) -> None:
        def fake_runner(command, **kwargs):
            del kwargs
            stdout = (
                "tool/__pycache__/module.cpython-312.pyc\n"
                if command[:2] == ["git", "ls-files"]
                else ""
            )
            return subprocess.CompletedProcess(command, 0, stdout, "")

        report = release_gate.run_checks(runner=fake_runner)

        self.assertFalse(report["ok"])
        hygiene = report["checks"]["repository_hygiene"]
        self.assertEqual(hygiene["status"], "FAIL")
        self.assertEqual(hygiene["tracked_cache_count"], 1)


if __name__ == "__main__":
    unittest.main()
