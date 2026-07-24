from __future__ import annotations

import os
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = (
    REPO_ROOT
    / "agent"
    / "skills"
    / "reverse"
    / "scripts"
    / "bootstrap-reverse.sh"
)
REFRESH_INDEX = (
    REPO_ROOT
    / "agent"
    / "skills"
    / "reverse"
    / "scripts"
    / "refresh-tool-index.sh"
)
DIRECT_SKILL_DOCS = (
    REPO_ROOT / "agent" / "skills" / "reverse-security.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "js-reverse" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "ida-reverse" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "apk-reverse" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "radare2" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "firmware-pentest" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "pwn-chain" / "SKILL.md",
    REPO_ROOT / "agent" / "skills" / "reverse" / "binary-diff" / "SKILL.md",
    REPO_ROOT
    / "agent"
    / "skills"
    / "reverse"
    / "patch-diff-exploit"
    / "SKILL.md",
)


class ReverseBootstrapTest(unittest.TestCase):
    def run_bootstrap(
        self,
        *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if environment:
            env.update(environment)
        return subprocess.run(
            ["bash", str(BOOTSTRAP), *arguments],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def test_script_syntax_and_help_describe_safe_modes(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(BOOTSTRAP)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        help_result = self.run_bootstrap("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("--detect", help_result.stdout)
        self.assertIn("--dry-run", help_result.stdout)
        self.assertIn("--install", help_result.stdout)
        self.assertIn("--apply --mcp-config FILE", help_result.stdout)
        self.assertIn("Read-only detection (default)", help_result.stdout)

    def test_default_mode_is_read_only_detection(self) -> None:
        completed = self.run_bootstrap("jadx")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("mode=detect", completed.stdout)
        self.assertIn("capability=jadx", completed.stdout)
        self.assertIn("agent capability detector (read-only)", completed.stdout)
        self.assertIn("side_effects=none", completed.stdout)

    def test_dry_run_does_not_write_explicit_mcp_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = root / "client" / "mcp.json"
            completed = self.run_bootstrap(
                "--dry-run",
                "--mcp-config",
                str(config_path),
                "anything-analyzer",
                environment={
                    "HOME": str(root),
                    "ANYTHING_ANALYZER_MCP_URL": (
                        "http://runtime-provider.example.invalid/mcp"
                    ),
                },
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("mode=dry-run", completed.stdout)
            self.assertIn(
                "action=runtime-provider-and-explicit-mcp-config",
                completed.stdout,
            )
            self.assertIn("side_effects=none", completed.stdout)
            self.assertFalse(config_path.exists())

    def test_automatic_service_start_is_rejected(self) -> None:
        completed = self.run_bootstrap(
            "--apply",
            "--mcp-config",
            "synthetic-mcp.json",
            "--start-services",
            "anything-analyzer",
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("Automatic service start was removed", completed.stderr)
        self.assertFalse((REPO_ROOT / "synthetic-mcp.json").exists())

    def test_apply_for_mcp_requires_explicit_config_before_side_effects(self) -> None:
        completed = self.run_bootstrap("--apply", "anything-analyzer")

        self.assertEqual(completed.returncode, 2)
        self.assertIn("requires --mcp-config FILE", completed.stderr)

    def test_script_has_no_global_config_or_fixed_endpoint_assumption(self) -> None:
        source = BOOTSTRAP.read_text(encoding="utf-8")

        for forbidden in (
            ".claude/mcp.json",
            "$HOME/tools",
            "23816",
            "13337",
            "127.0.0.1:",
            "localhost:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("require/profiles.json", source)
        self.assertIn("tool/detect_capabilities.py", source)

    def test_direct_skill_docs_do_not_repeat_removed_bootstrap_promises(self) -> None:
        forbidden_phrases = (
            "自动写入 Claude MCP 配置",
            "bootstrap-reverse.ps1",
            "%USERPROFILE%\\Tools",
            "127.0.0.1:7555",
            "127.0.0.1:13337",
            "端口 23816",
        )
        for path in DIRECT_SKILL_DOCS:
            text = path.read_text(encoding="utf-8")
            for phrase in forbidden_phrases:
                with self.subTest(document=path.name, phrase=phrase):
                    self.assertNotIn(phrase, text)

    def test_generated_tool_index_can_be_recovered_from_tracked_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            markdown = root / "tool-index.md"
            json_output = root / "tool-index.json"
            environment = os.environ.copy()
            environment["HOME"] = str(root)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"

            completed = subprocess.run(
                [
                    "bash",
                    str(REFRESH_INDEX),
                    str(markdown),
                    str(json_output),
                ],
                cwd=REPO_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(markdown.is_file())
            payload = json.loads(json_output.read_text(encoding="utf-8"))
            self.assertGreater(len(payload["tools"]), 0)
            self.assertTrue(
                all(
                    item["path"] is None or "/" not in item["path"]
                    for item in payload["tools"]
                )
            )


if __name__ == "__main__":
    unittest.main()
