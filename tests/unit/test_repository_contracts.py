from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = REPO_ROOT / "tool"
SCHEMA_DIR = REPO_ROOT / "agent" / "schemas"
TACTIC_DIR = REPO_ROOT / "agent" / "tactics"
CAPABILITY_MANIFEST = REPO_ROOT / "agent" / "capabilities" / "manifest.yaml"
ROOT_AGENT = REPO_ROOT / "AGENTS.md"
MAIN_AGENT = REPO_ROOT / "agent" / "AGENT.md"
sys.path.insert(0, str(TOOL_DIR))

import bounty_candidate_queue as candidate_queue  # noqa: E402
import check_markdown_links  # noqa: E402
from cybertest_core.schema_validation import (  # noqa: E402
    assert_valid,
    load_json_document,
)


PERSONAL_PATH_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home|root)/[^/\s\"'\\]+/"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"']+\\"),
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"(?![A-Za-z0-9_-])"
)
DOMAIN_RE = re.compile(
    r"(?<![@A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b"
)
IPV4_RE = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]{0,39}"
    r"(?![0-9A-Fa-f:])"
)
ALLOWED_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
    )
)
ALLOWED_IPV6_NETWORKS = (
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("::1/128"),
)
TEXT_FIXTURE_SUFFIXES = {
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".js",
    ".map",
}
NON_DOMAIN_ARTIFACT_SUFFIXES = {
    ".html",
    ".json",
    ".yaml",
    ".yml",
    ".js",
    ".map",
    ".md",
    ".txt",
}
CRITICAL_CLIS = (
    "bounty_candidate_queue.py",
    "scan_pipeline.py",
    "quality_gate.py",
    "detect_capabilities.py",
    "run_dynamic_validation.py",
    "release_gate.py",
    "build_case_index.py",
    "check_markdown_links.py",
)


def duplicate_values(values: list[str]) -> set[str]:
    return {value for value in values if values.count(value) > 1}


def is_reserved_domain(domain: str) -> bool:
    normalized = domain.rstrip(".").lower()
    return (
        normalized in {"example.com", "example.net", "example.org"}
        or normalized.endswith(
            (
                ".example.com",
                ".example.net",
                ".example.org",
                ".example",
                ".invalid",
                ".test",
            )
        )
    )


class RepositoryContractTest(unittest.TestCase):
    def test_root_agent_local_references_exist(self) -> None:
        text = ROOT_AGENT.read_text(encoding="utf-8")
        references = {
            value.rstrip("/")
            for value in re.findall(r"`([^`\n]+)`", text)
            if value.startswith(
                (
                    "agent/",
                    "precedent-auth.md",
                    "program.md",
                    "temporarytool/",
                    "tool/",
                )
            )
            and "YYYY-" not in value
        }

        self.assertGreater(len(references), 0)
        missing = sorted(
            reference
            for reference in references
            if not (REPO_ROOT / reference).exists()
        )
        self.assertEqual(missing, [])

    def test_root_agent_keeps_attention_routing_contract(self) -> None:
        text = ROOT_AGENT.read_text(encoding="utf-8")

        for forbidden in (
            "每次执行下一步操作之前",
            "`skills/hack-skill.md`",
            "每次操作重复读取",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("使用中文作为默认工作语言"), 1)
        self.assertFalse(any(pattern.search(text) for pattern in PERSONAL_PATH_PATTERNS))
        self.assertNotRegex(text, r"\b\d+\s*(?:个|项|种)\s*工具\b")

    def test_main_agent_stays_within_budget_and_routes_exist(self) -> None:
        text = MAIN_AGENT.read_text(encoding="utf-8")
        self.assertLessEqual(len(text.splitlines()), 260)

        route_section = text.split("## 一级路由", 1)[1].split(
            "## 主执行原则",
            1,
        )[0]
        route_targets = {
            value
            for value in re.findall(r"`([^`\n]+)`", route_section)
            if value.startswith("skills/") and value.endswith(".md")
        }
        self.assertGreater(len(route_targets), 0)
        missing = sorted(
            target
            for target in route_targets
            if not (MAIN_AGENT.parent / target).is_file()
        )
        self.assertEqual(missing, [])

    def test_pyproject_has_dependency_free_unittest_metadata(self) -> None:
        payload = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(payload["project"]["dependencies"], [])
        self.assertEqual(payload["tool"]["cybertest"]["tests"]["framework"], "unittest")
        self.assertEqual(
            payload["tool"]["cybertest"]["tests"]["start-directory"],
            "tests",
        )
        self.assertEqual(
            payload["tool"]["cybertest"]["tests"]["pattern"],
            "test_*.py",
        )

    def test_all_repository_schemas_are_json_and_versioned(self) -> None:
        schema_paths = sorted(SCHEMA_DIR.glob("*.schema.json"))
        self.assertGreater(len(schema_paths), 0)
        schema_ids: list[str] = []

        for path in schema_paths:
            with self.subTest(schema=path.name):
                schema = load_json_document(path)
                self.assertIsInstance(schema, dict)
                self.assertEqual(
                    schema.get("$schema"),
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertIsInstance(schema.get("$id"), str)
                self.assertTrue(schema["$id"].endswith(path.name))
                schema_ids.append(schema["$id"])

                properties = schema.get("properties", {})
                version_schema = properties.get("schema_version") or properties.get(
                    "route_version"
                )
                self.assertIsInstance(version_schema, dict)
                self.assertIsInstance(version_schema.get("const"), str)

        self.assertEqual(duplicate_values(schema_ids), set())

    def test_tactic_registry_is_complete_unique_and_schema_valid(self) -> None:
        index = load_json_document(TACTIC_DIR / "index.yaml")
        schema = load_json_document(SCHEMA_DIR / "tactic.schema.json")
        entries = index["tactics"]
        registry_ids = [entry["id"] for entry in entries]
        registry_paths = [entry["path"] for entry in entries]

        self.assertEqual(duplicate_values(registry_ids), set())
        self.assertEqual(duplicate_values(registry_paths), set())
        actual_paths = {
            path.relative_to(TACTIC_DIR).as_posix()
            for path in TACTIC_DIR.rglob("*.yaml")
            if path.name != "index.yaml"
        }
        self.assertEqual(set(registry_paths), actual_paths)

        capability_ids = {
            item["id"]
            for item in load_json_document(CAPABILITY_MANIFEST)["capabilities"]
        }
        for entry in entries:
            with self.subTest(tactic=entry["id"]):
                relative = Path(entry["path"])
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                document = load_json_document(TACTIC_DIR / relative)
                self.assertEqual(entry["id"], document["id"])
                assert_valid(document, schema, entry["id"])
                for requirement in document.get("required_capabilities", []):
                    self.assertIn(requirement["id"], capability_ids)

    def test_capability_manifest_is_json_compatible_and_unique(self) -> None:
        manifest = load_json_document(CAPABILITY_MANIFEST)
        self.assertEqual(manifest["schema_version"], "2.0")
        capabilities = manifest["capabilities"]
        capability_ids = [item["id"] for item in capabilities]
        self.assertEqual(duplicate_values(capability_ids), set())
        self.assertEqual(len(capability_ids), 6)

        known = set(capability_ids)
        for capability in capabilities:
            with self.subTest(capability=capability["id"]):
                self.assertIsInstance(capability["provides"], list)
                self.assertIsInstance(capability["fallbacks"], list)
                self.assertIsInstance(capability["detectors"], dict)
                self.assertTrue(capability["availability_requires"])
                for fallback in capability["fallbacks"]:
                    self.assertIn(fallback["capability"], known)

    def test_reusable_fixtures_contain_only_anonymous_identifiers(self) -> None:
        fixture_paths = sorted(
            path
            for root in (REPO_ROOT / "tests" / "fixtures", REPO_ROOT / "tests" / "golden")
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in TEXT_FIXTURE_SUFFIXES
        )
        self.assertGreater(len(fixture_paths), 0)
        symbolic_capability_ids = {
            item["id"]
            for item in load_json_document(CAPABILITY_MANIFEST)["capabilities"]
        }

        violations: list[str] = []
        for path in fixture_paths:
            text = path.read_text(encoding="utf-8", errors="replace")
            relative = path.relative_to(REPO_ROOT).as_posix()
            for pattern in PERSONAL_PATH_PATTERNS:
                if pattern.search(text):
                    violations.append(f"{relative}:personal-absolute-path")
            if PRIVATE_KEY_RE.search(text):
                violations.append(f"{relative}:private-key")
            if JWT_RE.search(text):
                violations.append(f"{relative}:jwt")

            for email in EMAIL_RE.findall(text):
                domain = email.rsplit("@", 1)[1]
                if not is_reserved_domain(domain):
                    violations.append(f"{relative}:email:{domain}")
            for domain in DOMAIN_RE.findall(text):
                normalized_domain = domain.lower()
                if (
                    not is_reserved_domain(domain)
                    and normalized_domain not in symbolic_capability_ids
                    and Path(normalized_domain).suffix
                    not in NON_DOMAIN_ARTIFACT_SUFFIXES
                ):
                    violations.append(f"{relative}:domain:{domain}")
            for raw_ip in IPV4_RE.findall(text):
                try:
                    address = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                if not any(address in network for network in ALLOWED_IPV4_NETWORKS):
                    violations.append(f"{relative}:ipv4:{raw_ip}")
            for raw_ip in IPV6_RE.findall(text):
                try:
                    address = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                if not any(address in network for network in ALLOWED_IPV6_NETWORKS):
                    violations.append(f"{relative}:ipv6:{raw_ip}")

        self.assertEqual(violations, [])

    def test_critical_cli_help_smoke(self) -> None:
        for script_name in CRITICAL_CLIS:
            with self.subTest(cli=script_name):
                completed = subprocess.run(
                    [sys.executable, str(TOOL_DIR / script_name), "--help"],
                    cwd=REPO_ROOT,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("usage:", completed.stdout.lower())

    def test_candidate_cli_keeps_v1_default_and_explicit_v2_switch(self) -> None:
        self.assertFalse(candidate_queue.parse_args([]).enable_tactics)
        self.assertTrue(
            candidate_queue.parse_args(["--enable-tactics"]).enable_tactics
        )

    def test_core_clis_remain_importable_as_tool_namespace_modules(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import tool.bounty_candidate_queue; "
                    "import tool.quality_gate; "
                    "import tool.scan_pipeline"
                ),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_core_modules_do_not_reverse_import_cli_facades(self) -> None:
        forbidden = (
            "import tool.scan_pipeline",
            "from tool import scan_pipeline",
            "import tool.quality_gate",
            "from tool import quality_gate",
            "import tool.bounty_candidate_queue",
            "from tool import bounty_candidate_queue",
        )
        violations: list[str] = []
        for path in sorted((TOOL_DIR / "cybertest_core").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for phrase in forbidden:
                if phrase in text:
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{phrase}"
                    )
        self.assertEqual(violations, [])

    def test_repository_markdown_relative_links_resolve(self) -> None:
        report = check_markdown_links.check_paths(
            check_markdown_links.DEFAULT_ROOTS,
            repo_root=REPO_ROOT,
        )

        self.assertTrue(report["ok"], report)
        self.assertEqual(report["broken_link_count"], 0)
        self.assertGreater(report["checked_local_link_count"], 0)


if __name__ == "__main__":
    unittest.main()
