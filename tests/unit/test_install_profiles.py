from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRE = ROOT / "require"
MAC_INSTALLER = REQUIRE / "install_macos.sh"
WINDOWS_INSTALLER = REQUIRE / "install_windows.ps1"
WINDOWS_CMD = REQUIRE / "install_windows.cmd"
PROFILES = REQUIRE / "profiles.json"
MAC_LOG = REQUIRE / "install_macos.log"
PERSONAL_PATH_RE = re.compile(
    r"/" + "Users/" + r"|[A-Z]:\\" + "Users" + r"\\"
)


def file_snapshot(path: Path) -> tuple[bool, bytes | None, int | None]:
    if not path.exists():
        return False, None, None
    stat = path.stat()
    return True, path.read_bytes(), stat.st_mtime_ns


class InstallProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile_data = json.loads(PROFILES.read_text(encoding="utf-8"))

    def test_profile_manifest_is_portable_and_has_expected_profiles(self) -> None:
        self.assertEqual(self.profile_data["schema_version"], "1.0")
        self.assertEqual(self.profile_data["default_profile"], "full")
        self.assertEqual(
            set(self.profile_data["profiles"]),
            {"minimal", "web", "full", "reverse"},
        )

        command_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
        for name, profile in self.profile_data["profiles"].items():
            with self.subTest(profile=name):
                commands = profile["commands"]
                self.assertTrue(commands)
                self.assertEqual(len(commands), len(set(commands)))
                self.assertTrue(all(command_pattern.fullmatch(item) for item in commands))
                self.assertNotRegex(json.dumps(profile), PERSONAL_PATH_RE)

    def test_macos_help_keeps_legacy_flags_and_exposes_new_modes(self) -> None:
        result = subprocess.run(
            ["bash", str(MAC_INSTALLER), "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for flag in (
            "--profile",
            "--detect",
            "--dry-run",
            "--update-path",
            "--with-casks",
            "--skip-brew",
            "--skip-go-tools",
            "--skip-python-tools",
            "--skip-path-update",
        ):
            self.assertIn(flag, result.stdout)

    def test_macos_dry_run_is_side_effect_free_and_matches_profiles(self) -> None:
        before_log = file_snapshot(MAC_LOG)
        with tempfile.TemporaryDirectory() as temporary:
            temp_root = Path(temporary)
            fake_bin = temp_root / "bin"
            fake_home = temp_root / "home"
            sentinel = temp_root / "external-command-called"
            fake_bin.mkdir()
            fake_home.mkdir()

            for name in ("brew", "curl", "go", "pipx"):
                wrapper = fake_bin / name
                wrapper.write_text(
                    "#!/bin/sh\n"
                    'printf "%s\\n" "$0" >> "$CYBERTEST_TEST_SENTINEL"\n'
                    "exit 97\n",
                    encoding="utf-8",
                )
                wrapper.chmod(0o755)

            environment = dict(os.environ)
            environment.update(
                {
                    "HOME": str(fake_home),
                    "PATH": f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                    "CYBERTEST_TEST_SENTINEL": str(sentinel),
                }
            )

            for profile_name, profile in self.profile_data["profiles"].items():
                with self.subTest(profile=profile_name):
                    result = subprocess.run(
                        [
                            "bash",
                            str(MAC_INSTALLER),
                            "--dry-run",
                            "--profile",
                            profile_name,
                            "--update-path",
                        ],
                        cwd=ROOT,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"profile={profile_name}", result.stdout)
                    reported = {
                        line.split(maxsplit=1)[1]
                        for line in result.stdout.splitlines()
                        if line.startswith(("present  ", "planned  ", "missing  "))
                    }
                    self.assertEqual(reported, set(profile["commands"]))
                    self.assertNotIn(str(ROOT), result.stdout)
                    self.assertNotRegex(result.stdout, PERSONAL_PATH_RE)

            self.assertFalse(sentinel.exists())
            self.assertEqual(list(fake_home.iterdir()), [])

        self.assertEqual(file_snapshot(MAC_LOG), before_log)

    def test_macos_detect_is_read_only_and_invalid_profile_fails(self) -> None:
        before_log = file_snapshot(MAC_LOG)
        detect = subprocess.run(
            ["bash", str(MAC_INSTALLER), "--detect", "--profile", "minimal"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        invalid = subprocess.run(
            ["bash", str(MAC_INSTALLER), "--dry-run", "--profile", "unknown"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(detect.returncode, 0, detect.stderr)
        self.assertIn("mode=detect profile=minimal", detect.stdout)
        self.assertNotIn(str(ROOT), detect.stdout)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(file_snapshot(MAC_LOG), before_log)

    def test_windows_installer_has_equivalent_read_only_contract(self) -> None:
        source = WINDOWS_INSTALLER.read_text(encoding="utf-8")

        self.assertIn('[ValidateSet("minimal", "web", "full", "reverse")]', source)
        for flag in (
            "[switch]$Detect",
            "[switch]$DryRun",
            "[switch]$UpdatePath",
            "[switch]$SkipWinget",
            "[switch]$SkipGoTools",
            "[switch]$SkipPythonTools",
            "[switch]$NoPathUpdate",
        ):
            self.assertIn(flag, source)
        self.assertLess(source.index("if ($Detect)"), source.index("Set-Content -Path $LogPath"))
        self.assertLess(source.index("if ($DryRun)"), source.index("Set-Content -Path $LogPath"))
        self.assertIn("if ($UpdatePath -and -not $NoPathUpdate)", source)
        self.assertNotIn("if (-not $NoPathUpdate)", source)
        self.assertIn("No installation, network access, PATH update, or log write", source)
        for profile_name, profile in self.profile_data["profiles"].items():
            with self.subTest(profile=profile_name):
                match = re.search(
                    rf'"{profile_name}"\s*\{{\s*return @\((.*?)\)\s*\}}',
                    source,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(match)
                commands = set(re.findall(r'"([^"]+)"', match.group(1)))
                self.assertEqual(commands, set(profile["commands"]))

    def test_windows_cmd_forwards_profiles_without_pausing_read_only_modes(self) -> None:
        source = WINDOWS_CMD.read_text(encoding="utf-8")

        self.assertIn("install_windows.ps1", source)
        self.assertIn("%*", source)
        self.assertIn("-Detect", source)
        self.assertIn("-DryRun", source)
        self.assertIn('if "%skip_pause%"=="0" pause', source)

    def test_docs_lead_with_detection_and_capability_recheck(self) -> None:
        documentation = (
            (ROOT / "README.md").read_text(encoding="utf-8")
            + (REQUIRE / "require.md").read_text(encoding="utf-8")
        )

        self.assertIn("--detect --profile web", documentation)
        self.assertIn("-Detect -Profile web", documentation)
        self.assertIn("tool/detect_capabilities.py --dry-run", documentation)
        self.assertIn("--update-path", documentation)
        self.assertIn("-UpdatePath", documentation)


if __name__ == "__main__":
    unittest.main()
