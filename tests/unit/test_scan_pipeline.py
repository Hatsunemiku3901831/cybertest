from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tool import run_dynamic_validation
from tool.cybertest_core.schema_validation import assert_valid, load_json_document
from tool.scan_pipeline import (
    MODE_PHASES,
    NETWORK_PROFILES,
    PHASE_DAG,
    PHASE_DEPS,
    PHASE_REGISTRY,
    Pipeline,
    _available_capabilities,
    parse_args,
    run_candidate_queue,
    run_tactic_match,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "pipeline"


def make_pipeline(
    output_dir: Path,
    *,
    mode: str = "deep",
    network_profile: str = "internet-web",
    phases: str | None = None,
    dry_run: bool = False,
    capabilities: Path | None = None,
    materials: Path | None = None,
) -> Pipeline:
    argv = [
        "--authorized",
        "--domain",
        "example.test",
        "--mode",
        mode,
        "--network-profile",
        network_profile,
        "--output-dir",
        str(output_dir),
    ]
    if phases:
        argv.extend(["--phases", phases])
    if dry_run:
        argv.append("--dry-run")
    if capabilities:
        argv.extend(["--capabilities", str(capabilities)])
    if materials:
        argv.extend(["--materials", str(materials)])
    return Pipeline(parse_args(argv))


class ScanPipelineTest(unittest.TestCase):
    def test_capability_report_requires_healthy_v2_but_accepts_v1(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            v2_report = root / "v2.json"
            v2_report.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "capabilities": [
                            {
                                "capability": "browser.interactive",
                                "installed": True,
                                "healthy": False,
                                "available": False,
                                "health": "installed_only",
                            },
                            {
                                "capability": "http.replay",
                                "installed": True,
                                "healthy": False,
                                "available": True,
                                "health": "degraded",
                            },
                            {
                                "capability": "cli.http",
                                "installed": True,
                                "healthy": True,
                                "available": True,
                                "health": "ok",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            v1_report = root / "v1.json"
            v1_report.write_text(
                json.dumps(
                    {
                        "capabilities": [
                            {
                                "capability": "browser.interactive",
                                "available": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                _available_capabilities(v2_report),
                {"cli.http"},
            )
            self.assertEqual(
                _available_capabilities(v1_report),
                {"browser.interactive"},
            )

    def test_pipeline_candidate_phase_opts_into_v2_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_file = Path(temporary) / "candidate.json"
            captured: list[str] = []

            def fake_run(argv, timeout=None, **kwargs):
                captured.extend(argv)
                output_file.write_text(
                    json.dumps({"ok": True, "candidates": []}),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch("tool.scan_pipeline._run", side_effect=fake_run):
                result = run_candidate_queue(
                    pipeline_dir=Path(temporary),
                    output_file=output_file,
                    timeout=10,
                )

            self.assertTrue(result["ok"])
            self.assertIn("--enable-tactics", captured)

    def test_offline_sidecar_hash_is_deterministic_for_same_inputs(self) -> None:
        source = FIXTURES / "full-offline-replay.json"
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json"
            second = Path(temporary) / "second.json"
            runner = PHASE_REGISTRY["js_intel"]["runner"]

            first_result = runner(
                source_files=[source],
                output_file=first,
                timeout=10,
            )
            second_result = runner(
                source_files=[source],
                output_file=second,
                timeout=10,
            )

            self.assertTrue(first_result["ok"])
            self.assertTrue(second_result["ok"])
            first_payload = json.loads(first.read_text(encoding="utf-8"))
            second_payload = json.loads(second.read_text(encoding="utf-8"))
            self.assertEqual(
                first_payload["analysis_hash"],
                second_payload["analysis_hash"],
            )
            self.assertEqual(
                first_payload["observations"],
                second_payload["observations"],
            )
            self.assertEqual(
                first_payload["input_sources"],
                second_payload["input_sources"],
            )

    def test_all_modes_include_ordered_offline_semantic_stages(self) -> None:
        expected_offline = [
            "js_intel",
            "api_contract",
            "control_gap",
            "candidate_queue",
            "tactic_match",
            "semantic_quality_gate",
        ]
        for mode, phase_config in MODE_PHASES.items():
            with self.subTest(mode=mode):
                phases = list(phase_config)
                self.assertEqual(
                    [phase for phase in phases if phase in expected_offline],
                    expected_offline,
                )
                pipeline = make_pipeline(Path("/tmp") / mode, mode=mode)
                self.assertEqual(
                    [
                        phase
                        for phase in pipeline.phases
                        if phase in expected_offline
                    ],
                    expected_offline,
                )
                self.assertTrue(
                    set(
                        {
                            "browser_validate",
                            "burp_replay",
                            "js_runtime_validate",
                            "oast_check",
                        }
                    ).isdisjoint(pipeline.phases)
                )

        self.assertEqual(
            PHASE_DAG["tactic_match"]["depends_on"],
            ["candidate_queue", "js_intel", "api_contract"],
        )
        self.assertEqual(
            PHASE_DEPS["quality_gate"],
            PHASE_DAG["quality_gate"]["depends_on"],
        )
        self.assertIn("quality_gate", PHASE_REGISTRY)

    def test_explicit_semantic_subset_is_stably_topologically_ordered(self) -> None:
        pipeline = make_pipeline(
            Path("/tmp") / "semantic-order",
            phases=(
                "semantic_quality_gate,tactic_match,candidate_queue,"
                "control_gap,api_contract,js_intel"
            ),
        )

        self.assertEqual(
            pipeline.phases,
            [
                "js_intel",
                "api_contract",
                "control_gap",
                "candidate_queue",
                "tactic_match",
                "semantic_quality_gate",
            ],
        )

    def test_fresh_run_quality_gate_reads_current_candidate_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(
                output_dir,
                phases="quality_gate,candidate_queue",
            )
            events: list[str] = []
            candidate_visible: list[bool] = []

            def fake_candidate_queue(**kwargs):
                events.append("candidate_queue")
                payload = {"ok": True, "candidate_count": 0}
                Path(kwargs["output_file"]).write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                return {"ok": True, "result": payload}

            def fake_quality_gate(**kwargs):
                events.append("quality_gate")
                state = json.loads(
                    (Path(kwargs["pipeline_dir"]) / "pipeline_state.json")
                    .read_text(encoding="utf-8")
                )
                candidate = state["phase_outputs"].get("candidate_queue", {})
                candidate_visible.append(
                    candidate.get("status") == "completed"
                    and Path(candidate.get("output_file", "")).is_file()
                )
                payload = {"ok": True, "status": "PASS"}
                Path(kwargs["output_file"]).write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                return {"ok": True, "result": payload}

            with patch.dict(
                PHASE_REGISTRY["candidate_queue"],
                {"runner": fake_candidate_queue},
            ), patch.dict(
                PHASE_REGISTRY["quality_gate"],
                {"runner": fake_quality_gate},
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            self.assertEqual(events, ["candidate_queue", "quality_gate"])
            self.assertEqual(candidate_visible, [True])

    def test_dag_uses_recorded_output_and_unions_root_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="httpx")
            recorded = FIXTURES / "subfinder-with-results.json"
            state = {
                "phase_outputs": {
                    "subfinder": {
                        "phase_id": "subfinder",
                        "status": "completed",
                        "ok": True,
                        "output_file": str(recorded),
                        "input_sources": [],
                    }
                }
            }

            input_file, sources = pipeline._build_host_input_details(
                "httpx", state, output_dir / "input"
            )

            self.assertIsNotNone(input_file)
            self.assertEqual(
                input_file.read_text(encoding="utf-8").splitlines(),
                ["api.example.test", "example.test", "www.example.test"],
            )
            self.assertIn(str(recorded), sources)
            self.assertIn("root_domain:example.test", sources)
            self.assertEqual(PHASE_DAG["httpx"]["depends_on"], ["subfinder"])

    def test_empty_subfinder_still_probes_root_for_dnsx_and_httpx(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="dnsx,httpx")
            state = {
                "phase_outputs": {
                    "subfinder": {
                        "ok": True,
                        "output_file": str(FIXTURES / "subfinder-empty.json"),
                    }
                }
            }

            for phase in ("dnsx", "httpx"):
                with self.subTest(phase=phase):
                    input_file, sources = pipeline._build_host_input_details(
                        phase, state, output_dir / phase
                    )
                    self.assertIsNotNone(input_file)
                    self.assertEqual(
                        input_file.read_text(encoding="utf-8").splitlines(),
                        ["example.test"],
                    )
                    self.assertIn("root_domain:example.test", sources)

    def test_legacy_numbered_phase_directory_is_read_only_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir)
            legacy_output = output_dir / "phase_01_subfinder" / "result.json"
            legacy_output.parent.mkdir(parents=True)
            legacy_output.write_text(
                (FIXTURES / "subfinder-with-results.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )

            resolved = pipeline._phase_output_path(
                "subfinder", {"phase_outputs": {"subfinder": {"ok": True}}}
            )

            self.assertEqual(resolved, legacy_output)
            self.assertEqual(
                pipeline._phase_dir("subfinder"),
                output_dir / "phase_subfinder",
            )

    def test_only_lan_network_profile_selects_lan_fast(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            selected = {}
            for profile in NETWORK_PROFILES:
                pipeline = make_pipeline(base / profile, network_profile=profile)
                selected[profile] = pipeline._phase_overrides("nmap")["profile"]

            self.assertEqual(selected["lan"], "lan-fast")
            self.assertEqual(selected["internet-web"], "web")
            self.assertEqual(selected["internet-api"], "web")
            self.assertEqual(selected["mobile-api"], "web")

    def test_dry_run_does_not_execute_or_create_pipeline_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "dry-run"
            pipeline = make_pipeline(
                output_dir,
                network_profile="internet-api",
                dry_run=True,
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                result = pipeline.run()

            self.assertEqual(result, 0)
            self.assertIn("Network profile: internet-api", stdout.getvalue())
            self.assertIn("web", stdout.getvalue())
            self.assertFalse(pipeline.state_path.exists())

    def test_new_state_records_explicit_phase_metadata_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="subfinder")

            def fake_subfinder(**kwargs):
                payload = {"ok": True, "subdomains": []}
                Path(kwargs["output_file"]).write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                return {"ok": True, "result": payload}

            with patch.dict(
                PHASE_REGISTRY["subfinder"], {"runner": fake_subfinder}
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            state = json.loads(pipeline.state_path.read_text(encoding="utf-8"))
            phase = state["phase_outputs"]["subfinder"]
            self.assertEqual(phase["phase_id"], "subfinder")
            self.assertEqual(phase["status"], "completed")
            self.assertEqual(
                Path(phase["output_file"]),
                output_dir / "phase_subfinder" / "result.json",
            )
            self.assertEqual(phase["input_sources"], ["root_domain:example.test"])
            self.assertEqual(state["network_profile"], "internet-web")
            self.assertEqual(state["state_version"], "2.0")

    def test_old_state_is_normalized_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="subfinder,httpx")
            old_state = {
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "phases_requested": ["subfinder", "httpx"],
                "phases_completed": ["subfinder"],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {
                    "subfinder": {
                        "ok": True,
                        "output_file": "phase_01_subfinder/result.json",
                        "summary": "0 subdomains",
                    }
                },
            }
            output_dir.mkdir(parents=True, exist_ok=True)
            pipeline.state_path.write_text(
                json.dumps(old_state), encoding="utf-8"
            )

            loaded = pipeline.load_state()

            phase = loaded["phase_outputs"]["subfinder"]
            self.assertEqual(loaded["state_version"], "1.0")
            self.assertEqual(loaded["network_profile"], "internet-web")
            self.assertEqual(phase["phase_id"], "subfinder")
            self.assertEqual(phase["status"], "completed")
            self.assertEqual(phase["input_sources"], [])

    def test_resume_skips_completed_offline_phase_and_uses_recorded_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(
                output_dir,
                phases="api_contract,js_intel",
            )
            js_output = output_dir / "phase_js_intel" / "result.json"
            js_output.parent.mkdir(parents=True)
            js_output.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "schema_version": "1.0",
                        "observations": {
                            "api_references": [
                                "https://api.example.test/api/v1/users/1001"
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            state = {
                "state_version": "2.0",
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "network_profile": "internet-web",
                "phases_requested": ["js_intel", "api_contract"],
                "phases_completed": ["js_intel"],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {
                    "js_intel": {
                        "phase_id": "js_intel",
                        "status": "completed",
                        "ok": True,
                        "output_file": str(js_output),
                        "input_sources": [],
                    }
                },
            }
            pipeline.state_path.write_text(json.dumps(state), encoding="utf-8")

            with patch.dict(
                PHASE_REGISTRY["js_intel"],
                {
                    "runner": lambda **_kwargs: (_ for _ in ()).throw(
                        AssertionError("completed phase must not rerun")
                    )
                },
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            resumed = json.loads(
                pipeline.state_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                resumed["phases_completed"],
                ["js_intel", "api_contract"],
            )
            api_state = resumed["phase_outputs"]["api_contract"]
            self.assertEqual(api_state["input_sources"], [str(js_output)])
            self.assertEqual(len(api_state["output_sha256"]), 64)

    def test_failed_phase_resume_success_clears_historical_terminal_states(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="subfinder")
            state = {
                "state_version": "2.0",
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "network_profile": "internet-web",
                "phases_requested": ["subfinder"],
                "phases_completed": [],
                "phases_skipped": ["subfinder"],
                "phases_failed": ["subfinder"],
                "phase_outputs": {
                    "subfinder": {
                        "phase_id": "subfinder",
                        "status": "failed",
                        "ok": False,
                        "output_file": str(
                            output_dir / "phase_subfinder" / "result.json"
                        ),
                        "input_sources": ["root_domain:example.test"],
                    }
                },
            }
            output_dir.mkdir(parents=True, exist_ok=True)
            pipeline.state_path.write_text(json.dumps(state), encoding="utf-8")

            def successful_retry(**kwargs):
                payload = {"ok": True, "subdomains": []}
                Path(kwargs["output_file"]).write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                return {"ok": True, "result": payload}

            with patch.dict(
                PHASE_REGISTRY["subfinder"],
                {"runner": successful_retry},
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            resumed = json.loads(
                pipeline.state_path.read_text(encoding="utf-8")
            )
            self.assertEqual(resumed["phases_completed"], ["subfinder"])
            self.assertEqual(resumed["phases_skipped"], [])
            self.assertEqual(resumed["phases_failed"], [])
            summary = json.loads(
                (output_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertTrue(summary["ok"])

    def test_load_state_repairs_completed_phase_with_stale_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, phases="subfinder")
            phase_output = (
                output_dir / "phase_subfinder" / "result.json"
            )
            phase_output.parent.mkdir(parents=True)
            phase_output.write_text(
                json.dumps({"ok": True, "subdomains": []}),
                encoding="utf-8",
            )
            state = {
                "state_version": "2.0",
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "network_profile": "internet-web",
                "phases_requested": ["subfinder"],
                "phases_completed": ["subfinder"],
                "phases_skipped": [],
                "phases_failed": ["subfinder"],
                "phase_outputs": {
                    "subfinder": {
                        "phase_id": "subfinder",
                        "status": "completed",
                        "ok": True,
                        "output_file": str(phase_output),
                        "input_sources": ["root_domain:example.test"],
                    }
                },
            }
            pipeline.state_path.write_text(json.dumps(state), encoding="utf-8")

            with patch.dict(
                PHASE_REGISTRY["subfinder"],
                {
                    "runner": lambda **_kwargs: (_ for _ in ()).throw(
                        AssertionError("completed phase must not rerun")
                    )
                },
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            resumed = json.loads(
                pipeline.state_path.read_text(encoding="utf-8")
            )
            self.assertEqual(resumed["phases_completed"], ["subfinder"])
            self.assertEqual(resumed["phases_failed"], [])
            self.assertTrue(
                json.loads(
                    (output_dir / "summary.json").read_text(encoding="utf-8")
                )["ok"]
            )

    def test_tactic_match_counts_only_explicit_route_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            candidate_source = (
                base / "phase_candidate_queue" / "result.json"
            )
            candidate_source.parent.mkdir(parents=True)
            candidate_source.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "schema_version": "2.0",
                        "candidates": [
                            {
                                "id": "BC-MATCHED",
                                "route_status": "matched",
                                "route_decision_id": "RD-MATCHED",
                                "matched_tactics": [{"id": "TACTIC-MATCHED"}],
                            },
                            {
                                "id": "BC-GAP",
                                "route_status": "route_gap",
                                "route_decision_id": "RD-GAP",
                                "matched_tactics": [],
                            },
                            {
                                "id": "BC-BLOCKED",
                                "route_status": "blocked_need_material",
                                "route_decision_id": "RD-BLOCKED",
                                "resume_tactic_id": "TACTIC-RESUME",
                                "matched_tactics": [],
                            },
                            {
                                "id": "BC-POLICY",
                                "route_status": "policy_conflict",
                                "route_decision_id": "RD-POLICY",
                                "matched_tactics": [],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output_file = base / "phase_tactic_match" / "result.json"
            output_file.parent.mkdir(parents=True)

            result = run_tactic_match(
                source_files=[candidate_source],
                output_file=output_file,
                timeout=10,
            )

            self.assertTrue(result["ok"])
            observations = result["result"]["observations"]
            self.assertEqual(observations["route_gap_count"], 1)
            self.assertEqual(observations["matched_candidate_count"], 1)
            blocked = next(
                item
                for item in observations["matches"]
                if item["candidate_id"] == "BC-BLOCKED"
            )
            self.assertEqual(blocked["resume_tactic_id"], "TACTIC-RESUME")

    def test_old_early_quality_result_is_recomputed_after_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(
                output_dir,
                phases="quality_gate,candidate_queue",
            )
            old_state = {
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "phases_requested": ["quality_gate", "candidate_queue"],
                "phases_completed": ["quality_gate"],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {
                    "quality_gate": {
                        "ok": True,
                        "output_file": "phase_quality_gate/result.json",
                    }
                },
            }
            output_dir.mkdir(parents=True, exist_ok=True)
            pipeline.state_path.write_text(
                json.dumps(old_state), encoding="utf-8"
            )

            loaded = pipeline.load_state()

            self.assertEqual(
                pipeline.phases,
                ["candidate_queue", "quality_gate"],
            )
            self.assertEqual(
                loaded["phases_requested"],
                ["candidate_queue", "quality_gate"],
            )
            self.assertNotIn("quality_gate", loaded["phases_completed"])
            self.assertNotIn("quality_gate", loaded["phase_outputs"])

    def test_completed_legacy_order_requeues_only_quality_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(
                output_dir,
                phases="quality_gate,candidate_queue",
            )
            old_state = {
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "quick",
                "phases_requested": ["quality_gate", "candidate_queue"],
                "phases_completed": ["quality_gate", "candidate_queue"],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {
                    "candidate_queue": {
                        "ok": True,
                        "output_file": "phase_candidate_queue/result.json",
                    },
                    "quality_gate": {
                        "ok": True,
                        "output_file": "phase_quality_gate/result.json",
                    },
                },
            }
            output_dir.mkdir(parents=True, exist_ok=True)
            pipeline.state_path.write_text(
                json.dumps(old_state), encoding="utf-8"
            )

            loaded = pipeline.load_state()

            self.assertEqual(
                loaded["phases_completed"],
                ["candidate_queue"],
            )
            self.assertIn("candidate_queue", loaded["phase_outputs"])
            self.assertNotIn("quality_gate", loaded["phase_outputs"])

    def test_full_mode_offline_fixture_replay_closes_pipeline_contract(self) -> None:
        fixture = json.loads(
            (FIXTURES / "full-offline-replay.json").read_text(encoding="utf-8")
        )
        fixture_phases = set(fixture)
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary)
            pipeline = make_pipeline(output_dir, mode="full")
            events: list[str] = []

            def fixture_runner(phase_id):
                def run(**kwargs):
                    events.append(phase_id)
                    payload = fixture[phase_id]
                    Path(kwargs["output_file"]).write_text(
                        json.dumps(payload), encoding="utf-8"
                    )
                    return {"ok": payload.get("ok", False), "result": payload}

                return run

            def observed_runner(phase_id, original):
                def run(**kwargs):
                    events.append(phase_id)
                    return original(**kwargs)

                return run

            with contextlib.ExitStack() as stack:
                for phase_id in pipeline.phases:
                    runner = PHASE_REGISTRY[phase_id]["runner"]
                    replacement = (
                        fixture_runner(phase_id)
                        if phase_id in fixture_phases
                        else observed_runner(phase_id, runner)
                    )
                    stack.enter_context(
                        patch.dict(
                            PHASE_REGISTRY[phase_id],
                            {"runner": replacement},
                        )
                    )
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                result = pipeline.run()

            self.assertEqual(result, 0)
            self.assertEqual(events, pipeline.phases)
            self.assertEqual(
                [
                    phase
                    for phase in events
                    if phase
                    in {
                        "js_intel",
                        "api_contract",
                        "control_gap",
                        "candidate_queue",
                        "tactic_match",
                        "semantic_quality_gate",
                    }
                ],
                [
                    "js_intel",
                    "api_contract",
                    "control_gap",
                    "candidate_queue",
                    "tactic_match",
                    "semantic_quality_gate",
                ],
            )
            self.assertTrue(
                {
                    "browser_validate",
                    "burp_replay",
                    "js_runtime_validate",
                    "oast_check",
                }.isdisjoint(events)
            )

            state = json.loads(pipeline.state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["phases_completed"], pipeline.phases)
            for phase_id in (
                "js_intel",
                "api_contract",
                "control_gap",
                "tactic_match",
            ):
                with self.subTest(phase=phase_id):
                    phase_state = state["phase_outputs"][phase_id]
                    output_path = Path(phase_state["output_file"])
                    self.assertTrue(output_path.is_file())
                    self.assertTrue(phase_state["input_sources"])
                    self.assertEqual(len(phase_state["output_sha256"]), 64)
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                    self.assertEqual(payload["analysis_mode"], "offline")
                    self.assertEqual(len(payload["analysis_hash"]), 64)
                    self.assertTrue(payload["input_sources"])
                    self.assertTrue(
                        all(
                            len(source["sha256"]) == 64
                            for source in payload["input_sources"]
                        )
                    )

            semantic = state["phase_outputs"]["semantic_quality_gate"]
            self.assertEqual(semantic["status"], "completed")
            self.assertIn(
                str(
                    output_dir
                    / "phase_tactic_match"
                    / "result.json"
                ),
                semantic["input_sources"],
            )

    def test_optional_dynamic_phase_blocks_without_tactic_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "pipeline"
            capabilities = Path(temporary) / "capabilities.json"
            materials = Path(temporary) / "materials.json"
            capabilities.write_text(
                json.dumps(
                    {
                        "capabilities": [
                            {
                                "capability": "browser.interactive",
                                "available": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            materials.write_text(
                json.dumps(
                    {
                        "available_materials": [
                            "target_url",
                            "authorized_test_session",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            pipeline = make_pipeline(
                output_dir,
                phases="browser_validate",
                capabilities=capabilities,
                materials=materials,
            )

            with patch(
                "tool.scan_pipeline._run",
                side_effect=AssertionError("dynamic plan must not invoke tools"),
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            payload = json.loads(
                (
                    output_dir
                    / "phase_browser_validate"
                    / "result.json"
                ).read_text(encoding="utf-8")
            )
            observations = payload["observations"]
            self.assertEqual(payload["analysis_mode"], "dynamic_plan_only")
            self.assertEqual(
                observations["execution_status"],
                "blocked_need_route",
            )
            self.assertIsNone(observations["route_binding"])
            self.assertEqual(observations["eligible_route_count"], 0)
            self.assertFalse(observations["execution_performed"])
            self.assertFalse(observations["automatic_execution"])

    def test_optional_dynamic_phase_binds_matched_route_before_ready(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_dir = root / "pipeline"
            capabilities = root / "capabilities.json"
            materials = root / "materials.json"
            capabilities.write_text(
                json.dumps(
                    {
                        "capabilities": [
                            {
                                "capability": "browser.interactive",
                                "available": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            materials.write_text(
                json.dumps(
                    {
                        "available_materials": [
                            "target_url",
                            "authorized_test_session",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            tactic_output = (
                output_dir / "phase_tactic_match" / "result.json"
            )
            tactic_output.parent.mkdir(parents=True)
            tactic_output.write_text(
                json.dumps(
                    {
                        "ok": True,
                        "phase_id": "tactic_match",
                        "observations": {
                            "matches": [
                                {
                                    "candidate_id": "BC-BOUND",
                                    "route_status": "matched",
                                    "route_decision_id": "RD-BOUND",
                                    "matched_tactics": [
                                        {"id": "TACTIC-BOUND"}
                                    ],
                                    "resume_tactic_id": None,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            pipeline = make_pipeline(
                output_dir,
                phases="tactic_match,browser_validate",
                capabilities=capabilities,
                materials=materials,
            )
            state = {
                "state_version": "2.0",
                "started_at": "2026-01-01T00:00:00Z",
                "domain": "example.test",
                "mode": "deep",
                "network_profile": "internet-web",
                "phases_requested": [
                    "tactic_match",
                    "browser_validate",
                ],
                "phases_completed": ["tactic_match"],
                "phases_skipped": [],
                "phases_failed": [],
                "phase_outputs": {
                    "tactic_match": {
                        "phase_id": "tactic_match",
                        "status": "completed",
                        "ok": True,
                        "output_file": str(tactic_output),
                        "input_sources": [],
                    }
                },
            }
            pipeline.state_path.write_text(
                json.dumps(state), encoding="utf-8"
            )

            with patch(
                "tool.scan_pipeline._run",
                side_effect=AssertionError("dynamic plan must not invoke tools"),
            ), contextlib.redirect_stdout(io.StringIO()):
                result = pipeline.run()

            self.assertEqual(result, 0)
            payload = json.loads(
                (
                    output_dir
                    / "phase_browser_validate"
                    / "result.json"
                ).read_text(encoding="utf-8")
            )
            observations = payload["observations"]
            self.assertEqual(
                observations["execution_status"],
                "ready_for_plan_completion",
            )
            self.assertEqual(
                observations["route_binding"],
                {
                    "candidate_id": "BC-BOUND",
                    "tactic_id": "TACTIC-BOUND",
                    "route_decision_id": "RD-BOUND",
                    "route_status": "matched",
                },
            )
            draft = observations["dynamic_validation_plan"]
            self.assertEqual(draft["plan_status"], "draft")
            self.assertFalse(draft["policy"]["permitted"])
            assert_valid(
                draft,
                load_json_document(
                    ROOT
                    / "agent"
                    / "schemas"
                    / "dynamic-validation-plan.schema.json"
                ),
                "pipeline dynamic plan draft",
            )
            loaded_draft = run_dynamic_validation.load_plan(
                output_dir
                / "phase_browser_validate"
                / "result.json"
            )
            self.assertEqual(loaded_draft, draft)
            self.assertEqual(
                run_dynamic_validation.assess_plan(loaded_draft)["status"],
                "blocked_need_plan_completion",
            )

    def test_optional_dynamic_phase_resumes_blocked_route_only_after_requirement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tactic_output = root / "phase_tactic_match" / "result.json"
            tactic_output.parent.mkdir(parents=True)
            tactic_output.write_text(
                json.dumps(
                    {
                        "phase_id": "tactic_match",
                        "observations": {
                            "matches": [
                                {
                                    "candidate_id": "BC-RESUME",
                                    "route_status": "blocked_need_material",
                                    "route_decision_id": "RD-RESUME",
                                    "matched_tactics": [],
                                    "resume_tactic_id": "TACTIC-RESUME",
                                    "missing_materials": [
                                        "controlled_test_account"
                                    ],
                                    "missing_capabilities": [],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            capabilities = root / "capabilities.json"
            capabilities.write_text(
                json.dumps(
                    {
                        "capabilities": [
                            {
                                "capability": "browser.interactive",
                                "available": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            materials = root / "materials.json"
            materials.write_text(
                json.dumps(
                    {
                        "available_materials": [
                            "target_url",
                            "authorized_test_session",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            blocked_output = root / "blocked-dynamic-plan.json"
            blocked = PHASE_REGISTRY["browser_validate"]["runner"](
                source_files=[tactic_output],
                output_file=blocked_output,
                timeout=10,
                phase_id="browser_validate",
                capabilities_file=capabilities,
                materials_file=materials,
            )
            self.assertTrue(blocked["ok"])
            self.assertEqual(
                blocked["result"]["observations"]["execution_status"],
                "blocked_need_route",
            )
            self.assertIsNone(
                blocked["result"]["observations"]["route_binding"]
            )

            materials.write_text(
                json.dumps(
                    {
                        "available_materials": [
                            "target_url",
                            "authorized_test_session",
                            "controlled_test_account",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output_file = root / "dynamic-plan.json"

            result = PHASE_REGISTRY["browser_validate"]["runner"](
                source_files=[tactic_output],
                output_file=output_file,
                timeout=10,
                phase_id="browser_validate",
                capabilities_file=capabilities,
                materials_file=materials,
            )

            self.assertTrue(result["ok"])
            observations = result["result"]["observations"]
            self.assertEqual(
                observations["execution_status"],
                "ready_for_plan_completion",
            )
            self.assertEqual(
                observations["route_binding"],
                {
                    "candidate_id": "BC-RESUME",
                    "tactic_id": "TACTIC-RESUME",
                    "route_decision_id": "RD-RESUME",
                    "route_status": "blocked_need_material",
                    "resumed_requirements": {
                        "materials": ["controlled_test_account"],
                        "capabilities": [],
                    },
                },
            )
            self.assertEqual(
                observations["dynamic_validation_plan"]["plan_status"],
                "draft",
            )


if __name__ == "__main__":
    unittest.main()
