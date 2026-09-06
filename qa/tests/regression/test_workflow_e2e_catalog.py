#!/usr/bin/env python3
"""Regression contracts for the developer-only firmware workflow E2E harness."""
from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
CATALOG = FW / "src/runtime/workflow_tests/catalog"
STATE = FW / "src/runtime/input/state.rs"
HARNESS_STATES = {"WorkflowTestsMenu", "WorkflowTestsCategory", "WorkflowTestsResult"}


def app_state_variants() -> set[str]:
    text = STATE.read_text()
    marker = "pub enum AppState {"
    start = text.index(marker) + len(marker)
    depth = 1
    index = start
    while depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    body = text[start:index - 1]
    variants: set[str] = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#")):
            continue
        match = re.match(r"([A-Z][A-Za-z0-9_]*)\b", stripped)
        if match:
            variants.add(match.group(1))
    return variants


def catalog_text() -> str:
    return "\n".join(path.read_text() for path in sorted(CATALOG.glob("*.rs")))


class WorkflowE2ECatalogTests(unittest.TestCase):
    def test_workflow_test_facade_exports_only_symbols_used_outside_submodules(self) -> None:
        facade = (FW / "src/runtime/workflow_tests/mod.rs").read_text()
        self.assertNotIn("WorkflowFixtures", facade)
        self.assertNotIn("WorkflowSpec", facade)
        self.assertNotIn("pub(crate) use runner::{run_all", facade)
        self.assertIn("pub(crate) use runner::WorkflowSummary", facade)

    def test_every_user_facing_app_state_is_owned_by_a_workflow(self) -> None:
        catalog = catalog_text()
        missing = sorted(
            state for state in app_state_variants() - HARNESS_STATES
            if not re.search(rf"\b{re.escape(state)}\b", catalog)
        )
        self.assertEqual(missing, [])

    def test_workflow_ids_are_unique_stable_and_every_spec_declares_fixtures(self) -> None:
        concrete = "\n".join(
            path.read_text() for path in sorted(CATALOG.glob("*.rs")) if path.name != "mod.rs"
        )
        ids = re.findall(r'id\s*:\s*"([a-z0-9-]+)"', concrete)
        specs = re.findall(r"\bWorkflowSpec\s*\{", concrete)
        fixtures = re.findall(r"\bfixtures\s*:", concrete)
        self.assertGreater(len(ids), 50)
        self.assertEqual(len(ids), len(specs))
        self.assertEqual(len(ids), len(fixtures))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value) for value in ids))

    def test_each_category_fits_shared_menu_capacity_with_run_category_entry(self) -> None:
        for path in sorted(CATALOG.glob("*.rs")):
            if path.name == "mod.rs":
                continue
            count = len(re.findall(r"\bWorkflowSpec\s*\{", path.read_text()))
            self.assertLessEqual(count + 1, 16, path.name)
        catalog = (CATALOG / "mod.rs").read_text()
        self.assertIn('menu.items[0] = "Run Category";', catalog)

    def test_harness_is_test_only_and_compile_checked_on_both_boards(self) -> None:
        manifest = tomllib.loads((FW / "Cargo.toml").read_text())
        self.assertIn("workflow-tests", manifest["features"])
        policy = (FW / "src/feature_policy.rs").read_text()
        self.assertIn('feature = "workflow-tests"', policy)
        self.assertIn("developer/QA firmware features are forbidden in production/silent builds", policy)
        matrix = (ROOT / "tools/build/firmware/build_matrix.py").read_text()
        self.assertIn('FirmwareBuild("waveshare,workflow-tests", PSRAM_OCTAL)', matrix)
        self.assertIn('FirmwareBuild("m5stack,workflow-tests")', matrix)

    def test_catalog_runner_uses_production_navigation_policy_without_preboard_smoke(self) -> None:
        runner = (FW / "src/runtime/workflow_tests/runner.rs").read_text()
        self.assertIn("workflow_owner_for", runner)
        self.assertIn("workflow_transition_allowed", runner)
        self.assertIn("workflow_input_route_valid", runner)
        self.assertNotIn("run_root_input_smoke", runner)
        self.assertNotIn("ContactGate::new()", runner)
        self.assertNotIn("TouchEventType::Contact", runner)
        self.assertNotIn("AppData", runner)
        self.assertNotIn("seed_mgr", runner)
        self.assertNotIn("signing_key", runner)
        self.assertNotIn("navigation.app.state =", runner)

    def test_tools_catalog_runner_and_connected_auto_gate_have_separate_roles(self) -> None:
        controller = (FW / "src/runtime/interactions/workflow_tests.rs").read_text()
        main = (FW / "src/main.rs").read_text()
        harness = (FW / "src/runtime/workflow_tests/mod.rs").read_text()
        connected = "\n".join(
            path.read_text() for path in sorted((FW / "src/runtime/workflow_tests/connected").glob("*.rs"))
        )
        harness_all = harness + "\n" + connected
        command = (FW / "src/runtime/workflow_tests/command.rs").read_text()
        self.assertIn("WorkflowCommand::RunAll", controller)
        self.assertIn("WorkflowCommand::RunCategory", controller)
        self.assertIn("WorkflowCommand::RunOne", controller)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]', main)
        self.assertIn("runtime::workflow_tests::run_boot_gate()", main)
        self.assertNotIn("report_boot_gate", main)
        self.assertNotIn("execute(WorkflowCommand::RunAll)", harness)
        self.assertNotIn("run_root_input_smoke", harness)
        self.assertIn("KASSIGNER_WORKFLOW_TESTS: BEGIN", harness)
        self.assertIn("KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE", harness)
        self.assertIn("run_connected_gate", harness)
        self.assertNotIn("SHADOW_GATE_OK", harness)
        self.assertIn("CONNECTED GATE BEGIN", harness)
        self.assertIn("TOUCH PROBE BEGIN", harness_all)
        self.assertIn("TOUCH PROBE OK", harness_all)
        derivation = (FW / "src/runtime/signing/derivation.rs").read_text()
        signing = (FW / "src/runtime/signing.rs").read_text()
        self.assertIn("install_workflow_receive_fixture(ad)", harness_all)
        self.assertIn("RECEIVE PUBLIC FIXTURE READY", harness_all)
        self.assertIn('pub(crate) fn install_workflow_receive_fixture', derivation)
        self.assertIn("const GENERATOR_X: [u8; 32]", derivation)
        self.assertIn("ad.wallet.addresses.pubkey_cache.fill(GENERATOR_X)", derivation)
        self.assertIn("ad.wallet.addresses.change_pubkey_cache.fill(GENERATOR_X)", derivation)
        self.assertIn("ad.wallet.addresses.pubkeys_cached = true", derivation)
        fixture = derivation.split("pub(crate) fn install_workflow_receive_fixture", 1)[1].split("/// Populate receive/change", 1)[0]
        self.assertNotIn("seed_mgr", fixture)
        self.assertNotIn("private", fixture.lower())
        self.assertIn('pub(crate) use derivation::install_workflow_receive_fixture;', signing)
        self.assertIn("ROOT TILE {} DWELL OK", harness_all)
        self.assertNotIn("ROOT TILE {} HOME BEGIN", harness_all)
        self.assertIn("ROOT TILE {} HOME ROUTE OK", harness_all)
        self.assertNotIn("run_catalog_gate", harness)
        self.assertNotIn("runner::run_category", harness)
        self.assertNotIn("CATALOG COMPLETE", harness)
        self.assertIn("RUNTIME GUI NAVIGATION BEGIN", harness)
        self.assertIn("CONTROLLER NAVIGATION BEGIN", harness)
        connected_gate = harness.split("pub(crate) fn run_connected_gate(", 1)[1]
        self.assertLess(connected_gate.index("CONNECTED GATE BEGIN"), connected_gate.index("CONTROLLER NAVIGATION BEGIN"))
        self.assertNotIn("runner::", connected_gate)
        self.assertIn("SCREEN_DWELL_MS", harness_all)
        self.assertIn("handle_connected_root_probe", harness_all)
        self.assertIn("SETTINGS EXHAUSTIVE ROOT BEGIN", harness_all)
        self.assertIn("SETTINGS ROOT ITEMS PASS 6/6", harness_all)
        self.assertIn("SETTINGS PAGING BOUNDARIES OK", harness_all)
        self.assertIn("SETTINGS DISPLAY BOUNDARIES/HIL OK", harness_all)
        self.assertIn("RECEIVE CONTROLS PASS", harness_all)
        self.assertIn("RECEIVE CUSTOM INDEX OK", harness_all)
        self.assertIn("handle_display_settings_navigation", harness_all)
        self.assertIn("apply_requested_brightness", harness_all)
        self.assertIn("handle_settings_menu_navigation", harness_all)
        self.assertIn("AppState::DisplaySettings", harness_all)
        self.assertIn("SETTINGS AUDIO BOUNDARIES OK", harness_all)
        self.assertIn("AppState::AudioSettings", harness_all)
        self.assertIn("SETTINGS OUTSIDE-ITEM NOOP OK", harness_all)
        self.assertIn("CONNECTED HOME/ROOT PASS", harness_all)
        self.assertIn("handle_audio_settings_navigation", harness_all)
        self.assertIn("AppState::AudioSettings", harness_all)
        self.assertIn("WALLET MANAGEMENT BEGIN", harness_all)
        self.assertIn("WALLET MANAGEMENT PASS", harness_all)
        self.assertIn("AppState::ShowAddress", harness_all)
        self.assertIn("AppState::SeedsMenu", harness_all)
        self.assertIn("CONNECTED ROOT NAV PASS 4/4", harness)
        self.assertIn("KASSIGNER_WORKFLOW_TESTS: PASS ALL", harness)
        early_gate = harness.split("pub(crate) fn run_boot_gate()", 1)[1].split("}\n\n", 1)[0]
        self.assertNotIn("KASSIGNER_WORKFLOW_TESTS: PASS", early_gate)
        self.assertNotIn("runner::", early_gate)
        self.assertNotIn("execute(", early_gate)
        self.assertNotIn("Atomic", early_gate)
        self.assertNotIn("for ", early_gate)
        self.assertNotIn("while ", early_gate)
        self.assertNotIn("if ", early_gate)
        self.assertIn("pub(crate) fn execute", command)
        self.assertNotIn("ad.navigation.app.state =", controller)


    def test_connected_receive_scenario_is_reachable_and_host_registry_matches_firmware(self) -> None:
        connected_mod = (FW / "src/runtime/workflow_tests/connected/mod.rs").read_text()
        runner = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text()
        receive = (FW / "src/runtime/workflow_tests/connected/receive.rs").read_text()

        rust_block = connected_mod.split("const CONNECTED_TRANCHES", 1)[1].split("];", 1)[0]
        rust_names = re.findall(r'\("([A-Z0-9-]+)",\s*[a-z_]+::exercise\)', rust_block)
        python_block = runner.split("CONNECTED_TRANCHES = (", 1)[1].split(")\nWORKFLOW_FAILURE_CONTEXT_PREFIXES", 1)[0]
        python_names = re.findall(r'"([A-Z0-9-]+)"', python_block)

        self.assertEqual(rust_names, python_names)
        self.assertEqual(rust_names[-1], "RECEIVE")
        self.assertIn('("RECEIVE", receive::exercise)', connected_mod)
        self.assertIn('"receive": 11', runner)
        self.assertIn('"11" => 10', connected_mod)
        self.assertIn("handle_connected_root_probe", receive)
        self.assertIn("workflow_wallet_select(ad, 0)", receive)
        self.assertIn("AppState::ShowAddress", receive)
        self.assertIn("handle_navigation_touch", receive)

    def test_development_menu_and_headless_autorun_are_separate_features(self) -> None:
        manifest = (FW / "Cargo.toml").read_text()
        main = (FW / "src/main.rs").read_text()
        make_helper = (ROOT / "scripts/common/lib/make_tasks.py").read_text()
        runner = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text()
        self.assertIn('developer-ui = []', manifest)
        self.assertIn('workflow-tests = ["developer-ui", "provisioning-ui"]', manifest)
        self.assertNotIn('workflow-tests = ["verbose-boot"]', manifest)
        self.assertIn('workflow-test-auto = ["workflow-tests"]', manifest)
        self.assertIn('workflow-runtime-auto = ["workflow-test-auto"]', manifest)
        self.assertIn('workflow-hil-auto = ["workflow-runtime-auto"]', manifest)
        self.assertRegex(main, r'#\[cfg\(feature = "workflow-test-auto"\)\]\s+runtime::workflow_tests::run_boot_gate\(\);')
        self.assertNotIn('#[cfg(feature = "workflow-tests")]\n    let workflow_test_summary = runtime::workflow_tests::run_boot_gate();', main)
        self.assertIn('features = "m5stack,workflow-tests,argon2-bench"', make_helper)
        self.assertIn('profile = "workflow-hil-auto" if hil else ("workflow-runtime-auto" if board == "m5stack" else "workflow-test-auto")', runner)
        self.assertIn('f"{feature},{profile}"', runner)

    def test_connected_runner_reuses_existing_serial_monitor_supervision(self) -> None:
        runner = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text()
        harness = (FW / "src/runtime/workflow_tests/mod.rs").read_text()
        self.assertIn("from run_hardware_tests import flash_and_monitor", runner)
        self.assertIn("KASSIGNER_WORKFLOW_TESTS: PASS", runner)
        self.assertIn('profile = "workflow-hil-auto" if hil else ("workflow-runtime-auto" if board == "m5stack" else "workflow-test-auto")', runner)
        self.assertIn('f"{feature},{profile}"', runner)
        main = (FW / "src/main.rs").read_text()
        self.assertIn('not(any(feature = "hardware-tests", feature = "workflow-test-auto"))', main)
        gate_at = main.index("runtime::workflow_tests::run_boot_gate();")
        startup_at = main.index("runtime::unit_tests::boot::run_startup_tests")
        board_at = main.index("boot::m5stack::initialize!")
        event_runner = (FW / "src/runtime/event_loop/runner.rs").read_text()
        connected_at = event_runner.index("workflow_auto::run(")
        startup_prepare_at = event_runner.index("persistent_wallet.prepare_startup(ad)")
        startup_render_at = event_runner.index("startup_ui::render(")
        self.assertLess(gate_at, startup_at)
        self.assertLess(gate_at, board_at)
        self.assertNotIn("runtime::workflow_tests::take_over!", main)
        self.assertLess(startup_prepare_at, startup_render_at)
        self.assertLess(startup_render_at, connected_at)
        self.assertNotIn('$crate::runtime::secret_state::initialize();', harness)
        self.assertNotIn('alloc::boxed::Box::new(crate::runtime::data::AppData::new())', harness)
        self.assertIn('#[inline(never)]\npub(crate) fn run_connected_gate', harness)
        self.assertIn('status_interval=10', runner)
        self.assertIn('repeat_abort_marker="KASSIGNER_WORKFLOW_TESTS: BEGIN"', runner)
        self.assertIn('phase_start_marker="BOOT PHASE startup-ui DONE:"', runner)
        self.assertIn('phase_end_marker="KASSIGNER_WORKFLOW_TESTS: CONNECTED GATE BEGIN"', runner)
        self.assertIn('phase_timeout=15', runner)
        self.assertIn('[workflow-e2e 1/4]', runner)
        self.assertIn('[workflow-e2e 4/4]', runner)
        supervisor = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
        self.assertNotIn("stdin=subprocess.DEVNULL", supervisor)
        self.assertIn("private_monitor_input", supervisor)
        self.assertIn("stdin=monitor_stdin", supervisor)
        self.assertIn("preserved_terminal", supervisor)
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("workflow-e2e:", makefile)
        self.assertIn('workflow-e2e "$(BOARD)" "$(PORT)"', makefile)

    def test_workflow_test_modules_stay_grouped_and_small(self) -> None:
        direct_files = list((FW / "src/runtime/workflow_tests").glob("*.rs"))
        catalog_files = list(CATALOG.glob("*.rs"))
        self.assertLessEqual(len(direct_files), 12)
        self.assertLessEqual(len(catalog_files), 12)
        for path in [*direct_files, *catalog_files, FW / "src/runtime/interactions/workflow_tests.rs"]:
            lines = path.read_text().count("\n") + 1
            self.assertLessEqual(lines, 450, f"{path.relative_to(ROOT)}: {lines}")

    def test_headless_run_all_keeps_serial_io_out_of_inner_workflow_loop(self) -> None:
        runner = (FW / "src/runtime/workflow_tests/runner.rs").read_text()
        run_all = runner.split("pub(crate) fn run_all(", 1)[1].split("fn validate_group", 1)[0]
        group = runner.split("fn validate_group", 1)[1].split("fn validate_and_log", 1)[0]
        self.assertIn("WorkflowCategory::ALL", run_all)
        self.assertIn("E2E SUMMARY", run_all)
        self.assertEqual(run_all.count("log!("), 1)
        self.assertNotIn("validate_and_log", run_all)
        self.assertNotIn("log!(", group)

    def test_on_device_workflow_commands_keep_runtime_watchdog_alive(self) -> None:
        controller = (FW / "src/runtime/interactions/workflow_tests.rs").read_text()
        command = (FW / "src/runtime/workflow_tests/command.rs").read_text()
        runner = (FW / "src/runtime/workflow_tests/runner.rs").read_text()
        dispatch = (FW / "src/runtime/event_loop/dispatch.rs").read_text()
        navigation_dispatch = (FW / "src/runtime/event_loop/navigation_dispatch.rs").read_text()
        touch_routes = (FW / "src/runtime/event_loop/touch_routes.rs").read_text()
        core = (FW / "src/runtime/core_s3.rs").read_text()

        self.assertIn("liveness: &mut dyn FnMut()", controller)
        self.assertGreaterEqual(controller.count("workflow_tests::execute("), 3)
        self.assertIn("liveness: &mut dyn FnMut()", command)
        self.assertIn("runner::run_all(liveness)", command)
        run_all = runner.split("pub(crate) fn run_all(", 1)[1].split("fn validate_group", 1)[0]
        group = runner.split("fn validate_group", 1)[1].split("fn validate_and_log", 1)[0]
        self.assertGreaterEqual(run_all.count("liveness();"), 2)
        self.assertIn("liveness();", group)
        self.assertNotIn("log!(", group)
        self.assertIn("&mut $watchdog_feed, input", dispatch)
        self.assertIn("liveness: &mut dyn FnMut()", navigation_dispatch)
        self.assertIn("&mut $watchdog_feed, input", touch_routes)
        self.assertIn("30_000", core)

    def test_connected_supervisor_fails_fast_on_device_panic(self) -> None:
        monitor = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
        self.assertIn("====================== PANIC", monitor)
        self.assertIn("panicked at ", monitor)
        self.assertIn("Guru Meditation Error", monitor)
        self.assertIn("panic detected; capturing the diagnostic tail before aborting", monitor)
        self.assertIn("diagnostic tail captured", monitor)

    def test_dead_code_diagnostics_apply_to_all_firmware_feature_profiles(self) -> None:
        shared_security = (FW / "src/boot/shared/security.rs").read_text()
        lockdown = (FW / "src/hw/shared/lockdown.rs").read_text()
        fixtures = (CATALOG / "mod.rs").read_text()
        gate = '#[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]'
        self.assertIn(gate, shared_security)
        self.assertGreaterEqual(lockdown.count(gate), 2)
        self.assertIn('#[cfg(feature = "waveshare")]\n    pub(crate) const CAMERA_TUNING', fixtures)
        harness = (FW / "src/runtime/workflow_tests/mod.rs").read_text()
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub(crate) fn run_boot_gate()', harness)
        self.assertNotIn('report_boot_gate', harness)
        main = (FW / "src/main.rs").read_text()
        self.assertIn('#![deny(unused_imports)]', main)
        self.assertIn('#![warn(dead_code)]', main)
        self.assertNotRegex(main, r"#!\s*\[.*allow\s*\(\s*dead_code\s*\).*")
        self.assertIn('any(not(feature = "hardware-tests"), feature = "m5stack")', main)
        self.assertIn('use crate::runtime::data::AppData;', main)
        runner = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text()
        self.assertIn('target" / "qa" / "workflow-e2e" / "build.log"', runner)
        self.assertIn('workflow firmware produced', runner)
        self.assertIn('warnings are release-blocking', runner)
        self.assertIn('workflow firmware build failed; complete log', runner)
        self.assertIn('Compiler error summary:', runner)
        self.assertIn('print_compiler_error_summary()', runner)


if __name__ == "__main__":
    unittest.main()


class ProductionRootReachabilityTests(unittest.TestCase):
    def test_user_capabilities_are_validated_from_main_menu_not_fixture_entry(self) -> None:
        import sys
        architecture_root = ROOT / "qa/checks"
        if str(architecture_root) not in sys.path:
            sys.path.insert(0, str(architecture_root))
        from architecture.firmware import firmware_workflows

        errors = firmware_workflows._check_production_root_reachability(ROOT)
        self.assertEqual(errors, [], "\n".join(errors))
        checker = (ROOT / "qa/checks/architecture/firmware/firmware_workflows.py").read_text()
        self.assertIn('graph_path = root / "qa/config/workflow/production_ui_graph.json"', checker)
        self.assertIn('required_actions = {', checker)
        self.assertIn('"settings.advanced.firmware_update": "FirmwareUpdateReady"', checker)
        self.assertIn('"settings.advanced.pop_it": "PopItPrompt"', checker)
        self.assertIn('"multisig.kpub": "MultisigMenu"', checker)
        self.assertIn('_reachable(route_graph, target)', checker)

    def test_workflow_runner_does_not_claim_fixture_start_establishes_reachability(self) -> None:
        runner = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/runner.rs").read_text()
        self.assertIn("fixture execution does not establish production reachability", runner)
        self.assertNotIn("reachable workflow", runner.lower())
