from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkflowCameraOwnershipTests(unittest.TestCase):
    def test_workflow_profile_runs_only_after_authoritative_production_startup(self):
        main = (ROOT / "apps/signer-firmware/src/main.rs").read_text()
        runner = (ROOT / "apps/signer-firmware/src/runtime/event_loop/runner.rs").read_text()
        auto = (ROOT / "apps/signer-firmware/src/runtime/event_loop/runner/workflow_auto.rs").read_text()
        harness = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/mod.rs").read_text()
        self.assertNotIn('runtime::workflow_tests::take_over!(', main)
        self.assertNotIn('macro_rules! take_over', harness)
        prepare = runner.index('persistent_wallet.prepare_startup(ad)')
        nav = runner.index('apply_startup_navigation(ad, startup)')
        render = runner.index('startup_ui::render(')
        connected = runner.index('workflow_auto::run(')
        self.assertLess(prepare, nav)
        self.assertLess(nav, render)
        self.assertLess(render, connected)
        self.assertIn('crate::runtime::workflow_tests::run_connected_gate(', auto)
        self.assertIn('crate::runtime::workflow_tests::park_after_gate(', auto)

    def test_runtime_workflow_persistence_is_redirected_to_dedicated_qa_flash(self):
        main = (ROOT / "apps/signer-firmware/src/main.rs").read_text()
        flash = (ROOT / "apps/signer-firmware/src/services/persistent_wallet/flash.rs").read_text()
        partitions = (ROOT / "apps/signer-firmware/partitions/m5stack-cores3.csv").read_text()
        self.assertIn('let (persistent_hmac, persistent_flash) = (peripherals.HMAC, peripherals.FLASH);', main)
        self.assertIn('#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]\nconst STATE_BASE: u32 = FLASH_SIZE - 8 * SECTOR_SIZE;', flash)
        self.assertIn('#[cfg(not(all(feature = "m5stack", feature = "workflow-runtime-auto")))]\nconst STATE_BASE: u32 = FLASH_SIZE - 4 * SECTOR_SIZE;', flash)
        self.assertIn('kassigner_qa,       data, undefined, 0xFF8000, 0x4000,', partitions)
        self.assertIn('kassigner_state,    data, undefined, 0xFFC000, 0x4000,', partitions)

    def test_m5stack_workflow_profile_marks_minimal_board_boundary_before_optional_peripherals(self):
        source = (ROOT / "apps/signer-firmware/src/boot/m5stack/mod.rs").read_text()
        workflow_cfg = source.index('#[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]\n        {')
        board_done = source.index('KASSIGNER_WORKFLOW_TESTS: BOARD PHASES COMPLETE', workflow_cfg)
        production_cfg = source.index('#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]', board_done)
        audio_begin = source.index('I2S1 hardware peripheral init...', production_cfg)
        camera_done = source.index('$crate::boot::m5stack::camera::finish_sensor_status(cam_status);', production_cfg)
        self.assertLess(workflow_cfg, board_done)
        self.assertLess(board_done, production_cfg)
        self.assertLess(production_cfg, audio_begin)
        self.assertLess(audio_begin, camera_done)

    def test_connected_gate_parks_in_test_harness_instead_of_entering_app_loop(self):
        source = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/mod.rs").read_text()
        self.assertIn('pub(crate) fn park_after_gate(', source)
        self.assertIn('watchdog_feed: &mut impl FnMut()', source)
        self.assertIn('KASSIGNER_WORKFLOW_TESTS: HARNESS PARKED', source)
        self.assertIn('delay.delay_millis(1_000);', source)

    def test_supervisor_fails_fast_if_minimal_board_handoff_stalls(self):
        runner = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text()
        supervisor = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
        self.assertIn('phase_start_marker="BOOT PHASE startup-ui DONE:"', runner)
        self.assertIn('phase_end_marker="KASSIGNER_WORKFLOW_TESTS: CONNECTED GATE BEGIN"', runner)
        self.assertIn('phase_timeout=15', runner)
        self.assertIn('stalled after {phase_start_marker!r}', supervisor)


if __name__ == "__main__":
    unittest.main()
