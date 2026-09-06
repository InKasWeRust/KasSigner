from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class WorkflowRuntimeParityTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")


    def test_main_no_longer_short_circuits_production_startup_for_workflow(self):
        main = self.read("apps/signer-firmware/src/main.rs")
        self.assertNotIn("workflow_tests::take_over!", main)
        self.assertNotIn("workflow_runtime_watchdog", main)
        self.assertIn("runtime::signing::run_firmware_verify", main)
        self.assertIn("boot::application::enforce_boot_known_answer_tests", main)
        self.assertIn("runtime::event_loop::runner::run", main)

    def test_workflow_gate_is_after_authoritative_runner_startup(self):
        runner = self.read("apps/signer-firmware/src/runtime/event_loop/runner.rs")
        auto = self.read("apps/signer-firmware/src/runtime/event_loop/runner/workflow_auto.rs")
        startup = runner.index("persistent_wallet.prepare_startup(ad)")
        startup_nav = runner.index("apply_startup_navigation", startup)
        startup_ui = runner.index("startup_ui::render", startup_nav)
        gate = runner.index("workflow_auto::run", startup_ui)
        normal_loop = runner.index("super::run!", gate)
        self.assertLess(startup, startup_nav)
        self.assertLess(startup_nav, startup_ui)
        self.assertLess(startup_ui, gate)
        self.assertLess(gate, normal_loop)
        self.assertIn("workflow_tests::run_connected_gate", auto)
        self.assertIn("workflow_tests::park_after_gate", auto)
        self.assertIn('#[cfg(not(feature = "workflow-test-auto"))]\n    {', runner)

    def test_workflow_build_uses_same_development_test_signing_key(self):
        workflow = self.read("qa/checks/firmware/run_workflow_tests.py")
        helper = self.read("scripts/common/lib/make_tasks.py")
        marker = 'tools" / "build" / "firmware" / "dev_test_signing_key.bin"'
        self.assertIn(marker, workflow)
        self.assertIn('dev_test_signing_key.bin', helper)
        self.assertIn('env["KASSIGNER_SIGNING_KEY"]', workflow)
        self.assertIn('env["KASSIGNER_SIGNING_KEY"]', helper)

    def test_rejection_dismissal_follows_production_return_owner(self):
        signing = self.read("apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs")
        self.assertIn("dismiss_rejected_to(AppState::ScanQR)", signing)
        self.assertIn("camera_loop::route_camera_back(self.ad)", signing)
        self.assertIn("dismiss_rejected_to(AppState::ConfirmTx)", signing)
        self.assertIn("self.tx_touch(20, 20, true)", signing)
        self.assertIn("zone_center(crate::ui::layout::ERROR_OK_ZONE)", signing)

    def test_runtime_gui_change_probe_uses_shared_visible_zone(self):
        gui = self.read("apps/signer-firmware/src/runtime/workflow_tests/connected/runtime_gui.rs")
        self.assertIn("zone_center(crate::ui::layout::ADDRESS_CHAIN_ZONE)", gui)
        self.assertNotIn("TouchInput::new(160, 190, false)", gui)

    def test_runtime_kpub_probe_preserves_production_operation_order(self):
        gui = self.read("apps/signer-firmware/src/runtime/workflow_tests/connected/runtime_gui.rs")
        deferred = self.read("apps/signer-firmware/src/runtime/event_loop/runner/deferred.rs")

        connect = gui[gui.index("fn probe_connect_kassee("):gui.index("fn probe_multisig_kpub(")]
        # Connect queues the operation as part of the root action, so it gets exactly
        # one loading render before the workflow driver begins real derivation.
        before_drive = connect[:connect.index("workflow_drive_connect_kassee")]
        self.assertEqual(before_drive.count("render(ad, display, i2c, sd, delay, watchdog_feed);"), 1)

        driver = deferred[deferred.index("fn workflow_drive_kpub_export("):deferred.index("pub(crate) fn workflow_drive_connect_kassee")]
        presented = driver.index("OperationPhase::Presented")
        take_ready = driver.index("take_ready_operation", presented)
        worker = driver.index("kpub::service_operation", take_ready)
        self.assertLess(presented, take_ready)
        self.assertLess(take_ready, worker)
        self.assertIn("OperationPhase::Running | OperationPhase::Progress(_)", driver)

    def test_two_input_signing_replays_real_progress_redraw_lifecycle(self):
        redraw = self.read("apps/signer-firmware/src/ui/redraw/presentation/mod.rs")
        adapter = self.read("apps/signer-firmware/src/runtime/signing/workflow_test.rs")
        connected = self.read("apps/signer-firmware/src/runtime/workflow_tests/connected/signing/result.rs")

        self.assertIn("if ad.presentation.operation.phase() == OperationPhase::Queued", redraw)
        self.assertEqual(redraw.count("mark_operation_presented(ad)"), 1)
        self.assertIn("OperationPhase::Running | OperationPhase::Progress(_)", adapter)
        self.assertIn("presentation::set_progress(ad, progress.min(100) as u8)", adapter)
        self.assertIn("workflow_activate_signing_operation", adapter)
        first = connected.index("OperationPhase::Progress(50)")
        redraw_progress = connected.index("ctx.redraw();", first)
        retained = connected.index("OperationPhase::Progress(50)", redraw_progress)
        second_step = connected.index("workflow_signing_step(ctx.ad)", retained)
        self.assertLess(first, redraw_progress)
        self.assertLess(redraw_progress, retained)
        self.assertLess(retained, second_step)
        self.assertIn("SIGN TX LIFECYCLE PROGRESS-REDRAW 1/2 PASS", connected)

    def test_workflow_gate_keeps_monitor_only_as_explicit_runtime_exception(self):
        main = self.read("apps/signer-firmware/src/main.rs")
        # Auto E2E must retain the serial monitor; this is an intentional test-I/O
        # difference, not a UI/navigation/runtime shortcut.
        self.assertIn('not(any(feature = "hardware-tests", feature = "workflow-test-auto"))', main)
        self.assertIn("post_boot_lockdown", main)


if __name__ == "__main__":
    unittest.main()
