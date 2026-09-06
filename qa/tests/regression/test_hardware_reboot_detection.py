from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def test_reboot_detector_arms_only_after_flash_completion_and_persists_across_reconnects():
    supervisor = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text()
    assert "repeat_abort_marker and flash_complete" in supervisor
    assert 'repeat_key = f"__repeat_abort__:{repeat_abort_marker}"' in supervisor
    assert "repeat_key in seen_markers" in supervisor
    assert "seen_markers.add(repeat_key)" in supervisor
    assert "repeat_abort_arm_marker" in supervisor
    assert "duplicate/replayed" in supervisor


def test_workflow_begin_and_preboard_markers_have_no_firmware_work_between_them():
    workflow = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/mod.rs").read_text()
    begin = workflow.index('log!("KASSIGNER_WORKFLOW_TESTS: BEGIN");')
    preboard = workflow.index('log!("KASSIGNER_WORKFLOW_TESTS: PREBOARD GATE COMPLETE");')
    between = workflow[begin:preboard]
    assert between.count("log!(") == 1
    assert "delay" not in between
    assert "watchdog" not in between
