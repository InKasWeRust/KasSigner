#!/usr/bin/env python3
"""Regression contracts for every M5Stack and Waveshare hardware adapter."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks/quality/crap"))

from source_complexity import function_decisions  # noqa: E402

BOARD_ROOTS = (
    "apps/signer-firmware/src/hw/m5stack",
    "apps/signer-firmware/src/hw/waveshare",
)


class AllBoardAdapterComplexityTests(unittest.TestCase):
    def test_every_production_board_function_stays_at_cc_four_or_less(self) -> None:
        offenders: list[str] = []
        for relative_root in BOARD_ROOTS:
            for path in (ROOT / relative_root).rglob("*.rs"):
                if "unit_tests" in path.parts:
                    continue
                relative = path.relative_to(ROOT).as_posix()
                for record in function_decisions(path.read_text(), relative):
                    if record.decisions > 4:
                        offenders.append(
                            f"{relative}:{record.line} {record.name}={record.decisions}"
                        )
        self.assertEqual(offenders, [])

    def test_board_loops_and_state_decisions_are_owned_by_shared_helpers(self) -> None:
        ownership = {
            "crates/signer-firmware-core/src/storage/retry.rs": (
                "poll_sdhost_command",
                "poll_r1_response",
                "poll_ready_response",
            ),
            "crates/signer-firmware-core/src/storage/card.rs": (
                "classify_card_kind",
                "classify_card_state",
                "command_frame",
            ),
            "crates/signer-firmware-core/src/power/sequencing.rs": (
                "run_register_writes",
            ),
            "crates/signer-firmware-core/src/camera/registers.rs": (
                "write_pairs",
                "write_banked",
            ),
            "crates/signer-firmware-core/src/camera/dma.rs": (
                "plan_decode_submission",
                "descriptor_action",
                "copy_sample_with",
            ),
            "crates/signer-firmware-core/src/presentation/audio.rs": (
                "fill_stereo_square_wave",
                "fill_stereo_tick",
            ),
            "crates/signer-firmware-core/src/input/recovery.rs": (
                "run_i2c_recovery",
            ),
        }
        for relative, fragments in ownership.items():
            source = (ROOT / relative).read_text()
            for fragment in fragments:
                self.assertIn(fragment, source, f"{relative} lacks {fragment}")


if __name__ == "__main__":
    unittest.main()
