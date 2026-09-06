#!/usr/bin/env python3
"""Regression tests for board-owned firmware layouts and final-image identity."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
BOARD_LAYOUT_PATH = ROOT / "tools/build/firmware/board_layout.py"
VERIFY_IMAGE_PATH = ROOT / "tools/build/firmware/verify_image_hash.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BOARD_LAYOUT = load_module("board_layout_contract", BOARD_LAYOUT_PATH)
VERIFY_IMAGE = load_module("verify_image_contract", VERIFY_IMAGE_PATH)


class FirmwareBoardLayoutTests(unittest.TestCase):
    def test_m5stack_cores3_layout_is_dual_ota_and_preserves_state_tail(self) -> None:
        layout = BOARD_LAYOUT.layout_for("m5stack")
        BOARD_LAYOUT.validate_layout(layout)
        self.assertEqual(layout.app_offset, 0x10000)
        self.assertEqual(layout.app_size, 0x200000)
        self.assertEqual(layout.flash_size_bytes, 0x1000000)
        self.assertEqual(layout.state_offset, 0xFFC000)
        self.assertEqual(layout.state_size, 0x4000)
        self.assertEqual(layout.state_offset + layout.state_size, layout.flash_size_bytes)
        args = layout.espflash_args()
        self.assertEqual(
            layout.espflash_connection_args(),
            ["--chip", "esp32s3", "--before", "usb-reset"],
        )
        self.assertIn("--partition-table", args)
        self.assertIn("--target-app-partition", args)
        self.assertIn("ota_0", args)
        self.assertIn("16mb", args)
        rows = BOARD_LAYOUT._read_partitions(layout.partition_path())
        by_name = {row[0]: row for row in rows}
        self.assertEqual(by_name["otadata"], ("otadata", "data", "ota", 0xD000, 0x2000))
        self.assertEqual(by_name["ota_0"], ("ota_0", "app", "ota_0", 0x10000, 0x200000))
        self.assertEqual(by_name["ota_1"], ("ota_1", "app", "ota_1", 0x210000, 0x200000))
        self.assertNotIn("factory", by_name)

    def test_waveshare_boards_reserve_persistent_state_tail(self) -> None:
        for board in ("waveshare", "waveshare-af"):
            layout = BOARD_LAYOUT.layout_for(board)
            BOARD_LAYOUT.validate_layout(layout)
            self.assertEqual(
                layout.partition_table,
                "apps/signer-firmware/partitions/waveshare-esp32s3-touch-lcd-2.csv",
            )
            self.assertEqual(layout.flash_size_bytes, 0x1000000)
            self.assertEqual(layout.app_offset, 0x10000)
            self.assertEqual(layout.app_size, 0xFEC000)
            self.assertEqual(layout.state_offset, 0xFFC000)
            self.assertEqual(layout.state_size, 0x4000)
            self.assertEqual(layout.state_offset + layout.state_size, layout.flash_size_bytes)
            args = layout.espflash_args()
            self.assertEqual(layout.espflash_connection_args(), ["--chip", "esp32s3"])
            self.assertIn("--partition-table", args)
            self.assertIn("--target-app-partition", args)
            self.assertIn("factory", args)
            self.assertIn("16mb", args)
            rows = BOARD_LAYOUT._read_partitions(layout.partition_path())
            by_name = {row[0]: row for row in rows}
            self.assertEqual(
                by_name["factory"],
                ("factory", "app", "factory", 0x10000, 0xFEC000),
            )
            if board == "m5stack":
                self.assertEqual(
                    by_name["kassigner_qa"],
                    ("kassigner_qa", "data", "undefined", 0xFF8000, 0x4000),
                )
            self.assertEqual(
                by_name["kassigner_state"],
                ("kassigner_state", "data", "undefined", 0xFFC000, 0x4000),
            )

    def test_firmware_update_partition_hashes_match_board_csvs(self) -> None:
        # Runtime SD/QR firmware updating is intentionally retired. Partition identity
        # is now bound by host release tooling and the shared board-layout helper.
        generator = (ROOT / "tools/firmware/gen_update_manifest.rs").read_text()
        self.assertIn("partition_hash(board, &args[7])", generator)
        self.assertIn("partition_layout_hash", generator)
        self.assertFalse((ROOT / "apps/signer-firmware/src/services/fw_update/layout.rs").exists())
        m5 = BOARD_LAYOUT.partition_sha256(BOARD_LAYOUT.layout_for("m5stack"))
        wave = BOARD_LAYOUT.partition_sha256(BOARD_LAYOUT.layout_for("waveshare"))
        wave_af = BOARD_LAYOUT.partition_sha256(BOARD_LAYOUT.layout_for("waveshare-af"))
        self.assertIsNotNone(m5)
        self.assertIsNotNone(wave)
        self.assertEqual(wave, wave_af)

    def test_layout_validator_rejects_state_overlap_or_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_root = Path(temporary)
            relative = Path("apps/signer-firmware/partitions/m5stack-cores3.csv")
            destination = fake_root / relative
            destination.parent.mkdir(parents=True)
            original = (ROOT / relative).read_text()
            destination.write_text(original.replace("0xFFC000, 0x4000", "0x20F000, 0x4000"))
            layout = BOARD_LAYOUT.layout_for("m5stack")
            with mock.patch.object(BOARD_LAYOUT, "ROOT", fake_root):
                with self.assertRaisesRegex(ValueError, "overlaps|remain at"):
                    BOARD_LAYOUT.validate_layout(layout)


class FinalImageIdentityTests(unittest.TestCase):
    def _fixture(self, root: Path, *, mutate_hash: bool = False) -> tuple[Path, Path, str]:
        segment = bytes((index * 17 + 3) & 0xFF for index in range(257))
        address = 0x42010020
        image = bytearray(24)
        image[0] = 0xE9
        image[1] = 1
        image.extend(address.to_bytes(4, "little"))
        image.extend(len(segment).to_bytes(4, "little"))
        image.extend(segment)
        image_path = root / "app.bin"
        image_path.write_bytes(image)
        digest = hashlib.sha256(segment).digest()
        embedded = bytearray(digest)
        if mutate_hash:
            embedded[0] ^= 0x01
        values = ", ".join(f"0x{value:02x}" for value in embedded)
        source = root / "firmware_hash.rs"
        source.write_text(
            "pub static EXPECTED_FIRMWARE_HASH: [u8; 32] = [\n"
            f"    {values}\n"
            "];\n"
            f"pub static FIRMWARE_SIZE: usize = {len(segment)};\n"
            f"pub static FIRMWARE_IADDR: u32 = 0x{address:08X};\n"
        )
        return image_path, source, digest.hex()

    def test_final_image_verifier_binds_address_length_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image, source, expected = self._fixture(Path(temporary))
            self.assertEqual(VERIFY_IMAGE.verify(image, source), expected)

    def test_final_image_verifier_rejects_hash_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image, source, _ = self._fixture(Path(temporary), mutate_hash=True)
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                VERIFY_IMAGE.verify(image, source)


if __name__ == "__main__":
    unittest.main()
