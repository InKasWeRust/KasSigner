#!/usr/bin/env python3
"""Regression coverage for board-storage transport ownership."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.firmware.subsystems.firmware_storage import (  # noqa: E402
    _check_transport_owner_imports,
)


WAVESHARE_LEAVES = (
    "routing.rs", "clock.rs", "command.rs", "initialization.rs",
    "block.rs", "multi_block.rs", "multi_block/fifo.rs", "boot.rs",
)
M5_LEAVES = ("block.rs", "multi_block.rs", "card.rs", "mod.rs")


class FirmwareTransportOwnerTests(unittest.TestCase):
    def _root(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        ws = root / "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost"
        m5 = root / "apps/signer-firmware/src/hw/m5stack/storage/transport"
        ws.mkdir(parents=True)
        m5.mkdir(parents=True)
        for name in WAVESHARE_LEAVES:
            path = ws / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("use super::super::registers::{SDHOST_CTRL};\n")
        for name in M5_LEAVES:
            (m5 / name).write_text("// CoreS3 shared-SPI transport leaf\n")
        protocol = m5 / "protocol"
        protocol.mkdir()
        (protocol / "mod.rs").write_text("mod wire;\n")
        (protocol / "initialization.rs").write_text("// SD initialization\n")
        (protocol / "wire.rs").write_text(
            "crate::hw::m5stack::spi_bus::with_sd_selected(false, |_| Ok(()));\n"
        )
        return temporary, root

    def test_accepts_direct_owner_imports(self) -> None:
        temporary, root = self._root()
        with temporary:
            self.assertEqual(_check_transport_owner_imports(root), [])

    def test_rejects_wildcard_inheritance(self) -> None:
        temporary, root = self._root()
        with temporary:
            target = root / (
                "apps/signer-firmware/src/hw/waveshare/storage/"
                "transport/sdhost/block.rs"
            )
            target.write_text("use super::*;\n")
            errors = _check_transport_owner_imports(root)
            self.assertTrue(any("register owner" in error for error in errors))
            self.assertTrue(any("wildcard inheritance" in error for error in errors))

    def test_rejects_m5_raw_spi2_bypass(self) -> None:
        temporary, root = self._root()
        with temporary:
            target = root / "apps/signer-firmware/src/hw/m5stack/storage/transport/block.rs"
            target.write_text("const SPI2_CLOCK_REG: u32 = 0x6002_400C;\n")
            errors = _check_transport_owner_imports(root)
            self.assertTrue(any("bypasses the shared SPI2 owner" in error for error in errors))


    def test_real_protocol_helpers_reach_transport_siblings_without_crate_widening(self) -> None:
        protocol = ROOT / "apps/signer-firmware/src/hw/m5stack/storage/transport/protocol"
        facade = (protocol / "mod.rs").read_text()
        initialization = (protocol / "initialization.rs").read_text()
        wire = (protocol / "wire.rs").read_text()
        visibility = "pub(in crate::hw::m5stack::storage::transport)"

        self.assertIn("pub(super) use initialization::initialize_card;", facade)
        self.assertIn(f"{visibility} fn initialize_card", initialization)
        for helper in (
            "command_data", "finish_transaction", "read_exact",
            "require_success", "transfer_byte", "write_all",
        ):
            self.assertIn(f"{visibility} fn {helper}", wire)
        self.assertNotIn("pub(crate) fn initialize_card", initialization)
        self.assertNotIn("pub(crate) fn command_data", wire)


if __name__ == "__main__":
    unittest.main()
