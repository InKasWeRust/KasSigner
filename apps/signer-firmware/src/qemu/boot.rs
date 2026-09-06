// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! QEMU board-bootstrap stub.
//!
//! The ROM and second-stage ESP bootloader remain real because QEMU boots a
//! complete ESP32-S3 flash image. This module replaces only external-board
//! initialization that QEMU cannot emulate.

use super::hw::{display::ConsoleDisplay, touch::ScriptedTouch};

pub(crate) fn initialize() -> (ConsoleDisplay, ScriptedTouch) {
    crate::log!();
    crate::log!("Board: ESP32-S3 QEMU");
    crate::log!("KasSigner Firmware v{}", env!("CARGO_PKG_VERSION"));
    crate::log!("QEMU board bootstrap: external peripherals stubbed");
    crate::log!("  display -> UART console");
    crate::log!("  touch   -> deterministic scripted events");
    crate::log!("  power   -> timer-backed no-op");
    crate::log!();
    (ConsoleDisplay::new(), ScriptedTouch::new())
}
