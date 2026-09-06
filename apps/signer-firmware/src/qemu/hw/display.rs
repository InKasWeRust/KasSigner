// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! UART-backed display used by the QEMU runtime.

use super::touch::TouchEvent;

pub(crate) struct ConsoleDisplay;

impl ConsoleDisplay {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[cfg(feature = "qemu-tests")]
    pub(crate) fn emit_uart_probe(&mut self) -> bool {
        crate::log!("KASSIGNER_QEMU_UART_PROBE");
        true
    }

    pub(crate) fn show_ready(&mut self) {
        crate::log!("KASSIGNER_QEMU_READY");
        crate::log!("Runtime entered without board peripheral initialization");
    }

    pub(crate) fn show_touch(&mut self, event: TouchEvent) {
        match event {
            TouchEvent::Tap { x, y } => {
                crate::log!("QEMU touch: tap x={} y={}", x, y);
            }
            TouchEvent::Back => crate::log!("QEMU touch: back"),
        }
    }

    pub(crate) fn show_heartbeat(&mut self, iteration: u32) {
        crate::log!("QEMU runtime heartbeat: {}", iteration);
    }
}
