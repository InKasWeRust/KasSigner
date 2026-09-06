// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Contract tests for external-board stubs used only by QEMU.

use super::report::Report;
use crate::qemu::hw::{
    display::ConsoleDisplay,
    power,
    touch::{ScriptedTouch, TouchEvent},
};
use esp_hal::delay::Delay;

pub(crate) fn run(
    report: &mut Report,
    display: &mut ConsoleDisplay,
    delay: &mut Delay,
) {
    report.check("UART console output", display.emit_uart_probe());
    report.check("deterministic touch script", test_touch());
    report.check("QEMU power-idle facade", test_power(delay));
}

fn test_touch() -> bool {
    let mut touch = ScriptedTouch::new();
    let expected = [
        TouchEvent::Tap { x: 160, y: 120 },
        TouchEvent::Tap { x: 280, y: 24 },
        TouchEvent::Back,
    ];
    for event in expected {
        if touch.next_event() != Some(event) {
            return false;
        }
    }
    touch.next_event().is_none() && touch.consumed() == expected.len()
}

fn test_power(delay: &mut Delay) -> bool {
    power::idle(delay);
    true
}
