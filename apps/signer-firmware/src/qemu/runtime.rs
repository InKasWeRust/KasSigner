// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Minimal QEMU runtime loop.
//!
//! This loop verifies platform selection, UART output, timer progress, and the
//! replaceable display/touch/power boundary without pretending unsupported
//! external board peripherals are present.

use super::hw::{
    display::ConsoleDisplay,
    power,
    touch::ScriptedTouch,
};
use esp_hal::delay::Delay;

const HEARTBEAT_INTERVAL: u32 = 20;

pub(crate) fn run(
    mut display: ConsoleDisplay,
    mut touch: ScriptedTouch,
    mut delay: Delay,
) -> ! {
    display.show_ready();
    let mut iteration = 0u32;

    loop {
        if let Some(event) = touch.next_event() {
            display.show_touch(event);
        }

        if iteration % HEARTBEAT_INTERVAL == 0 {
            display.show_heartbeat(iteration);
        }

        iteration = iteration.wrapping_add(1);
        power::idle(&mut delay);
    }
}
