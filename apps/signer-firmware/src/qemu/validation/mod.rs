// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! QEMU hardware-behavior and target known-answer test suite.

mod report;
mod soc;
mod stubs;
mod target;
mod unsupported;

use crate::qemu::hw::{display::ConsoleDisplay, power};
use esp_hal::delay::Delay;
use report::Report;

pub(crate) fn run(display: &mut ConsoleDisplay, delay: &mut Delay) -> bool {
    crate::log!("KASSIGNER_QEMU_TESTS_BEGIN");
    crate::log!("QEMU tests exercise emulated SoC resources and stub contracts");
    let mut report = Report::new();
    soc::run(&mut report, delay);
    stubs::run(&mut report, display, delay);
    target::run(&mut report);
    unsupported::register(&mut report);
    report.finish()
}

pub(crate) fn halt(delay: &mut Delay) -> ! {
    crate::log!("QEMU test failure: runtime startup blocked");
    loop {
        power::idle(delay);
    }
}
