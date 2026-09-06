// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! ESP32-S3 QEMU platform backend.
//!
//! QEMU keeps the real ESP ROM, second-stage bootloader, CPU, mapped flash,
//! UART, timer, and RNG register path. External board peripherals remain behind
//! focused stubs because QEMU does not model the physical board wiring.

#[cfg(feature = "qemu-tests")]
pub(crate) mod allocator;
pub(crate) mod boot;
pub(crate) mod hw;
pub(crate) mod runtime;
#[cfg(feature = "qemu-tests")]
pub(crate) mod validation;

use esp_hal::{clock::CpuClock, delay::Delay};

pub(crate) fn run() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let _peripherals = esp_hal::init(config);
    #[cfg(feature = "qemu-tests")]
    allocator::initialize();
    let delay = Delay::new();
    let (display, touch) = boot::initialize();

    #[cfg(feature = "qemu-tests")]
    let (display, delay) = {
        let mut display = display;
        let mut delay = delay;
        if !validation::run(&mut display, &mut delay) {
            validation::halt(&mut delay);
        }
        (display, delay)
    };

    runtime::run(display, touch, delay)
}
