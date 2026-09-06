// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Board-neutral application boot policy.
//!
//! This module keeps presentation and post-peripheral boot decisions out of the
//! ESP-HAL ownership function. Hardware singleton construction remains in
//! `main.rs`, while these focused helpers own ordinary control-flow policy.

pub(crate) fn print_banner() {
    crate::log!();
    crate::log!("Board: {}", crate::hw::ACTIVE_BOARD_NAME);
    crate::log!("╔════════════════════════════════════╗");
    crate::log!(
        "║      KasSigner Firmware v{}     ║",
        env!("CARGO_PKG_VERSION")
    );
    crate::log!("║   Secure Boot for Kaspa Signer     ║");
    crate::log!("╚════════════════════════════════════╝");
    crate::log!();
}

#[cfg(all(not(feature = "hardware-tests"), not(feature = "skip-tests")))]
pub(crate) fn enforce_boot_known_answer_tests() {
    if !crate::runtime::unit_tests::boot::run_boot_tests() {
        panic!("boot cryptographic known-answer test failed");
    }
}
