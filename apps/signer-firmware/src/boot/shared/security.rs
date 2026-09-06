// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Fail-closed security lockdown stages shared by both ESP32-S3 boards.

#[inline]
pub(crate) fn early_lockdown() {
    if !crate::hw::lockdown::early_lockdown() {
        panic!("wireless power-domain lockdown verification failed");
    }
}

#[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]
#[inline]
pub(crate) fn post_boot_lockdown() {
    crate::hw::lockdown::post_boot_lockdown();
}
