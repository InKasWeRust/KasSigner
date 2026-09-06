// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! QEMU power policy.

use esp_hal::delay::Delay;

pub(crate) fn idle(delay: &mut Delay) {
    delay.delay_millis(250);
}
