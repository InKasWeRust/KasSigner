// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Firmware façade for the host-tested button state machine.

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
pub use signer_firmware_core::input::button::ButtonEvent;

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
pub use signer_firmware_core::input::button::Button;
