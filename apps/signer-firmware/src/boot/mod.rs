// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Staged firmware boot orchestration.
//!
//! Shared boot policy lives in `shared/`. Each board owns its complete
//! peripheral-initialization path under its named module.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
pub(crate) mod shared;

#[cfg(feature = "waveshare")]
pub(crate) mod waveshare;
#[cfg(feature = "m5stack")]
pub(crate) mod m5stack;

pub(crate) use shared::{application, security};
