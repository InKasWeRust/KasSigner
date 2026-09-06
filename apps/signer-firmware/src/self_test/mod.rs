// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Hardware-independent boot self-test primitives shared by physical boards and QEMU.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
pub(crate) mod crypto;
pub(crate) mod memory;
