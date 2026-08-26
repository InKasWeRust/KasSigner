// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// crypto/mod.rs — the hardware-free security primitives.
//
//   - Constant-time comparison (constant_time)
//   - Flow integrity counters (flow)
//
// Hardware entropy collection (`entropy`) stays in the firmware; this crate
// reaches it through `crate::entropy` (the injected source).

pub mod constant_time;
pub mod flow;
