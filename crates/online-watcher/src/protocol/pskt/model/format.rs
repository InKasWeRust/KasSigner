// KasSee Web — PSKT / PSKB format model
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde::Serialize;

pub(crate) use kassigner_protocol::wire::pskt_envelope::{PSKB_MAGIC, PSKT_MAGIC};

/// Detected wire format for a given hex payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PsktFormat {
    /// `PSKB` magic — body is `[<PSKT>]`.
    Pskb,
    /// `PSKT` magic — body is `<PSKT>` directly.
    PsktSingle,
    /// Not a PSKT-shaped payload.
    Unknown,
}
