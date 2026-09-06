// KasSee Web — PSKT / PSKB wire errors
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

#[derive(Debug)]
pub(crate) enum PsktWireError {
    UnknownFormat,
    OuterHex(String),
    TooShort,
    MagicMismatch,
    InnerHex(String),
    Json(String),
}
