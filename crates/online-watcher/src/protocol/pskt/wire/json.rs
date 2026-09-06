// KasSee Web — PSKT JSON body encoding
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::Value;

use crate::protocol::pskt::error::PsktWireError;

pub(crate) fn decode_json_body(body_hex: &[u8]) -> Result<Value, PsktWireError> {
    let json_bytes =
        hex::decode(body_hex).map_err(|error| PsktWireError::InnerHex(error.to_string()))?;
    serde_json::from_slice(&json_bytes).map_err(|error| PsktWireError::Json(error.to_string()))
}

pub(crate) fn encode_json_body(root: &Value) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(root).map_err(|error| error.to_string())?;
    Ok(hex::encode(json).into_bytes())
}
