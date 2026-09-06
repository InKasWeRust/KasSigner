// KasSee Web — signature classification for KSPT adapters
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

use crate::protocol::pskt::review::{find_pubkey_position_in_redeem, parse_multisig_redeem};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KsptEncodingMode {
    Finalized,
    Relay,
}

pub(crate) struct EncodedSignature {
    pub(crate) pubkey_position: u8,
    pub(crate) bytes: [u8; 64],
}

pub(crate) fn collect_signatures(
    script_public_key: &[u8],
    redeem_script: Option<&[u8]>,
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    if is_p2sh_script(script_public_key) {
        if let Some(redeem_script) = redeem_script {
            return collect_p2sh_signatures(redeem_script, partial_signatures, mode);
        }
    }
    collect_single_path_signature(partial_signatures, mode)
}

fn is_p2sh_script(script_public_key: &[u8]) -> bool {
    script_public_key.len() == 35
        && script_public_key.first() == Some(&0xAA)
        && script_public_key.get(1) == Some(&0x20)
        && script_public_key.get(34) == Some(&0x87)
}

fn collect_p2sh_signatures(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    if mode == KsptEncodingMode::Finalized && redeem_script.first() == Some(&0x63) {
        return collect_finalized_covenant_signature(redeem_script, partial_signatures);
    }
    if let Some((required, _)) = parse_multisig_redeem(redeem_script) {
        return collect_checked_multisig(redeem_script, partial_signatures, mode, required);
    }
    if mode == KsptEncodingMode::Relay {
        return Ok(Vec::new());
    }
    Err("redeem is not a valid M-of-N multisig".into())
}

fn collect_checked_multisig(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
    required: u8,
) -> Result<Vec<EncodedSignature>, String> {
    let signatures = collect_multisig_signatures(redeem_script, partial_signatures)?;
    if mode == KsptEncodingMode::Finalized && signatures.len() < required as usize {
        return Err(format!(
            "multisig not ready: {} sig(s) present, need {}",
            signatures.len(),
            required
        ));
    }
    Ok(signatures)
}

fn collect_single_path_signature(
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    match partial_signatures.iter().next() {
        Some((_, signature)) => Ok(vec![EncodedSignature {
            pubkey_position: 0,
            bytes: decode_signature(
                signature,
                "partial sig missing schnorr variant (ECDSA unsupported)",
            )?,
        }]),
        None if mode == KsptEncodingMode::Relay => Ok(Vec::new()),
        None => Err("input has no signature".into()),
    }
}

pub(crate) fn collect_finalized_covenant_signature(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Vec<EncodedSignature>, String> {
    let (public_key, signature) = partial_signatures
        .iter()
        .next()
        .ok_or_else(|| "covenant input has no signature".to_string())?;
    let xonly_public_key = if public_key.len() == 66 {
        &public_key[2..]
    } else {
        public_key.as_str()
    };
    let owner_public_key = if redeem_script.len() >= 34 && redeem_script[1] == 0x20 {
        Some(hex::encode(&redeem_script[2..34]))
    } else {
        None
    };
    let pubkey_position = u8::from(owner_public_key.as_deref() != Some(xonly_public_key));
    Ok(vec![EncodedSignature {
        pubkey_position,
        bytes: decode_signature(signature, "partial sig missing schnorr variant")?,
    }])
}

fn collect_multisig_signatures(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Vec<EncodedSignature>, String> {
    let mut signatures = Vec::with_capacity(partial_signatures.len());
    for (public_key, signature) in partial_signatures {
        if public_key.len() != 66 {
            continue;
        }
        let pubkey_position = find_pubkey_position_in_redeem(redeem_script, public_key)
            .ok_or_else(|| format!("pubkey not in redeem: {}", public_key))?;
        signatures.push(EncodedSignature {
            pubkey_position,
            bytes: decode_signature(
                signature,
                "partial sig missing schnorr variant (ECDSA unsupported)",
            )?,
        });
    }
    signatures.sort_by_key(|signature| signature.pubkey_position);
    Ok(signatures)
}

fn decode_signature(value: &Value, missing_message: &str) -> Result<[u8; 64], String> {
    let signature_hex = value
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_message.to_string())?;
    if signature_hex.len() != 128 {
        return Err(format!("bad sig length: {}", signature_hex.len()));
    }
    let signature = hex::decode(signature_hex).map_err(|e| format!("sig hex: {}", e))?;
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&signature);
    Ok(bytes)
}
