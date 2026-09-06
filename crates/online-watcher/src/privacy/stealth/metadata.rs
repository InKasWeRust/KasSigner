use k256::PublicKey;

use super::keys::{pubkey_from_xonly, x_only_bytes};

pub struct StealthMeta {
    pub scan_pubkey: PublicKey,
    pub spend_pubkey: PublicKey,
}

pub fn derive_stealth_meta(
    account_key: &crate::account::bip32::ExtPubKey,
) -> Result<StealthMeta, String> {
    let scan_key = account_key.derive_child(2)?.derive_child(0)?;
    Ok(StealthMeta {
        scan_pubkey: scan_key.key,
        spend_pubkey: account_key.key,
    })
}

pub fn encode_stealth_meta(meta: &StealthMeta) -> String {
    format!(
        "{}{}",
        hex::encode(x_only_bytes(&meta.scan_pubkey)),
        hex::encode(x_only_bytes(&meta.spend_pubkey)),
    )
}

pub fn decode_stealth_meta(value: &str) -> Result<StealthMeta, String> {
    if value.len() != 128 {
        return Err(format!(
            "Stealth meta-address must be 128 hex chars, got {}",
            value.len()
        ));
    }
    let bytes = hex::decode(value).map_err(|error| format!("Invalid hex: {error}"))?;
    Ok(StealthMeta {
        scan_pubkey: pubkey_from_xonly(&bytes[..32])?,
        spend_pubkey: pubkey_from_xonly(&bytes[32..])?,
    })
}
