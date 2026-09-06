mod address;
mod bip32;

use serde::{Deserialize, Serialize};

use crate::{error::ProtocolError, Network};

pub use address::{
    address_to_script_pubkey, decode_address, encode_address, encode_p2pk_address,
    encode_p2sh_address,
};
#[cfg(feature = "kassee-compat")]
pub use bip32::ExtPubKey;
pub use bip32::{decode_kpub_text, extend_addresses, import_kpub, import_kpub_raw, WalletData};

#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressBranch {
    Receive,
    Change,
}

impl AddressBranch {
    const CODES: [u8; 2] = [0, 1];
    const BRANCHES: [AddressBranch; 2] = [AddressBranch::Receive, AddressBranch::Change];

    #[must_use]
    pub const fn code(self) -> u8 {
        Self::CODES[self as usize]
    }

    pub fn from_code(value: u8) -> Result<Self, ProtocolError> {
        Self::BRANCHES
            .get(usize::from(value))
            .copied()
            .ok_or_else(|| {
                ProtocolError::derivation(format!("invalid KasSigner address branch: {value}"))
            })
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedAddress {
    pub address: String,
    pub branch: AddressBranch,
    pub index: u32,
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDescriptor {
    pub network: Network,
    pub account_kpub: String,
    pub account_fingerprint: String,
    pub receive_addresses: Vec<DerivedAddress>,
    pub change_addresses: Vec<DerivedAddress>,
}

pub fn decode_account(payload: &str, network: Network) -> Result<AccountDescriptor, String> {
    let raw = decode_account_payload(payload)?;
    let canonical = canonical_account_text(&raw)?;
    let xpub = bip32::ExtPubKey::from_kpub(&canonical)?;
    let account_fingerprint = account_fingerprint(&xpub)?;
    let receive_addresses = derive_addresses(&xpub, network, AddressBranch::Receive, 0, 20)?;
    let change_addresses = derive_addresses(&xpub, network, AddressBranch::Change, 0, 20)?;
    Ok(AccountDescriptor {
        network,
        account_kpub: canonical,
        account_fingerprint,
        receive_addresses,
        change_addresses,
    })
}

fn decode_account_payload(
    payload: &str,
) -> Result<[u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN], String> {
    if let Ok(raw) = hex::decode(payload) {
        if raw.len() == shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN {
            return raw
                .as_slice()
                .try_into()
                .map_err(|_| "invalid account payload length".to_string());
        }
        if let Ok(text) = core::str::from_utf8(&raw) {
            return bip32::decode_kpub_text(text);
        }
    }
    bip32::decode_kpub_text(payload)
}

fn canonical_account_text(
    payload: &[u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<String, String> {
    let mut text = [0u8; shared_signer::account_key::ACCOUNT_KEY_TEXT_LEN];
    let length = shared_signer::account_key::encode_account_key_text(payload, &mut text)
        .ok_or_else(|| "Account-key payload is not canonical".to_string())?;
    core::str::from_utf8(&text[..length])
        .map(str::to_owned)
        .map_err(|_| "Canonical account-key text is not UTF-8".to_string())
}

fn account_fingerprint(xpub: &bip32::ExtPubKey) -> Result<String, String> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let point = xpub.key.to_encoded_point(true);
    let compressed: [u8; 33] = point
        .as_bytes()
        .try_into()
        .map_err(|_| "invalid account public key".to_string())?;
    Ok(hex::encode(shared_signer::pairing::account_fingerprint(
        &compressed,
        &xpub.chain_code,
    )))
}

pub fn derive_addresses(
    account: &bip32::ExtPubKey,
    network: Network,
    branch: AddressBranch,
    start: u32,
    count: u8,
) -> Result<Vec<DerivedAddress>, String> {
    let end = start
        .checked_add(u32::from(count))
        .ok_or_else(|| "address range exceeds non-hardened derivation space".to_string())?;
    if end > shared_signer::pairing::SOFT_INDEX_LIMIT {
        return Err("address range exceeds non-hardened derivation space".to_string());
    }
    let chain = account.derive_child(u32::from(branch.code()))?;
    (0..u32::from(count))
        .map(|offset| {
            let index = start + offset;
            let child = chain.derive_child(index)?;
            Ok(DerivedAddress {
                address: address::encode_p2pk_address(
                    &child.x_only_bytes(),
                    network.address_prefix(),
                ),
                branch,
                index,
            })
        })
        .collect()
}

pub fn derive_public_batch(
    keys: impl IntoIterator<Item = ([u8; 32], AddressBranch, u32)>,
    network: Network,
) -> Vec<DerivedAddress> {
    keys.into_iter()
        .map(|(key, branch, index)| DerivedAddress {
            address: address::encode_p2pk_address(&key, network.address_prefix()),
            branch,
            index,
        })
        .collect()
}
