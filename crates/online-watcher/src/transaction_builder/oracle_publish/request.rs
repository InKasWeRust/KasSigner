use crate::account::{address, bip32};
use crate::serialization::input::{decode_named_32, parse_json};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct PublishApiRequest {
    pub(crate) wallet_json: String,
    pub(crate) oracle_address: String,
    pub(crate) redeem_script_hex: String,
    pub(crate) covenant_id_hex: String,
    pub(crate) heartbeat_cov_id_hex: String,
    pub(crate) image_id_hex: String,
    pub(crate) control_id_hex: String,
    pub(crate) set_root_hex: String,
    pub(crate) hashfn_hex: String,
    pub(crate) seal_hex: String,
    pub(crate) claim_hex: String,
    pub(crate) control_index_hex: String,
    pub(crate) control_digests_hex: String,
    pub(crate) journal_hex: String,
    pub(crate) fee: String,
    pub(crate) change_address: String,
    pub(crate) network: String,
    pub(crate) ws_url: String,
    #[serde(default)]
    pub(crate) omit_heartbeat: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct PublishRequestInput<'a> {
    pub(crate) wallet_json: &'a str,
    pub(crate) oracle_address: &'a str,
    pub(crate) redeem_script_hex: &'a str,
    pub(crate) covenant_id_hex: &'a str,
    pub(crate) heartbeat_cov_id_hex: &'a str,
    pub(crate) image_id_hex: &'a str,
    pub(crate) control_id_hex: &'a str,
    pub(crate) set_root_hex: &'a str,
    pub(crate) hashfn_hex: &'a str,
    pub(crate) seal_hex: &'a str,
    pub(crate) claim_hex: &'a str,
    pub(crate) control_index_hex: &'a str,
    pub(crate) control_digests_hex: &'a str,
    pub(crate) journal_hex: &'a str,
    pub(crate) fee: u64,
    pub(crate) change_address: &'a str,
    pub(crate) network: &'a str,
    pub(crate) ws_url: &'a str,
    pub(crate) omit_heartbeat: bool,
}

pub(crate) struct PublishRequest {
    pub(crate) wallet: bip32::WalletData,
    pub(crate) oracle_address: String,
    pub(crate) redeem_script_hex: String,
    pub(crate) covenant_id_hex: String,
    pub(crate) heartbeat_cov_id_hex: String,
    pub(crate) image_id: [u8; 32],
    pub(crate) control_id: [u8; 32],
    pub(crate) set_root: [u8; 32],
    pub(crate) hashfn: u8,
    pub(crate) seal_hex: String,
    pub(crate) claim_hex: String,
    pub(crate) control_index_hex: String,
    pub(crate) control_digests_hex: String,
    pub(crate) journal_hex: String,
    pub(crate) new_price: u64,
    pub(crate) new_t: u64,
    pub(crate) fee: u64,
    pub(crate) change_spk: Vec<u8>,
    pub(crate) network: String,
    pub(crate) ws_url: String,
    pub(crate) omit_heartbeat: bool,
}

struct ValidatedPublishFields {
    wallet: bip32::WalletData,
    change_spk: Vec<u8>,
    image_id: [u8; 32],
    control_id: [u8; 32],
    set_root: [u8; 32],
    hashfn: u8,
    journal: Vec<u8>,
}

impl PublishRequest {
    pub(crate) fn parse_string(input: PublishRequestInput<'_>) -> Result<Self, String> {
        parse_json(input.wallet_json, "Bad wallet JSON").and_then(|wallet| {
            address::address_to_script_pubkey(input.change_address).and_then(|change_spk| {
                decode_named_32(input.image_id_hex, "image_id").and_then(|image_id| {
                    decode_named_32(input.control_id_hex, "control_id").and_then(|control_id| {
                        decode_named_32(input.set_root_hex, "set_root").and_then(|set_root| {
                            decode_hash_function(input.hashfn_hex).and_then(|hashfn| {
                                validate_publish_covenant_ids(&input).and_then(|()| {
                                    decode_journal(input.journal_hex, &set_root).map(|journal| {
                                        Self::from_validated(
                                            input,
                                            ValidatedPublishFields {
                                                wallet,
                                                change_spk,
                                                image_id,
                                                control_id,
                                                set_root,
                                                hashfn,
                                                journal,
                                            },
                                        )
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }

    fn from_validated(input: PublishRequestInput<'_>, fields: ValidatedPublishFields) -> Self {
        let mut price = [0u8; 8];
        price.copy_from_slice(&fields.journal[0..8]);
        let mut publish_time = [0u8; 8];
        publish_time.copy_from_slice(&fields.journal[8..16]);
        Self {
            wallet: fields.wallet,
            oracle_address: input.oracle_address.to_owned(),
            redeem_script_hex: input.redeem_script_hex.to_owned(),
            covenant_id_hex: input.covenant_id_hex.to_owned(),
            heartbeat_cov_id_hex: input.heartbeat_cov_id_hex.to_owned(),
            image_id: fields.image_id,
            control_id: fields.control_id,
            set_root: fields.set_root,
            hashfn: fields.hashfn,
            seal_hex: input.seal_hex.to_owned(),
            claim_hex: input.claim_hex.to_owned(),
            control_index_hex: input.control_index_hex.to_owned(),
            control_digests_hex: input.control_digests_hex.to_owned(),
            journal_hex: input.journal_hex.to_owned(),
            new_price: u64::from_le_bytes(price),
            new_t: u64::from_le_bytes(publish_time),
            fee: input.fee,
            change_spk: fields.change_spk,
            network: input.network.to_owned(),
            ws_url: input.ws_url.to_owned(),
            omit_heartbeat: input.omit_heartbeat,
        }
    }
}

fn validate_publish_covenant_ids(input: &PublishRequestInput<'_>) -> Result<(), String> {
    decode_named_32(input.covenant_id_hex, "covenant_id")
        .and_then(|_| decode_named_32(input.heartbeat_cov_id_hex, "heartbeat_cov_id").map(|_| ()))
}

fn decode_hash_function(value: &str) -> Result<u8, String> {
    let bytes = hex::decode(value).map_err(|error| format!("Bad hashfn hex: {error}"))?;
    match bytes.as_slice() {
        [hashfn] => Ok(*hashfn),
        _ => Err(format!("hashfn must be 1 byte, got {}", bytes.len())),
    }
}

fn decode_journal(value: &str, set_root: &[u8; 32]) -> Result<Vec<u8>, String> {
    let journal = hex::decode(value).map_err(|error| format!("Bad journal hex: {error}"))?;
    if journal.len() != 48 {
        return Err(format!("journal must be 48 bytes, got {}", journal.len()));
    }
    if journal[16..48] != set_root[..] {
        return Err(
            "journal set_root (bytes 16..48) does not match the committed set_root".to_string(),
        );
    }
    Ok(journal)
}

pub(crate) fn decode_heartbeat_covenant_id(value: &str) -> Result<[u8; 32], String> {
    decode_named_32(value, "heartbeat_cov_id")
}

#[cfg(test)]
mod unit_tests;
