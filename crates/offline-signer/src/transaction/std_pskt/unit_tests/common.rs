use alloc::{format, vec, vec::Vec};

use shared_signer::{PsktParsed, TxInputFormat};

use crate::transaction::model::Transaction;

use super::super::{hex_decode_strict, parse_pskt, serialize_pskt, PskError};

pub(super) const TXID_ZERO: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub(super) const COVENANT_ID: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

pub(super) fn transaction_json(
    global_extra: &str,
    input_extra: &str,
    output_extra: &str,
) -> Vec<u8> {
    format!(
        "{{\"global\":{{\"version\":0,\"txVersion\":1,\"inputCount\":1,\"outputCount\":1{global_extra}}},\"inputs\":[{{\"utxoEntry\":{{\"amount\":1,\"scriptPublicKey\":\"0000\"}},\"previousOutpoint\":{{\"transactionId\":\"{TXID_ZERO}\",\"index\":0}},\"sighashType\":1{input_extra}}}],\"outputs\":[{{\"amount\":1,\"scriptPublicKey\":\"0000\"{output_extra}}}]}}"
    )
    .into_bytes()
}

pub(super) fn encode_wire(magic: &[u8; 4], json: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut wire = Vec::with_capacity(4 + json.len() * 2);
    wire.extend_from_slice(magic);
    for &byte in json {
        wire.push(HEX[(byte >> 4) as usize]);
        wire.push(HEX[(byte & 0x0f) as usize]);
    }
    wire
}

pub(super) fn parse_json(
    magic: &[u8; 4],
    json: &[u8],
) -> Result<(Transaction, PsktParsed, Vec<u8>), PskError> {
    let wire = encode_wire(magic, json);
    let mut scratch = vec![0u8; json.len()];
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::empty();
    parse_pskt(&wire, &mut scratch, &mut tx, &mut parsed)?;
    Ok((tx, parsed, scratch))
}

pub(super) fn serialize_json(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
) -> Result<Vec<u8>, PskError> {
    let mut wire = vec![0u8; 16_384];
    let len = serialize_pskt(tx, parsed, scratch, format, &mut wire)?;
    wire.truncate(len);
    Ok(decode_json(&wire))
}

pub(super) fn decode_json(wire: &[u8]) -> Vec<u8> {
    let mut json = vec![0u8; (wire.len() - 4) / 2];
    let len = hex_decode_strict(&wire[4..], &mut json).expect("serialized hexadecimal");
    json.truncate(len);
    json
}

pub(super) fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

pub(super) fn count_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}
