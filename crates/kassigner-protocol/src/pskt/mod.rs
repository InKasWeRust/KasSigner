//! PSKT/KSPT translation and response-processing primitives.

mod compact;
mod finalize;
mod relay;
mod relay_fields;
mod wire;

use crate::{AddressBranch, Network};

pub fn encode_pskt(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    relay::encode_pskt(pskt_hex, network)
}

pub fn merge_signed_kspt(
    original_pskt_hex: &str,
    signed_kspt: &[u8],
    network: Network,
) -> Result<String, String> {
    compact::validate_and_merge(original_pskt_hex, signed_kspt, network)
}

pub fn finalize_json(pskt_hex: &str) -> Result<String, String> {
    finalize::finalize_json(pskt_hex)
}

pub fn attach_input_derivation(
    pskt_hex: &str,
    input_index: usize,
    branch: AddressBranch,
    index: u32,
) -> Result<String, String> {
    wire::attach_input_derivation(pskt_hex, input_index, branch, index)
}

pub fn attach_output_derivation(
    pskt_hex: &str,
    output_index: usize,
    branch: AddressBranch,
    index: u32,
) -> Result<String, String> {
    wire::attach_output_derivation(pskt_hex, output_index, branch, index)
}

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::relay_fields::{find_pubkey_position, parse_ms45, parse_multisig_redeem};
    pub(crate) use super::wire::{decode, document, encode, parse_derivation, Format};
}
