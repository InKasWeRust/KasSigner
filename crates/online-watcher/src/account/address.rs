//! KasSee compatibility facade over protocol-owned Kaspa address primitives.

#[cfg(test)]
pub(super) use kassigner_protocol::encode_address;
pub use kassigner_protocol::{encode_p2pk_address, encode_p2sh_address};

pub fn decode_address(addr: &str) -> Result<(u8, [u8; 32]), String> {
    kassigner_protocol::compat::decode_address(addr)
}

pub fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, String> {
    kassigner_protocol::compat::address_to_script_pubkey(addr)
}

/// Map a Kaspa network label to the canonical address prefix for internal KasSee callers.
#[must_use]
pub(crate) fn network_prefix(network: &str) -> &'static str {
    match network {
        "testnet-10" | "testnet-11" | "testnet-12" => "kaspatest",
        "simnet" => "kaspasim",
        "devnet" => "kaspadev",
        _ => "kaspa",
    }
}
