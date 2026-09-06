// KasSee delegates reusable KSPT response validation/merge to the official protocol crate.

pub fn merge_signed_kspt_into_pskb(
    signed_kspt_hex: &str,
    pskb_wire_hex: &str,
) -> Result<String, String> {
    let network = signed_network(signed_kspt_hex)?;
    kassigner_protocol::merge_signed_kspt_hex(pskb_wire_hex, signed_kspt_hex, network)
        .map_err(|error| error.to_string())
}

fn signed_network(signed_kspt_hex: &str) -> Result<kassigner_protocol::Network, String> {
    const NETWORKS: [kassigner_protocol::Network; 4] = [
        kassigner_protocol::Network::Mainnet,
        kassigner_protocol::Network::Testnet10,
        kassigner_protocol::Network::Devnet,
        kassigner_protocol::Network::Simnet,
    ];
    let bytes = hex::decode(signed_kspt_hex).map_err(|error| format!("KSPT hex: {error}"))?;
    let code = find_network_trailer(&bytes)?;
    let index = code.checked_sub(1).map(usize::from);
    index
        .and_then(|value| NETWORKS.get(value).copied())
        .ok_or_else(|| "invalid compact KSPT network trailer".to_string())
}

fn find_network_trailer(bytes: &[u8]) -> Result<u8, String> {
    // The existing compact parser is the source of truth for locating trailers;
    // this helper only extracts the already-validated network marker.
    let transaction = super::parse_compact_kspt_transaction(bytes)?;
    Ok(transaction.network)
}
