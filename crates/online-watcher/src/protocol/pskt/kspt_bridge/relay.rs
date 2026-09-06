// KasSee delegates the reusable PSKT -> KSPT relay to the official protocol crate.

#[cfg(test)]
use serde_json::Value;

pub fn relay_pskb_as_kspt_hex_for_network(wire_hex: &str, network: &str) -> Result<String, String> {
    let network = kassigner_protocol::Network::parse(network).map_err(|error| error.to_string())?;
    kassigner_protocol::encode_pskt_hex(wire_hex, network).map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) fn first_outpoint(inputs: &[Value]) -> Option<([u8; 32], u32)> {
    let outpoint = inputs.first()?.get("previousOutpoint")?.as_object()?;
    let bytes = hex::decode(outpoint.get("transactionId")?.as_str()?).ok()?;
    let id = bytes.as_slice().try_into().ok()?;
    let index = outpoint
        .get("index")?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())?;
    Some((id, index))
}
