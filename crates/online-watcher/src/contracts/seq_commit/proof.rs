use crate::protocol::pskt;

const KSTL_SUBNETWORK_ID_HEX: &str = "4b53544c00000000000000000000000000000000";
const KSTL_GAS: u64 = 0;
const KSTL_TRANSACTION_VERSION: u16 = 1;
const STEALTH_PROOF_VERSION: u8 = 1;
const STEALTH_PROOF_LENGTH: usize = 34;

/// Stamp a KSTL sequence-commit proof onto an existing PSKB transaction.
///
/// The proof payload is the canonical `version || ephemeral_key || view_tag`
/// encoding consumed by the stealth scanner.
pub(crate) fn stamp_stealth_proof(
    wire_hex: &str,
    ephemeral_public_key: &[u8; 32],
    view_tag: u8,
) -> Result<String, String> {
    let payload = encode_stealth_proof(ephemeral_public_key, view_tag);
    pskt::set_tx_lane(
        wire_hex,
        KSTL_SUBNETWORK_ID_HEX,
        KSTL_GAS,
        KSTL_TRANSACTION_VERSION,
        &payload,
    )
}

fn encode_stealth_proof(
    ephemeral_public_key: &[u8; 32],
    view_tag: u8,
) -> [u8; STEALTH_PROOF_LENGTH] {
    let mut payload = [0u8; STEALTH_PROOF_LENGTH];
    payload[0] = STEALTH_PROOF_VERSION;
    payload[1..33].copy_from_slice(ephemeral_public_key);
    payload[33] = view_tag;
    payload
}
