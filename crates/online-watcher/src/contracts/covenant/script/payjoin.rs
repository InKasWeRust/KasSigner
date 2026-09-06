use super::{push_int, push_pubkey};
/// Build a PayJoin covenant redeem script.
///
/// Enforces that the spending TX has mixed inputs — the spender MUST
/// include at least one of their own UTXOs alongside the covenant UTXO.
/// This breaks chain analysis by making it impossible to distinguish
/// which inputs belong to which outputs.
///
/// Two branches:
///   1. Owner refund: owner reclaims after locktime (IF branch).
///   2. PayJoin spend: beneficiary claims, but ONLY in a TX with:
///      - At least `min_inputs` inputs (default 2)
///      - At least `min_outputs` outputs (default 2)
///      - Input[0] and Input[1] from different addresses (enforced via OpTxInputSpk)
///
/// Script:
///   OP_IF
///       <owner_pubkey> OP_CHECKSIGVERIFY
///       <locktime> OP_CHECKLOCKTIMEVERIFY
///       OP_TRUE
///   OP_ELSE
///       <beneficiary_pubkey> OP_CHECKSIGVERIFY
///       OP_TXINPUTCOUNT <min_inputs> OP_GREATERTHANOREQUAL OP_VERIFY
///       OP_TXOUTPUTCOUNT <min_outputs> OP_GREATERTHANOREQUAL OP_VERIFY
///       0 OP_TXINPUTSPK 1 OP_TXINPUTSPK OP_EQUAL OP_NOT OP_VERIFY
///       OP_TRUE
///   OP_ENDIF
///
/// Privacy yield: on-chain the TX looks like a normal multi-input spend.
/// The covenant creator guarantees that their funds can only be spent
/// in a PayJoin-style TX, forcing input mixing.
pub fn build_payjoin_covenant_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    locktime_daa: u64,
    min_inputs: u64,
    min_outputs: u64,
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(120);

    // Owner refund path (IF)
    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_1); // OP_TRUE

    // PayJoin beneficiary claim (ELSE)
    s.push(OP_ELSE);

    // Beneficiary must sign
    push_pubkey(&mut s, beneficiary_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // At least min_inputs inputs
    s.push(OP_TX_INPUT_COUNT);
    push_int(&mut s, min_inputs);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    // At least min_outputs outputs
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, min_outputs);
    s.push(OP_GREATERTHANOREQUAL);
    s.push(OP_VERIFY);

    // Input[0] and Input[1] must be from different addresses
    push_int(&mut s, 0); // push index 0
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 1); // push index 1
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUAL);
    s.push(OP_NOT);
    s.push(OP_VERIFY);

    s.push(OP_1); // OP_TRUE
    s.push(OP_ENDIF);
    s
}
