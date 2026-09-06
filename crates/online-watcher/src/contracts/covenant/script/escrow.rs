use super::{push_data, push_int, push_pubkey};
/// Build a 2-of-3 escrow covenant redeem script with arbiter.
///
/// Three parties: Alice (buyer), Bob (seller), Arbiter.
/// Five paths:
///   1. Alice releases to Bob (deal done)
///   2. Bob refunds to Alice (cancel)
///   3. Arbiter awards to Bob (dispute, Bob wins)
///   4. Arbiter refunds to Alice (dispute, Alice wins)
///   5. Dispute signal: buyer or seller sends funds back to same address
///      (heartbeat-style, signals arbitration needed)
///
/// Script:
///   IF
///     <alice_pk> CHECKSIGVERIFY 0 TX_OUTPUT_SPK <bob_spk> EQUALVERIFY TRUE
///   ELSE IF
///     <bob_pk> CHECKSIGVERIFY 0 TX_OUTPUT_SPK <alice_spk> EQUALVERIFY TRUE
///   ELSE IF
///     <arbiter_pk> CHECKSIGVERIFY
///     IF  0 TX_OUTPUT_SPK <bob_spk> EQUALVERIFY TRUE
///     ELSE 0 TX_OUTPUT_SPK <alice_spk> EQUALVERIFY TRUE
///     ENDIF
///   ELSE
///     IF <alice_pk> CHECKSIG
///     ELSE <bob_pk> CHECKSIG
///     ENDIF
///     TX_INPUT_INDEX TX_INPUT_SPK 0 TX_OUTPUT_SPK EQUALVERIFY TRUE
///   ENDIF ENDIF ENDIF
///
/// Sig scripts:
///   Alice releases:          <sig> TRUE
///   Bob refunds:             <sig> TRUE FALSE
///   Arbiter awards Bob:      <sig> TRUE TRUE FALSE FALSE
///   Arbiter refunds Alice:   <sig> FALSE TRUE FALSE FALSE
///   Buyer disputes:          <sig> TRUE FALSE FALSE FALSE
///   Seller disputes:         <sig> FALSE FALSE FALSE FALSE
///
/// The script starts with <salt> OP_DROP to make each escrow unique
/// even with the same participants.
pub fn build_escrow_script(
    alice_pubkey: &[u8; 32],
    bob_pubkey: &[u8; 32],
    arbiter_pubkey: &[u8; 32],
    alice_spk: &[u8],
    bob_spk: &[u8],
    salt: &[u8; 8],
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(524);

    // Salt: unique nonce so same participants produce different P2SH each time
    s.push(0x08); // push 8 bytes
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // OP_TX_OUTPUT_SPK pushes the full ScriptPublicKey including the
    // 2-byte LE version prefix. Prepend version 0x0000 to the raw
    // script bytes so the OP_EQUAL comparison matches.
    let mut bob_spk_full = Vec::with_capacity(2 + bob_spk.len());
    bob_spk_full.extend_from_slice(&[0x00, 0x00]);
    bob_spk_full.extend_from_slice(bob_spk);

    let mut alice_spk_full = Vec::with_capacity(2 + alice_spk.len());
    alice_spk_full.extend_from_slice(&[0x00, 0x00]);
    alice_spk_full.extend_from_slice(alice_spk);

    // Path 1: Alice releases to Bob (buyer confirms delivery)
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);

    // Path 2: Bob refunds to Alice (seller cancels)
    s.push(OP_IF);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);

    // Path 3+4: Arbiter decides direction
    s.push(OP_IF);
    push_pubkey(&mut s, arbiter_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Inner IF: arbiter awards Bob
    s.push(OP_IF);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    // Inner ELSE: arbiter refunds Alice
    s.push(OP_ELSE);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF); // arbiter direction

    s.push(OP_ELSE);

    // Path 5: Dispute signal (heartbeat back to self)
    // Either buyer or seller signs, output must go back to same P2SH
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ELSE);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ENDIF); // buyer/seller selector

    // Enforce output[0] == own input SPK (send back to same address)
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ENDIF); // arbiter/dispute
    s.push(OP_ENDIF); // bob/rest
    s.push(OP_ENDIF); // alice/rest
    s
}

/// Build a time-locked escrow covenant redeem script.
///
/// Two-party escrow with automatic refund after timeout.
/// - Alice signs → funds go to Bob (destination enforced via OUTPUT_SPK)
/// - Bob signs → funds go to Alice (destination enforced)
/// - After locktime passes → funds refund to Alice (no signature needed,
///   destination enforced, TX locktime must be >= threshold)
///
/// Script:
///   OP_IF
///       <alice_pk> OP_CHECKSIGVERIFY
///       0 OP_TX_OUTPUT_SPK <bob_spk_full> OP_EQUAL
///   OP_ELSE
///       OP_IF
///           <bob_pk> OP_CHECKSIGVERIFY
///           0 OP_TX_OUTPUT_SPK <alice_spk_full> OP_EQUAL
///       OP_ELSE
///           <locktime_daa> OP_CHECKLOCKTIMEVERIFY
///           0 OP_TX_OUTPUT_SPK <alice_spk_full> OP_EQUAL
///       OP_ENDIF
///   OP_ENDIF
///
/// Sig_scripts:
///   Alice releases: <sig> OP_TRUE        (outer IF)
///   Bob releases:   <sig> OP_TRUE OP_FALSE (outer ELSE → inner IF)
///   Timeout refund: OP_FALSE OP_FALSE    (outer ELSE → inner ELSE)
pub fn build_timelocked_escrow_script(
    alice_pubkey: &[u8; 32],
    bob_pubkey: &[u8; 32],
    alice_spk: &[u8],
    bob_spk: &[u8],
    locktime_daa: u64,
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(256);

    // Prepend 2-byte BE version prefix (0x0000) for OUTPUT_SPK comparison
    let mut bob_spk_full = Vec::with_capacity(2 + bob_spk.len());
    bob_spk_full.extend_from_slice(&[0x00, 0x00]);
    bob_spk_full.extend_from_slice(bob_spk);

    let mut alice_spk_full = Vec::with_capacity(2 + alice_spk.len());
    alice_spk_full.extend_from_slice(&[0x00, 0x00]);
    alice_spk_full.extend_from_slice(alice_spk);

    // Outer IF: Alice signs → Bob receives
    s.push(OP_IF);
    push_pubkey(&mut s, alice_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &bob_spk_full);
    s.push(OP_EQUAL);

    // Outer ELSE
    s.push(OP_ELSE);

    // Inner IF: Bob signs → Alice receives
    s.push(OP_IF);
    push_pubkey(&mut s, bob_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUAL);

    // Inner ELSE: Timeout → refund to Alice
    s.push(OP_ELSE);
    push_int(&mut s, locktime_daa);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &alice_spk_full);
    s.push(OP_EQUAL);

    s.push(OP_ENDIF); // inner
    s.push(OP_ENDIF); // outer
    s
}
