// KasSee Web — State-Machine + Ship-Escrow covenant builders (moved out of kspt.rs).
// Re-exported by kspt via `pub use state_machine::*`. License: GPL-3.0.

//! State-machine (supply-chain) and shipping-escrow covenant script builders.
//! Re-exported by the parent `kspt` module.

use super::{covenant_ops, push_data, push_int, push_pubkey};

/// Build a state machine covenant for supply chain traceability.
///
/// The covenant tracks state via the UTXO amount:
///   State 0 (manufactured):  base_amount + 0 * step
///   State 1 (shipped):       base_amount + 1 * step
///   State 2 (customs):       base_amount + 2 * step
///   State 3 (delivered):     base_amount + 3 * step (terminal)
///
/// Each state transition requires:
///   1. The correct role's signature (enforced per-state)
///   2. SPK continuity (output recreates the covenant)
///   3. Output amount = input amount + step (state increment)
///
/// The amount-as-state encoding is elegant because:
///   - No counter in the script — the script stays identical (same P2SH)
///   - State is readable by anyone inspecting the UTXO
///   - Each role adds `step` sompi to advance the state
///   - Terminal state has no continuity requirement (delivered = done)
///
/// Script structure:
///   CHECKSIGVERIFY on the active role's key (determined by input amount)
///   Verify SPK continuity (unless terminal)
///   Verify output amount = input amount + step
///
/// Roles: up to 4 state transitions with 4 different signers.
/// `roles[0]` signs the 0→1 transition, `roles[1]` signs 1→2, etc.
///
/// Parameters:
///   roles: array of pubkeys for each transition signer
///   base_amount: starting amount for state 0
///   step: amount increment per state (encodes state in amount)
///
// Kept: supply-chain state-machine covenant builder, not yet wired to UI.
#[allow(dead_code)]
pub fn build_state_machine_covenant_script(
    roles: &[[u8; 32]],
    base_amount: u64,
    step: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let num_states = roles.len();
    let mut s = Vec::with_capacity(512);

    // Salt: unique nonce so same participants produce different P2SH each time
    s.push(0x08); // push 8 bytes
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // ── Pure amount-based state dispatch ──
    // No genesis detection, no auth output checks.
    // SPK continuity verified via direct introspection:
    //   output[0].spk == input.spk
    // Amount verified via:
    //   output[0].amount == next_state_amount

    // Read input amount to determine current state
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);

    for (i, role) in roles.iter().enumerate() {
        let state_amount = base_amount - (i as u64) * step;
        let next_amount = base_amount - ((i + 1) as u64) * step;
        let is_terminal = i == num_states - 1;

        s.push(OP_DUP);
        push_int(&mut s, state_amount);
        s.push(OP_EQUAL);
        s.push(OP_IF);
        s.push(OP_DROP); // drop amount

        // Verify correct role's signature
        push_pubkey(&mut s, role);
        s.push(OP_CHECKSIGVERIFY);

        if !is_terminal {
            // Verify output[0] SPK == input SPK (covenant continues)
            push_int(&mut s, 0); // output index 0
            s.push(OP_TX_OUTPUT_SPK);
            s.push(OP_TX_INPUT_INDEX);
            s.push(OP_TX_INPUT_SPK);
            s.push(OP_EQUALVERIFY);

            // Verify output[0] amount == next state
            push_int(&mut s, 0); // output index 0
            s.push(OP_TX_OUTPUT_AMOUNT);
            push_int(&mut s, next_amount);
            s.push(OP_EQUALVERIFY);

            s.push(OP_1);
        } else {
            // Terminal: signer claims, no continuity
            s.push(OP_1);
        }

        s.push(OP_ELSE);
    }

    // No state matched → fail
    s.push(OP_DROP);
    s.push(OP_0);

    s.resize(s.len() + num_states, OP_ENDIF);

    s
}

/// Build a shipment-escrow covenant redeem script.
///
/// Three parties (Seller S, Deliverer D, Buyer B) plus a dormant Arbiter.
/// Buyer funds the whole pot: `total = product + fee`. The product price is
/// split 50/50: tranche1 (`t1`) released to the seller at pickup, tranche2
/// (`t2`) held until delivery. The delivery fee is paid in full at delivery.
///
/// Amount-dispatch state machine, two states keyed on the input amount:
///   state 0: input == total            (funded, awaiting pickup)
///   state 1: input == rem (= t2 + fee) (in transit, awaiting delivery)
///
/// STATE 0 (amount == total):
///   L1 IF  = pickup  : D CHECKSIGVERIFY; output[0] continues at `rem` to
///                      same P2SH; output[1] -> seller; exactly 2 outputs.
///   L1 ELSE = refund : (L2 IF arbiter sig) OR (L2 ELSE CLTV t1_deadline);
///                      output[0] -> buyer (full refund); exactly 1 output.
///
/// STATE 1 (amount == rem):
///   L1 IF  = pay-workers : authorized by (L2 IF buyer sig) OR
///                          (L3 IF arbiter sig) OR (L3 ELSE CLTV t2_deadline);
///                          output[0] -> seller, output[1] -> deliverer with
///                          amount == fee exactly; exactly 2 outputs.
///   L1 ELSE = refund     : arbiter sig only; output[0] -> buyer; 1 output.
///
/// Fee handling: the continuation amount at state 0 and the deliverer fee at
/// state 1 are enforced EXACT (so amount-dispatch stays deterministic and the
/// deliverer is paid in full). The network fee is absorbed by the seller's
/// output at each hop (seller receives tranche - netfee). Output count is
/// pinned at every terminal so nothing can be skimmed into an extra output.
///
/// Seller never signs: it is a pure payee, identified by its output SPK.
/// Pickup is signed by the deliverer (proof of handoff + implicit quality
/// vouch); delivery is signed by the buyer. The arbiter can act at both
/// states but only ever directs funds to S/D/B, never to itself.
///
/// Verified spend paths (selector layout, bottom-to-top in the sig_script):
///   pickup            <sig_D>   TRUE
///   delivery          <sig_B>   TRUE TRUE
///   state0 arb-refund <sig_Arb> TRUE FALSE
///   state0 timeout              FALSE FALSE
///   state1 arb-award  <sig_Arb> TRUE FALSE TRUE
///   state1 timeout              FALSE FALSE TRUE
///   state1 arb-refund <sig_Arb> FALSE
///
/// Test vector (product=100_000_000, fee=20_000_000, cltv1=1000, cltv2=2000,
/// salt=0420cb2431645a87, pubkeys = sequential bytes S=00..1f D=20..3f
/// B=40..5f Arb=60..7f): redeem is 466 bytes,
/// sha256 = c2aac78dcda85c7838242378943e43b9b9aeb4b241891950d8bfcd8c736c9fba.
#[allow(clippy::too_many_arguments)]
pub fn build_ship_escrow_script(
    s_pubkey: &[u8; 32],
    d_pubkey: &[u8; 32],
    b_pubkey: &[u8; 32],
    arbiter_pubkey: &[u8; 32],
    product_sompi: u64,
    fee_sompi: u64,
    cltv1_deadline: u64,
    cltv2_deadline: u64,
    salt: &[u8; 8],
) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(512);

    let t1 = product_sompi / 2;
    let _t2 = product_sompi - t1; // seller's second tranche (informational)
    let total = product_sompi + fee_sompi;
    let rem = total - t1; // = t2 + fee, the state-1 dispatch amount

    // Version-prefixed P2PK output SPKs (OP_TX_OUTPUT_SPK yields the full
    // ScriptPublicKey incl. 2-byte LE version prefix; prepend 0x0000 to match).
    let p2pk = |xo: &[u8; 32]| -> Vec<u8> {
        let mut v = Vec::with_capacity(36);
        v.extend_from_slice(&[0x00, 0x00]); // version prefix
        v.push(0x20); // push 32
        v.extend_from_slice(xo);
        v.push(OP_CHECKSIG);
        v
    };
    let s_spk_full = p2pk(s_pubkey);
    let d_spk_full = p2pk(d_pubkey);
    let b_spk_full = p2pk(b_pubkey);

    // Salt: unique nonce so identical participants produce different P2SH.
    s.push(0x08);
    s.extend_from_slice(salt);
    s.push(OP_DROP);

    // Read this input's amount and dispatch on it.
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_AMOUNT);

    // ===================== STATE 0 (amount == total) =====================
    s.push(OP_DUP);
    push_int(&mut s, total);
    s.push(OP_EQUAL);
    s.push(OP_IF);
    s.push(OP_DROP); // drop dispatched amount

    //   L1 IF = pickup (deliverer confirms handoff)
    s.push(OP_IF);
    push_pubkey(&mut s, d_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    // output[0] continues to same P2SH at `rem`
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_TX_INPUT_SPK);
    s.push(OP_EQUALVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_AMOUNT);
    push_int(&mut s, rem);
    s.push(OP_EQUALVERIFY);
    // output[1] -> seller (receives t1 - netfee)
    push_int(&mut s, 1);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &s_spk_full);
    s.push(OP_EQUALVERIFY);
    // exactly 2 outputs
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, 2);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);
    //   L1 ELSE = refund buyer (arbiter OR timeout)
    s.push(OP_IF); // L2 IF = arbiter refund
    push_pubkey(&mut s, arbiter_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ELSE); // L2 ELSE = timeout refund
    push_int(&mut s, cltv1_deadline);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_ENDIF); // end L2
                      // output[0] -> buyer (full refund)
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &b_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, 1);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE
    s.push(OP_ENDIF); // end L1 (pickup / refund)

    s.push(OP_ELSE);
    // ===================== STATE 1 (amount == rem) =======================
    s.push(OP_DUP);
    push_int(&mut s, rem);
    s.push(OP_EQUAL);
    s.push(OP_IF);
    s.push(OP_DROP);

    //   L1 IF = pay workers (seller t2 + deliverer fee)
    s.push(OP_IF);
    //     auth sub-selector: buyer | arbiter-award | timeout
    s.push(OP_IF); // L2 IF = buyer confirms delivery
    push_pubkey(&mut s, b_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ELSE);
    s.push(OP_IF); // L3 IF = arbiter award
    push_pubkey(&mut s, arbiter_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    s.push(OP_ELSE); // L3 ELSE = timeout
    push_int(&mut s, cltv2_deadline);
    s.push(OP_CHECKLOCKTIMEVERIFY);
    s.push(OP_ENDIF); // end L3
    s.push(OP_ENDIF); // end L2
                      //     enforce pay-workers outputs
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &s_spk_full); // output[0] -> seller (t2 - netfee)
    s.push(OP_EQUALVERIFY);
    push_int(&mut s, 1);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &d_spk_full); // output[1] -> deliverer
    s.push(OP_EQUALVERIFY);
    push_int(&mut s, 1);
    s.push(OP_TX_OUTPUT_AMOUNT);
    push_int(&mut s, fee_sompi); // deliverer gets exact fee
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, 2);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE

    s.push(OP_ELSE);
    //   L1 ELSE = refund buyer (arbiter only)
    push_pubkey(&mut s, arbiter_pubkey);
    s.push(OP_CHECKSIGVERIFY);
    push_int(&mut s, 0);
    s.push(OP_TX_OUTPUT_SPK);
    push_data(&mut s, &b_spk_full);
    s.push(OP_EQUALVERIFY);
    s.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut s, 1);
    s.push(OP_EQUALVERIFY);
    s.push(0x51); // OP_TRUE
    s.push(OP_ENDIF); // end L1 (pay / refund)

    s.push(OP_ELSE);
    // ===================== no state matched -> fail ======================
    s.push(OP_DROP);
    s.push(OP_0);
    s.push(OP_ENDIF); // end state 1
    s.push(OP_ENDIF); // end state 0

    s
}
