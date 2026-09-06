//! Human-attested Oracle-v1 covenant.
//!
//! Each covenant embeds one unique exact 32-byte statement commitment at
//! creation time. The oracle signs that commitment through KasSigner's isolated covenant-key hierarchy. The claim branch verifies only that
//! attestation from another covenant or another statement cannot be substituted.

use super::{push_data, push_int, push_pubkey};

pub const ORACLE_V1_SIG_OP_COUNT: u8 = 2;

type OracleV1BoundFields = ([u8; 16], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

pub fn build_oracle_v1_covenant_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    oracle_pubkey: &[u8; 32],
    expected_message_commitment: &[u8; 32],
    locktime_daa: u64,
    salt: &[u8; 16],
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut script = Vec::with_capacity(240);

    script.push(0x10);
    script.extend_from_slice(salt);
    script.push(OP_DROP);

    // Owner refund after timeout.
    script.push(OP_IF);
    push_pubkey(&mut script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_1);

    script.push(OP_ELSE);

    // Beneficiary claim: the oracle signature must be over this covenant's
    // exact, unique release-statement commitment. The oracle is NOT granted a
    // transaction-spend branch; optional beacons are ordinary oracle-funded
    // deposits carrying the authenticated attestation in the transaction payload.
    push_pubkey(&mut script, beneficiary_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_data(&mut script, expected_message_commitment);
    push_pubkey(&mut script, oracle_pubkey);
    script.push(OP_CHECKSIGFROMSTACK);
    script.push(OP_VERIFY);
    script.push(OP_1);

    script.push(OP_ENDIF);
    script
}

fn oracle_v1_layout_matches(script: &[u8], tail: usize) -> bool {
    use super::covenant_ops::*;
    let fixed = [
        (0usize, 0x10),
        (17, OP_DROP),
        (18, OP_IF),
        (19, 32),
        (52, OP_CHECKSIGVERIFY),
        (tail, OP_CHECKLOCKTIMEVERIFY),
        (tail + 1, OP_1),
        (tail + 2, OP_ELSE),
        (tail + 3, 32),
        (tail + 36, OP_CHECKSIGVERIFY),
        (tail + 37, 32),
        (tail + 70, 32),
        (tail + 103, OP_CHECKSIGFROMSTACK),
        (tail + 104, OP_VERIFY),
        (tail + 105, OP_1),
        (tail + 106, OP_ENDIF),
    ];
    fixed
        .iter()
        .all(|(index, expected)| script.get(*index) == Some(expected))
}

fn oracle_v1_bound_fields(script: &[u8], tail: usize) -> Option<OracleV1BoundFields> {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(script.get(1..17)?);
    let mut owner = [0u8; 32];
    owner.copy_from_slice(script.get(20..52)?);
    let mut beneficiary = [0u8; 32];
    beneficiary.copy_from_slice(script.get(tail + 4..tail + 36)?);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(script.get(tail + 38..tail + 70)?);
    let mut oracle = [0u8; 32];
    oracle.copy_from_slice(script.get(tail + 71..tail + 103)?);
    Some((salt, owner, beneficiary, commitment, oracle))
}

pub fn oracle_v1_attestation_binding(script: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    // Exact canonical layout. Everything after the variable-width locktime push
    // is fixed at 107 bytes, and everything before it is fixed at 53 bytes.
    // Parsing the fields and rebuilding the script prevents imported data from
    // smuggling extra branches around an Oracle-looking claim segment.
    let tail = script.len().checked_sub(107)?;
    if tail < 53 || !oracle_v1_layout_matches(script, tail) {
        return None;
    }
    let locktime = crate::protocol::script::extract_cltv_locktime(script)
        .ok()
        .flatten()?;
    let (salt, owner, beneficiary, commitment, oracle) = oracle_v1_bound_fields(script, tail)?;
    let canonical = build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        locktime,
        &salt,
    );
    (canonical.as_slice() == script).then_some((beneficiary, commitment, oracle))
}

pub fn oracle_v1_script_commits_to(
    script: &[u8],
    commitment: &[u8; 32],
    oracle_pubkey: &[u8; 32],
) -> bool {
    oracle_v1_attestation_binding(script).is_some_and(
        |(_, embedded_commitment, embedded_oracle)| {
            embedded_commitment == *commitment && embedded_oracle == *oracle_pubkey
        },
    )
}
