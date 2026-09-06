use crate::transaction::{
    kspt::{
        parse_compact_kspt, serialize_compact_kspt, sign_transaction, PsktError, SignedResponse,
    },
    model::{SigHashType, Transaction},
};

#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_compact_roundtrip() -> bool {
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 0;
    tx.network = crate::address::KaspaNetwork::Mainnet;
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].utxo_entry.amount = 10_000;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xac;
    tx.inputs[0].sig_count = 1;
    tx.inputs[0].sighash_type = SigHashType::All.to_byte();
    tx.inputs[0].sigs[0].present = true;
    tx.inputs[0].sigs[0].sighash_type = SigHashType::All.to_byte();
    tx.inputs[0].sigs[0].signature = [0x22; 64];
    tx.outputs[0].value = 9_000;
    tx.outputs[0].script_public_key.script_len = 34;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[33] = 0xac;

    let mut wire = [0u8; 1024];
    let Ok(size) = serialize_compact_kspt(&tx, &mut wire) else {
        return false;
    };
    let mut parsed = Transaction::try_new().expect("transaction test allocation");
    parse_compact_kspt(&wire[..size], &mut parsed).is_ok()
        && parsed.num_inputs == 1
        && parsed.num_outputs == 1
        && parsed.inputs[0].sig_count == 1
}

#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_invalid_magic() -> bool {
    let bad_data = [0u8; 6];
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    matches!(
        parse_compact_kspt(&bad_data, &mut tx),
        Err(PsktError::InvalidMagic)
    )
}

#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_signed_response_size() -> bool {
    let mut response = SignedResponse::new();
    if response
        .add_signature(0, SigHashType::All, &[0xab; 64])
        .is_err()
    {
        return false;
    }
    let mut buffer = [0u8; 256];
    matches!(response.serialize(&mut buffer), Ok(78))
}

#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_signing_rejects_empty_transaction() -> bool {
    sign_transaction(
        &Transaction::try_new().expect("transaction test allocation"),
        &[1u8; 32],
        SigHashType::All,
    )
    .is_err()
}

#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_kspt_tests() -> (u32, u32) {
    let checks = [
        test_compact_roundtrip(),
        test_invalid_magic(),
        test_signed_response_size(),
        test_signing_rejects_empty_transaction(),
    ];
    (
        checks.iter().filter(|passed| **passed).count() as u32,
        checks.len() as u32,
    )
}

#[test]
fn compact_kspt_vectors_pass() {
    let (passed, total) = run_kspt_tests();
    assert_eq!(passed, total);
}
