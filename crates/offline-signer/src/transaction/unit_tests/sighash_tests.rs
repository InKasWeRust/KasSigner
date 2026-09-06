use super::*;

// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: Keyed Blake2b produces different output than unkeyed.
pub fn test_keyed_differs() -> bool {
    let data = b"test data for keyed hash check";

    // Unkeyed
    let plain = blake2b_hash(data);

    // Keyed with signing hash domain key
    let mut h = KaspaBlake2b::new();
    h.update(data);
    let keyed = h.finalize();

    // They MUST differ — if they're the same, keying is not working
    plain != keyed
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: basic sighash computation for a single-input transaction.
pub fn test_sighash_basic() -> bool {
    // Create a simple transaction: 1 input, 1 output
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    // Input: UTXO with 5 KAS (500_000_000 sompi)
    tx.inputs[0].previous_outpoint.transaction_id = [0xAA; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 500_000_000;
    // Script P2PK: OP_DATA_32 <pubkey_x> OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send 4.99 KAS
    tx.outputs[0].value = 499_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // The sighash must not be all zeros
    let all_zero = sighash.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    // Must be deterministic
    let sighash2 = calculate_sighash(&tx, 0, SigHashType::All);
    sighash == sighash2
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: different inputs produce different sighashes.
pub fn test_sighash_different_inputs() -> bool {
    // Transaction with 2 inputs — each must have a different sighash
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 0;
    tx.num_inputs = 2;
    tx.num_outputs = 1;

    // Input 0
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 100_000_000;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xAA; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Input 1
    tx.inputs[1].previous_outpoint.transaction_id = [0x22; 32];
    tx.inputs[1].previous_outpoint.index = 1;
    tx.inputs[1].sequence = u64::MAX;
    tx.inputs[1].sig_op_count = 1;
    tx.inputs[1].utxo_entry.amount = 200_000_000;
    tx.inputs[1].utxo_entry.script_public_key.version = 0;
    tx.inputs[1].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[1].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[1].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[1].utxo_entry.script_public_key.script_len = 34;

    // Output
    tx.outputs[0].value = 290_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    let sighash0 = calculate_sighash(&tx, 0, SigHashType::All);
    let sighash1 = calculate_sighash(&tx, 1, SigHashType::All);

    // Must differ (each input has different outpoint, amount, script)
    sighash0 != sighash1
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: complete transaction signing pipeline.
pub fn test_sign_transaction_complete() -> bool {
    use crate::crypto::schnorr;
    use crate::derivation::bip32;
    use crate::derivation::bip39;

    // 1. Generate wallet
    let entropy = [0u8; 16];
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // 2. Create transaction: 1 input (our UTXO), 1 output
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    tx.inputs[0].previous_outpoint.transaction_id = [0x42; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = 0;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000; // 10 KAS

    // Script of the UTXO = P2PK with our pubkey
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pubkey_x);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send to another destination
    tx.outputs[0].value = 999_000_000; // 9.99 KAS (fee = 0.01 KAS)
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]); // destination
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // 3. Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // 4. Sign with Schnorr
    let sig = match schnorr::schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 5. Verify signature
    schnorr::schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: KAS amount formatting.
pub fn test_format_kas() -> bool {
    let mut buf = [0u8; 32];

    // 1.0 KAS = 100_000_000 sompi
    let len = Transaction::format_kas(100_000_000, &mut buf);
    if &buf[..len] != b"1.00" {
        return false;
    }

    // 10.5 KAS
    let len = Transaction::format_kas(1_050_000_000, &mut buf);
    if &buf[..len] != b"10.5" {
        return false;
    }

    // 0.001 KAS
    let len = Transaction::format_kas(100_000, &mut buf);
    if &buf[..len] != b"0.001" {
        return false;
    }

    true
}

/// Runs all sighash tests
#[cfg(any(test, feature = "verbose-boot"))]
/// Run all sighash test vectors.
pub fn run_sighash_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_keyed_differs() {
        passed += 1;
    }
    if test_sighash_basic() {
        passed += 1;
    }
    if test_sighash_different_inputs() {
        passed += 1;
    }
    if test_sign_transaction_complete() {
        passed += 1;
    }
    if test_format_kas() {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn sighash_vectors_pass() {
    let (passed, total) = run_sighash_tests();
    assert_eq!(passed, total);
}

#[test]
fn input_aux_randomness_binds_message_input_and_entropy() {
    use super::signing::input_aux_rand;

    let sighash = [0x3C; 32];
    let changed_sighash = [0xC3; 32];
    let first = input_aux_rand(&[0xA5; 32], &sighash, 0);
    let second = input_aux_rand(&[0xA5; 32], &sighash, 1);
    let different_entropy = input_aux_rand(&[0x5A; 32], &sighash, 0);
    let different_message = input_aux_rand(&[0xA5; 32], &changed_sighash, 0);
    assert_ne!(first, second);
    assert_ne!(first, different_entropy);
    assert_ne!(first, different_message);
}

#[test]
fn component_hashes_cover_all_sighash_and_covenant_payload_branches() {
    use super::components::{
        outputs_hash, payload_hash, previous_outputs_hash, sequences_hash, sig_op_counts_hash,
    };

    let mut tx = Transaction::try_new().expect("transaction test allocation");
    tx.version = 1;
    tx.num_inputs = 2;
    tx.num_outputs = 2;
    for index in 0..2 {
        tx.inputs[index].previous_outpoint.transaction_id = [index as u8 + 1; 32];
        tx.inputs[index].previous_outpoint.index = index as u32;
        tx.inputs[index].sequence = 10 + index as u64;
        tx.inputs[index].sig_op_count = index as u8 + 1;
        tx.inputs[index].utxo_entry.amount = 100 + index as u64;
        tx.outputs[index].value = 90 + index as u64;
        tx.outputs[index].script_public_key.script[0] = 0x20;
        tx.outputs[index].script_public_key.script[1..33].fill(0x30 + index as u8);
        tx.outputs[index].script_public_key.script[33] = 0xac;
        tx.outputs[index].script_public_key.script_len = 34;
    }
    tx.outputs[0].has_covenant = true;
    tx.outputs[0].covenant_auth_input = 1;
    tx.outputs[0].covenant_id = [0x77; 32];

    assert_ne!(previous_outputs_hash(&tx, SigHashType::All), [0; 32]);
    assert_eq!(
        previous_outputs_hash(&tx, SigHashType::AllAnyOneCanPay),
        [0; 32]
    );
    assert_ne!(sequences_hash(&tx, SigHashType::All), [0; 32]);
    for sighash in [
        SigHashType::None,
        SigHashType::Single,
        SigHashType::AllAnyOneCanPay,
    ] {
        assert_eq!(sequences_hash(&tx, sighash), [0; 32]);
    }
    assert_ne!(sig_op_counts_hash(&tx, SigHashType::All), [0; 32]);
    assert_eq!(
        sig_op_counts_hash(&tx, SigHashType::AllAnyOneCanPay),
        [0; 32]
    );

    let all = outputs_hash(&tx, SigHashType::All, 0);
    let single_zero = outputs_hash(&tx, SigHashType::Single, 0);
    let single_one = outputs_hash(&tx, SigHashType::Single, 1);
    assert_ne!(all, [0; 32]);
    assert_ne!(single_zero, single_one);
    assert_eq!(outputs_hash(&tx, SigHashType::None, 0), [0; 32]);
    assert_eq!(outputs_hash(&tx, SigHashType::Single, 2), [0; 32]);

    tx.outputs[0].has_covenant = false;
    assert_ne!(outputs_hash(&tx, SigHashType::All, 0), all);

    assert_eq!(
        payload_hash(&Transaction::try_new().expect("transaction test allocation")),
        [0; 32]
    );
    tx.payload[..3].copy_from_slice(b"KSP");
    tx.payload_len = 3;
    assert_ne!(payload_hash(&tx), [0; 32]);
    tx.payload_len = 0;
    tx.subnetwork_id = [1; 20];
    assert_ne!(payload_hash(&tx), [0; 32]);
}

#[test]
fn blake2b_known_answer_vectors_cover_streaming_boundaries() {
    const PLAIN_EMPTY: [u8; 32] = [
        0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda,
        0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f,
        0xe3, 0xa8,
    ];
    const PLAIN_ABC: [u8; 32] = [
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57,
        0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5,
        0x23, 0x19,
    ];
    const PLAIN_256: [u8; 32] = [
        0x39, 0xa7, 0xeb, 0x9f, 0xed, 0xc1, 0x9a, 0xab, 0xc8, 0x34, 0x25, 0xc6, 0x75, 0x5d, 0xd9,
        0x0e, 0x6f, 0x9d, 0x0c, 0x80, 0x49, 0x64, 0xa1, 0xf4, 0xaa, 0xee, 0xa3, 0xb9, 0xfb, 0x59,
        0x98, 0x35,
    ];
    const KEYED_EMPTY: [u8; 32] = [
        0x34, 0xc7, 0x50, 0x37, 0xad, 0x62, 0x74, 0x0d, 0x4b, 0x32, 0x28, 0xf8, 0x8f, 0x84, 0x4f,
        0x79, 0x01, 0xc0, 0x7b, 0xfa, 0xcd, 0x55, 0xa0, 0x45, 0xbe, 0x51, 0x8e, 0xab, 0xc1, 0x5e,
        0x52, 0xce,
    ];
    const KEYED_ABC: [u8; 32] = [
        0x1d, 0x25, 0xf7, 0xb1, 0x95, 0x71, 0xef, 0x69, 0xf5, 0xa7, 0xfa, 0xc4, 0x49, 0x4f, 0x74,
        0xbb, 0x9c, 0x41, 0x0e, 0xc4, 0x85, 0x57, 0x0b, 0xee, 0xfe, 0x5a, 0x7e, 0x8d, 0x11, 0xfc,
        0xc4, 0x65,
    ];
    const KEYED_128: [u8; 32] = [
        0x5f, 0x55, 0x37, 0x39, 0xcb, 0x20, 0x82, 0xab, 0x93, 0x2a, 0x23, 0x28, 0x75, 0x2e, 0x4b,
        0x0e, 0xd8, 0xf1, 0xc2, 0xb5, 0x18, 0x0c, 0x99, 0xf3, 0xf0, 0xd8, 0xfc, 0x07, 0xa0, 0x81,
        0x20, 0x70,
    ];
    const KEYED_129: [u8; 32] = [
        0x66, 0x75, 0x8f, 0x74, 0x65, 0xc3, 0x7b, 0xcc, 0x89, 0xb9, 0xe7, 0x0f, 0xb2, 0x87, 0x7c,
        0xb9, 0x44, 0x48, 0x63, 0x50, 0x58, 0xee, 0x1d, 0xa3, 0xd5, 0x5c, 0xbc, 0x65, 0x01, 0x2c,
        0x02, 0x85,
    ];
    const KEYED_256: [u8; 32] = [
        0xc8, 0x38, 0x49, 0x0f, 0x31, 0x7e, 0x96, 0x38, 0x42, 0x93, 0x48, 0x04, 0xa0, 0xfe, 0xbf,
        0xdc, 0xb7, 0xf5, 0x56, 0x19, 0xe2, 0xa0, 0xb6, 0x6a, 0xe9, 0x38, 0x46, 0x14, 0xb6, 0xc2,
        0x19, 0xa3,
    ];

    assert_eq!(blake2b_hash(b""), PLAIN_EMPTY);
    assert_eq!(blake2b_hash(b"abc"), PLAIN_ABC);
    let all_bytes = core::array::from_fn::<u8, 256, _>(|index| index as u8);
    assert_eq!(blake2b_hash(&all_bytes), PLAIN_256);

    fn keyed(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = KaspaBlake2b::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    assert_eq!(keyed(&[]), KEYED_EMPTY);
    assert_eq!(keyed(&[b"abc"]), KEYED_ABC);

    let bytes_128 = [b'x'; 128];
    let bytes_129 = [b'x'; 129];
    let bytes_256 = [b'x'; 256];
    assert_eq!(keyed(&[&bytes_128]), KEYED_128);
    assert_eq!(keyed(&[&bytes_129]), KEYED_129);
    assert_eq!(keyed(&[&bytes_256]), KEYED_256);

    assert_eq!(
        keyed(&[&bytes_129[..1], &bytes_129[1..128], &bytes_129[128..]]),
        KEYED_129
    );
    assert_eq!(keyed(&[&bytes_129[..1], &bytes_129[1..]]), KEYED_129);
    assert_eq!(
        keyed(&[
            &bytes_256[..127],
            &bytes_256[127..128],
            &bytes_256[128..129],
            &bytes_256[129..]
        ]),
        KEYED_256
    );
}

#[test]
fn blake2b_compression_binds_both_counter_halves_and_final_block_flag() {
    use super::blake2b::compress;

    let mut state = [0u64, 1, 2, 3, 4, 5, 6, 7];
    let block = core::array::from_fn::<u8, 128, _>(|index| index as u8);
    compress(
        &mut state,
        &block,
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        true,
    );
    assert_eq!(
        state,
        [
            0xc533_9e18_4c5d_8220,
            0x141e_0970_9f48_086a,
            0xf7d9_b1a7_baba_3bcc,
            0xc550_7a4a_3052_3324,
            0xc6d2_e0f7_b590_ba89,
            0x9aa9_3c30_5e5f_c052,
            0x31b8_9c5c_a616_04e0,
            0x0675_ee8d_67b6_236a,
        ],
    );
}

#[test]
fn final_sighash_binds_every_serialized_field_and_version_zero_sigops_only() {
    fn fixture(version: u16) -> Transaction {
        let mut tx = Transaction::try_new().expect("transaction test allocation");
        tx.version = version;
        tx.num_inputs = 1;
        tx.num_outputs = 1;
        tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
        tx.inputs[0].previous_outpoint.index = 3;
        tx.inputs[0].sequence = 7;
        tx.inputs[0].sig_op_count = 2;
        tx.inputs[0].utxo_entry.amount = 123_456_789;
        tx.inputs[0].utxo_entry.script_public_key.version = 4;
        tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
        tx.inputs[0].utxo_entry.script_public_key.script[1..33].fill(0x22);
        tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xac;
        tx.inputs[0].utxo_entry.script_public_key.script_len = 34;
        tx.outputs[0].value = 120_000_000;
        tx.outputs[0].script_public_key.version = 5;
        tx.outputs[0].script_public_key.script[0] = 0x20;
        tx.outputs[0].script_public_key.script[1..33].fill(0x33);
        tx.outputs[0].script_public_key.script[33] = 0xac;
        tx.outputs[0].script_public_key.script_len = 34;
        tx.locktime = 9;
        tx.subnetwork_id = [0x44; 20];
        tx.gas = 10;
        tx.payload[..3].copy_from_slice(b"abc");
        tx.payload_len = 3;
        tx
    }

    fn digest(tx: &Transaction) -> [u8; 32] {
        calculate_sighash(tx, 0, SigHashType::All)
    }

    let baseline_tx = fixture(0);
    let baseline = digest(&baseline_tx);

    macro_rules! differs {
        ($name:literal, $edit:expr) => {{
            let mut changed = fixture(0);
            $edit(&mut changed);
            assert_ne!(digest(&changed), baseline, $name);
        }};
    }

    differs!("version", |tx: &mut Transaction| tx.version = 1);
    differs!("previous tx id", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .transaction_id[0] ^=
        1);
    differs!("previous index", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .index += 1);
    differs!("script version", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .script_public_key
        .version += 1);
    differs!("script bytes", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .script_public_key
        .script[1] ^= 1);
    differs!("amount", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .amount += 1);
    differs!("sequence", |tx: &mut Transaction| tx.inputs[0].sequence +=
        1);
    differs!("version-zero sigop", |tx: &mut Transaction| tx.inputs[0]
        .sig_op_count +=
        1);
    differs!("output", |tx: &mut Transaction| tx.outputs[0].value += 1);
    differs!("locktime", |tx: &mut Transaction| tx.locktime += 1);
    differs!("subnetwork", |tx: &mut Transaction| tx.subnetwork_id[0] ^=
        1);
    differs!("gas", |tx: &mut Transaction| tx.gas += 1);
    differs!("payload", |tx: &mut Transaction| tx.payload[1] ^= 1);
    assert_ne!(
        calculate_sighash(&baseline_tx, 0, SigHashType::None),
        baseline,
        "sighash type"
    );

    let version_one = fixture(1);
    let version_one_digest = digest(&version_one);
    let mut changed_sigop = fixture(1);
    changed_sigop.inputs[0].sig_op_count += 1;
    assert_eq!(
        digest(&changed_sigop),
        version_one_digest,
        "version 1 excludes sig-op count from the final digest",
    );

    let version_two = fixture(2);
    let version_two_digest = digest(&version_two);
    let mut changed_v2_sigop = fixture(2);
    changed_v2_sigop.inputs[0].sig_op_count += 1;
    assert_eq!(
        digest(&changed_v2_sigop),
        version_two_digest,
        "every non-zero version excludes version-zero sig-op fields",
    );
}
