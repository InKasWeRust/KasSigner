use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::*;

fn xonly(secret: [u8; 32]) -> [u8; 32] {
    let public = k256::SecretKey::from_slice(&secret).unwrap().public_key();
    let encoded = public.to_encoded_point(true);
    let mut x = [0u8; 32];
    x.copy_from_slice(&encoded.as_bytes()[1..]);
    x
}

#[test]
fn oracle_attestation_decode_and_redeem_binding_are_native_testable() {
    let owner = xonly([1; 32]);
    let beneficiary = xonly([2; 32]);
    let oracle_secret = [3; 32];
    let oracle = xonly(oracle_secret);
    let commitment = [0x44; 32];
    let signature = offline_signer::crypto::schnorr::schnorr_sign(&oracle_secret, &commitment)
        .expect("oracle signature");
    let redeem = crate::contracts::covenant::script::build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        99,
        &[0x55; 16],
    );
    let checked = checked_redeem_and_attestation(
        &hex::encode(&redeem),
        &hex::encode(oracle),
        &hex::encode(signature.bytes),
        &hex::encode(commitment),
    )
    .expect("bound attestation");
    assert_eq!(checked, redeem);

    assert!(decode_attestation(
        "00",
        &hex::encode(signature.bytes),
        &hex::encode(commitment)
    )
    .is_err());
    assert!(decode_attestation(&hex::encode(oracle), "00", &hex::encode(commitment)).is_err());
    assert!(decode_attestation(&hex::encode(oracle), &hex::encode(signature.bytes), "00").is_err());
    assert!(checked_redeem_and_attestation(
        &hex::encode(&redeem),
        &hex::encode(oracle),
        &hex::encode(signature.bytes),
        &hex::encode([0x45; 32]),
    )
    .is_err());
    let mut bad_signature = signature.bytes;
    bad_signature[63] ^= 1;
    assert!(checked_redeem_and_attestation(
        &hex::encode(&redeem),
        &hex::encode(oracle),
        &hex::encode(bad_signature),
        &hex::encode(commitment),
    )
    .is_err());
}

#[test]
fn oracle_builder_rejects_empty_oversized_and_invalid_key_identity_inputs() {
    let owner = hex::encode(xonly([1; 32]));
    let beneficiary = hex::encode(xonly([2; 32]));
    let oracle = hex::encode(xonly([3; 32]));
    assert!(build_oracle_v1_json(
        &owner,
        &beneficiary,
        &oracle,
        &"11".repeat(32),
        "   ",
        1,
        "kaspa"
    )
    .is_err());
    assert!(build_oracle_v1_json(
        &owner,
        &beneficiary,
        &oracle,
        &"00".repeat(32),
        "Release",
        1,
        "kaspa"
    )
    .is_err());
    assert!(
        build_oracle_v1_json(&owner, &beneficiary, &oracle, "11", "Release", 1, "kaspa").is_err()
    );
    assert!(build_oracle_v1_json(
        &owner,
        &beneficiary,
        &oracle,
        &"11".repeat(32),
        &"x".repeat(300),
        1,
        "kaspa"
    )
    .is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn oracle_v1_wasm_facade_and_claim_transport_paths_are_host_exercised() {
    let owner = xonly([1; 32]);
    let beneficiary = xonly([2; 32]);
    let oracle_secret = [3; 32];
    let oracle = xonly(oracle_secret);
    let commitment = [0x44; 32];
    let signature = offline_signer::crypto::schnorr::schnorr_sign(&oracle_secret, &commitment)
        .expect("oracle signature");
    assert!(verify_oracle_v1_attestation(
        &hex::encode(oracle),
        &hex::encode(signature.bytes),
        &hex::encode(commitment),
    )
    .expect("oracle verify wrapper"));

    let built = covenant_oracle_v1(
        &hex::encode(owner),
        &hex::encode(beneficiary),
        &hex::encode(oracle),
        &"11".repeat(32),
        "Release after audit quorum",
        99,
        "mainnet",
    )
    .expect("oracle covenant wrapper");
    let value: serde_json::Value = serde_json::from_str(&built).unwrap();
    assert_eq!(value["type"], "oracle-v1");

    let redeem = crate::contracts::covenant::script::build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        99,
        &[0x55; 16],
    );
    let address = crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa")
        .expect("covenant address");
    let destination = crate::account::address::encode_p2pk_address(&beneficiary, "kaspa");
    let result = crate::wasm_api::test_support::ready(create_covenant_oracle_v1_claim(
        &address,
        &destination,
        &hex::encode(&redeem),
        &hex::encode(oracle),
        &hex::encode(signature.bytes),
        &hex::encode(commitment),
        1,
        "ws://unused",
    ));
    assert!(result.is_err());
}
