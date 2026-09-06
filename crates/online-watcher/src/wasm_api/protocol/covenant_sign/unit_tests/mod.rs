use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::*;

#[test]
fn covenant_anti_klepto_host_verifier_covers_decoding_signature_and_nonce_relation() {
    let secret = [3u8; 32];
    let public = k256::SecretKey::from_slice(&secret).unwrap().public_key();
    let encoded = public.to_encoded_point(true);
    let public_x = &encoded.as_bytes()[1..];
    let commitment = [4u8; 32];
    let signature =
        offline_signer::crypto::schnorr::schnorr_sign(&secret, &commitment).expect("signature");

    let result = verify_covenant_anti_klepto_string(
        &hex::encode(public_x),
        &hex::encode(commitment),
        &hex::encode([0x02].into_iter().chain([5u8; 32]).collect::<Vec<_>>()),
        &hex::encode(signature.bytes),
        &hex::encode([6u8; shared_signer::covenant_sign::SESSION_ID_LEN]),
        &hex::encode([7u8; 32]),
    )
    .expect("decoded verifier");
    assert!(!result, "synthetic nonce relation must fail closed");

    assert!(verify_covenant_anti_klepto_string(
        "00",
        &hex::encode(commitment),
        &hex::encode([2u8; 33]),
        &hex::encode(signature.bytes),
        &hex::encode([6u8; 16]),
        &hex::encode([7u8; 32]),
    )
    .is_err());
    assert!(decode_fixed::<32>("zz", "field").is_err());
    assert!(decode_fixed::<32>("00", "field").is_err());
    assert_eq!(
        decode_fixed::<16>(&hex::encode([8u8; 16]), "field").unwrap(),
        [8u8; 16]
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn covenant_anti_klepto_wasm_boundary_rejects_bad_hex() {
    assert!(super::verify_covenant_anti_klepto("zz", "00", "00", "00", "00", "00",).is_err());
}
