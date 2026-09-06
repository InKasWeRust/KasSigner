use super::*;
use k256::schnorr::SigningKey;

#[test]
fn final_signature_is_bip340_and_bound_to_host_nonce() {
    let private_key = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ];
    let message = [0xA5u8; 32];
    let provisional =
        crate::crypto::schnorr::schnorr_sign_with_aux_rand(&private_key, &message, &[0x19u8; 32])
            .unwrap();
    let nonce_point = provisional_nonce_point(&provisional);
    let session = [0x33u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    let host_secret = [0x55u8; 32];
    let final_signature = tweak_provisional_signature(
        &private_key,
        &message,
        &provisional,
        &session,
        &host_secret,
        0,
        0,
    )
    .unwrap();

    let signing_key = SigningKey::from_bytes(&private_key).unwrap();
    let public_x: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    crate::crypto::schnorr::schnorr_verify(&public_x, &message, &final_signature).unwrap();
    let public_key = canonical_public_key(&public_x);
    verify_nonce_relation(
        &nonce_point,
        &final_signature,
        &session,
        &host_secret,
        0,
        0,
        &public_key,
    )
    .unwrap();
    assert_ne!(final_signature.r_bytes(), provisional.r_bytes());
}

#[test]
fn wrong_host_secret_breaks_nonce_relation() {
    let private_key = [1u8; 32];
    let message = [2u8; 32];
    let provisional =
        crate::crypto::schnorr::schnorr_sign_with_aux_rand(&private_key, &message, &[3u8; 32])
            .unwrap();
    let session = [4u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    let final_signature = tweak_provisional_signature(
        &private_key,
        &message,
        &provisional,
        &session,
        &[5u8; 32],
        1,
        2,
    )
    .unwrap();
    let signing_key = SigningKey::from_bytes(&private_key).unwrap();
    let public_x: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let public_key = canonical_public_key(&public_x);
    assert!(verify_nonce_relation(
        &provisional_nonce_point(&provisional),
        &final_signature,
        &session,
        &[6u8; 32],
        1,
        2,
        &public_key,
    )
    .is_err());
}
#[test]
fn host_contribution_is_unique_per_signature_context() {
    let session = [0x11u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    let secret = [0x22u8; 32];
    let public_key = {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[32] = 0x03;
        key
    };
    let mut nonce_point = public_key;
    nonce_point[32] = 0x05;
    let first = shared_signer::anti_klepto::host_scalar_material(
        &session,
        &secret,
        0,
        0,
        &public_key,
        &nonce_point,
    );
    let second = shared_signer::anti_klepto::host_scalar_material(
        &session,
        &secret,
        1,
        0,
        &public_key,
        &nonce_point,
    );
    let third = shared_signer::anti_klepto::host_scalar_material(
        &session,
        &secret,
        0,
        1,
        &public_key,
        &nonce_point,
    );
    assert_ne!(first, second);
    assert_ne!(first, third);
}

#[test]
fn anti_klepto_rejects_invalid_key_points_and_scalar_boundaries() {
    let message = [0x42u8; 32];
    let signature = SchnorrSignature { bytes: [0u8; 64] };
    let session = [0x31u8; shared_signer::anti_klepto::SESSION_ID_LEN];
    let host_secret = [0x52u8; 32];
    assert_eq!(
        tweak_provisional_signature(
            &[0u8; 32],
            &message,
            &signature,
            &session,
            &host_secret,
            0,
            0
        ),
        Err(AntiKleptoError::InvalidPrivateKey),
    );

    let private_key = [1u8; 32];
    let provisional =
        crate::crypto::schnorr::schnorr_sign_with_aux_rand(&private_key, &message, &[0x63u8; 32])
            .expect("provisional signature");
    let signing_key = SigningKey::from_bytes(&private_key).expect("signing key");
    let public_x: [u8; 32] = signing_key.verifying_key().to_bytes().into();
    let public_key = canonical_public_key(&public_x);
    let final_signature = tweak_provisional_signature(
        &private_key,
        &message,
        &provisional,
        &session,
        &host_secret,
        0,
        0,
    )
    .expect("final signature");

    let mut odd_public = public_key;
    odd_public[0] = 0x03;
    assert_eq!(
        verify_nonce_relation(
            &provisional_nonce_point(&provisional),
            &final_signature,
            &session,
            &host_secret,
            0,
            0,
            &odd_public,
        ),
        Err(AntiKleptoError::InvalidNoncePoint),
    );
    let mut odd_nonce = provisional_nonce_point(&provisional);
    odd_nonce[0] = 0x03;
    assert_eq!(
        verify_nonce_relation(
            &odd_nonce,
            &final_signature,
            &session,
            &host_secret,
            0,
            0,
            &public_key
        ),
        Err(AntiKleptoError::InvalidNoncePoint),
    );
    assert!(scalar_from_canonical(&[0xff; 32]).is_none());
    assert_eq!(point_x_and_parity(&ProjectivePoint::IDENTITY), None);
    assert!(shared_signer::bytes::constant_time_eq(
        &[0x11; 32],
        &[0x11; 32]
    ));
    assert!(!shared_signer::bytes::constant_time_eq(
        &[0x11; 32],
        &[0x12; 32]
    ));
}

fn scalar_bytes(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

#[test]
fn anti_klepto_zero_scalar_and_nonce_cancellation_fail_closed() {
    assert_eq!(
        nonzero_host_scalar(&[0u8; 32]),
        Err(AntiKleptoError::InvalidHostContribution)
    );
    assert!(nonzero_host_scalar(&scalar_bytes(1)).is_ok());
    let one = scalar_from_canonical(&scalar_bytes(1)).expect("scalar one");
    assert_eq!(
        nonzero_nonce_sum(one, -one),
        Err(AntiKleptoError::InvalidHostContribution)
    );
    assert!(nonzero_nonce_sum(one, one).is_ok());
}

#[test]
fn anti_klepto_rejects_a_provisional_signature_with_zero_recovered_nonce() {
    let private_key = scalar_bytes(1);
    let message = [0x71u8; 32];
    let (_, public_x) = normalized_secret_and_public_x(&private_key).expect("normalized key");
    let secret = scalar_from_canonical(&private_key).expect("secret scalar");
    let r = [0x21u8; 32];
    let response = challenge(&r, &public_x, &message) * secret;
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(&response.to_bytes());
    let provisional = SchnorrSignature { bytes };
    assert_eq!(
        tweak_provisional_signature(
            &private_key,
            &message,
            &provisional,
            &[0x11; shared_signer::anti_klepto::SESSION_ID_LEN],
            &[0x22; 32],
            0,
            0,
        ),
        Err(AntiKleptoError::InvalidProvisionalSignature),
    );
}
