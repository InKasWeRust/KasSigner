use k256::elliptic_curve::sec1::ToEncodedPoint;

use super::super::adaptor::{
    complete_presignature, extract_secret, verify_bip340, verify_host_nonce_relation,
    verify_presignature, AdaptorPreSignature,
};

struct Fixture {
    public_x: [u8; 32],
    message: [u8; 32],
    adaptor_point_x: [u8; 32],
    adaptor_secret: [u8; 32],
    session_id: [u8; 16],
    host_secret: [u8; 32],
    base_nonce_point: [u8; 33],
    presig: AdaptorPreSignature,
}

fn fixture() -> Fixture {
    let private_key = [3u8; 32];
    let raw_adaptor_secret = [7u8; 32];
    let message = [9u8; 32];
    let session_id = [4u8; 16];
    let aux = [5u8; 32];
    let host_secret = [6u8; 32];
    let (adaptor_secret, adaptor_point_x) =
        offline_signer::crypto::adaptor::adaptor_point_from_secret(&raw_adaptor_secret)
            .expect("adaptor point");
    let base_nonce_point = offline_signer::crypto::adaptor::adaptor_base_nonce_point(
        &private_key,
        &message,
        &adaptor_point_x,
        &session_id,
        &aux,
    )
    .expect("base nonce");
    let generated = offline_signer::crypto::adaptor::create_adaptor_presignature(
        &private_key,
        &message,
        &adaptor_point_x,
        &session_id,
        &aux,
        &host_secret,
    )
    .expect("presignature");
    let public = k256::SecretKey::from_slice(&private_key)
        .expect("secret")
        .public_key();
    let encoded = public.to_encoded_point(true);
    let mut public_x = [0u8; 32];
    public_x.copy_from_slice(&encoded.as_bytes()[1..]);
    Fixture {
        public_x,
        message,
        adaptor_point_x,
        adaptor_secret,
        session_id,
        host_secret,
        base_nonce_point,
        presig: AdaptorPreSignature {
            bytes: generated.bytes,
            negated: generated.negated,
        },
    }
}

#[test]
fn public_adaptor_math_verifies_completes_extracts_and_checks_host_nonce_relation() {
    let f = fixture();
    verify_presignature(&f.public_x, &f.message, &f.presig, &f.adaptor_point_x)
        .expect("valid presignature");
    verify_host_nonce_relation(
        &f.public_x,
        &f.message,
        &f.adaptor_point_x,
        &f.session_id,
        &f.host_secret,
        &f.base_nonce_point,
        &f.presig,
    )
    .expect("host relation");

    let completed = complete_presignature(&f.presig, &f.adaptor_secret).expect("complete");
    verify_bip340(&f.public_x, &f.message, &completed).expect("completed BIP340");
    assert_eq!(
        extract_secret(&completed, &f.presig).expect("extract"),
        f.adaptor_secret
    );
}

#[test]
fn negated_presignature_host_relation_and_completion_are_bip340_valid() {
    let private_key = [3u8; 32];
    let raw_adaptor_secret = [7u8; 32];
    let message = [0x81u8; 32];
    let session_id = [0x82u8; 16];
    let host_secret = [0x83u8; 32];
    let (adaptor_secret, adaptor_point_x) =
        offline_signer::crypto::adaptor::adaptor_point_from_secret(&raw_adaptor_secret)
            .expect("adaptor point");
    let public = k256::SecretKey::from_slice(&private_key)
        .expect("secret")
        .public_key();
    let encoded = public.to_encoded_point(true);
    let mut public_x = [0u8; 32];
    public_x.copy_from_slice(&encoded.as_bytes()[1..]);

    for aux_byte in 1u8..=u8::MAX {
        let aux = [aux_byte; 32];
        let base_nonce_point = offline_signer::crypto::adaptor::adaptor_base_nonce_point(
            &private_key,
            &message,
            &adaptor_point_x,
            &session_id,
            &aux,
        )
        .expect("base nonce");
        let generated = offline_signer::crypto::adaptor::create_adaptor_presignature(
            &private_key,
            &message,
            &adaptor_point_x,
            &session_id,
            &aux,
            &host_secret,
        )
        .expect("presignature");
        if !generated.negated {
            continue;
        }
        let presig = AdaptorPreSignature {
            bytes: generated.bytes,
            negated: true,
        };
        verify_host_nonce_relation(
            &public_x,
            &message,
            &adaptor_point_x,
            &session_id,
            &host_secret,
            &base_nonce_point,
            &presig,
        )
        .expect("negated host relation");
        let completed =
            complete_presignature(&presig, &adaptor_secret).expect("negated completion");
        verify_bip340(&public_x, &message, &completed).expect("negated completion is BIP340-valid");
        assert_eq!(
            extract_secret(&completed, &presig).expect("extract"),
            adaptor_secret
        );
        return;
    }
    panic!("deterministic fixture did not produce a negated adaptor nonce");
}

#[test]
fn adaptor_verifiers_fail_closed_for_wrong_points_messages_scalars_and_host_secrets() {
    let f = fixture();
    assert!(verify_presignature(&[0; 32], &f.message, &f.presig, &f.adaptor_point_x).is_err());
    assert!(verify_presignature(&f.public_x, &f.message, &f.presig, &[0; 32]).is_err());
    let mut bad_presig = f.presig;
    bad_presig.bytes[63] ^= 1;
    assert!(verify_presignature(&f.public_x, &f.message, &bad_presig, &f.adaptor_point_x).is_err());

    assert!(verify_host_nonce_relation(
        &f.public_x,
        &f.message,
        &f.adaptor_point_x,
        &f.session_id,
        &[0x77; 32],
        &f.base_nonce_point,
        &f.presig,
    )
    .is_err());
    let mut bad_base = f.base_nonce_point;
    bad_base[0] = 0x04;
    assert!(verify_host_nonce_relation(
        &f.public_x,
        &f.message,
        &f.adaptor_point_x,
        &f.session_id,
        &f.host_secret,
        &bad_base,
        &f.presig,
    )
    .is_err());

    assert!(complete_presignature(&f.presig, &[0; 32]).is_err());
    let completed = complete_presignature(&f.presig, &f.adaptor_secret).expect("complete");
    assert!(verify_bip340(&f.public_x, &[0x55; 32], &completed).is_err());
    assert!(verify_bip340(&[0; 32], &f.message, &completed).is_err());

    let mut wrong_nonce = completed;
    wrong_nonce[0] ^= 1;
    assert!(extract_secret(&wrong_nonce, &f.presig).is_err());
    assert!(extract_secret(&f.presig.bytes, &f.presig).is_err());
}
