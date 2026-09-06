use super::*;
use crate::crypto::schnorr::{schnorr_verify, SchnorrSignature};

#[test]
fn transaction_bound_adaptor_presign_completes_and_extracts() {
    let sk = [3u8; 32];
    let raw_t = [7u8; 32];
    let (t, t_x) = adaptor_point_from_secret(&raw_t).expect("T");
    let msg = [9u8; 32];
    let sid = [4u8; 16];
    let aux = [5u8; 32];
    let host = [6u8; 32];
    let base = adaptor_base_nonce_point(&sk, &msg, &t_x, &sid, &aux).expect("base");
    let pre = create_adaptor_presignature(&sk, &msg, &t_x, &sid, &aux, &host).expect("presig");
    let (_, px) = normalized_secret_and_public_x(&sk).expect("pk");
    verify_adaptor_presignature(&px, &msg, &pre, &t_x).expect("verify presig");
    verify_host_nonce_relation(&px, &msg, &t_x, &sid, &host, &base, &pre).expect("host relation");
    let final_bytes = complete_adaptor_presignature(&pre, &t).expect("complete");
    assert_eq!(
        complete_adaptor_presignature(&pre, &[0u8; 32]),
        Err(AdaptorError::InvalidAdaptorPoint)
    );
    let sig = SchnorrSignature { bytes: final_bytes };
    schnorr_verify(&px, &msg, &sig).expect("completed BIP340");
    assert!(
        schnorr_verify(&px, &[8u8; 32], &sig).is_err(),
        "claim signature must be transaction-sighash bound"
    );
}

#[test]
fn negated_adaptor_nonce_branch_verifies_and_completes_exactly() {
    let sk = scalar_bytes(3);
    let (adaptor_secret, adaptor_x) =
        adaptor_point_from_secret(&scalar_bytes(7)).expect("adaptor point");
    let message = [0x91u8; 32];
    let session = [0x92u8; 16];
    let host = [0x93u8; 32];
    let (_, public_x) = normalized_secret_and_public_x(&sk).expect("public key");

    for aux_byte in 1u8..=u8::MAX {
        let aux = [aux_byte; 32];
        let base = adaptor_base_nonce_point(&sk, &message, &adaptor_x, &session, &aux)
            .expect("base nonce");
        let presig = create_adaptor_presignature(&sk, &message, &adaptor_x, &session, &aux, &host)
            .expect("presignature");
        if !presig.negated {
            continue;
        }

        verify_host_nonce_relation(
            &public_x, &message, &adaptor_x, &session, &host, &base, &presig,
        )
        .expect("negated host nonce relation");
        let completed =
            complete_adaptor_presignature(&presig, &adaptor_secret).expect("negated completion");
        schnorr_verify(&public_x, &message, &SchnorrSignature { bytes: completed })
            .expect("negated completion is BIP340-valid");
        return;
    }
    panic!("deterministic fixture did not produce a negated adaptor nonce");
}

#[test]
fn host_secret_changes_final_adaptor_nonce_relation() {
    let sk = [11u8; 32];
    let (_, t_x) = adaptor_point_from_secret(&[12u8; 32]).expect("T");
    let msg = [13u8; 32];
    let sid = [14u8; 16];
    let aux = [15u8; 32];
    let base = adaptor_base_nonce_point(&sk, &msg, &t_x, &sid, &aux).expect("base");
    let pre =
        create_adaptor_presignature(&sk, &msg, &t_x, &sid, &aux, &[16u8; 32]).expect("presig");
    let (_, px) = normalized_secret_and_public_x(&sk).expect("pk");
    assert!(verify_host_nonce_relation(&px, &msg, &t_x, &sid, &[17u8; 32], &base, &pre).is_err());
}

fn scalar_bytes(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

#[test]
fn adaptor_fail_closed_scalar_and_point_boundaries_are_explicit() {
    assert_eq!(
        adaptor_point_from_secret(&[0u8; 32]),
        Err(AdaptorError::InvalidPrivateKey)
    );
    assert_eq!(
        adaptor_point_from_secret(&[0xff; 32]),
        Err(AdaptorError::InvalidPrivateKey)
    );
    assert_eq!(
        normalized_secret_and_public_x(&[0u8; 32]),
        Err(AdaptorError::InvalidPrivateKey)
    );
    assert_eq!(point_x_and_parity(&ProjectivePoint::IDENTITY), None);

    assert_eq!(
        nonzero_reduced_scalar(&[0u8; 32], AdaptorError::InvalidNonce),
        Err(AdaptorError::InvalidNonce)
    );
    assert_eq!(
        nonzero_reduced_scalar(&[0u8; 32], AdaptorError::InvalidHostContribution),
        Err(AdaptorError::InvalidHostContribution),
    );
    assert!(nonzero_reduced_scalar(&scalar_bytes(1), AdaptorError::InvalidNonce).is_ok());

    let one = scalar_from_canonical(&scalar_bytes(1)).expect("scalar one");
    assert_eq!(
        nonzero_scalar_sum(one, -one, AdaptorError::InvalidHostContribution),
        Err(AdaptorError::InvalidHostContribution),
    );
    assert!(nonzero_scalar_sum(one, one, AdaptorError::InvalidHostContribution).is_ok());
}

#[test]
fn adaptor_completion_covers_both_nonce_parities_and_rejects_tampering() {
    let mut presig = AdaptorPreSignature {
        bytes: [0u8; 64],
        negated: false,
    };
    presig.bytes[32..].copy_from_slice(&scalar_bytes(3));
    let plus =
        complete_adaptor_presignature(&presig, &scalar_bytes(1)).expect("positive completion");
    assert_eq!(&plus[32..], &scalar_bytes(4));
    presig.negated = true;
    let minus =
        complete_adaptor_presignature(&presig, &scalar_bytes(1)).expect("negative completion");
    assert_eq!(&minus[32..], &scalar_bytes(2));

    let sk = scalar_bytes(3);
    let (_, adaptor_x) = adaptor_point_from_secret(&scalar_bytes(7)).expect("adaptor point");
    let message = [0x21u8; 32];
    let session = [0x31u8; 16];
    let presig = create_adaptor_presignature(
        &sk,
        &message,
        &adaptor_x,
        &session,
        &[0x41; 32],
        &[0x51; 32],
    )
    .expect("valid presignature");
    let (_, public_x) = normalized_secret_and_public_x(&sk).expect("public key");
    let mut tampered = presig;
    tampered.bytes[63] ^= 1;
    assert_eq!(
        verify_adaptor_presignature(&public_x, &message, &tampered, &adaptor_x),
        Err(AdaptorError::InvalidPreSignature),
    );
}

#[test]
fn normalized_private_key_covers_even_and_odd_public_key_parity() {
    let raw_even = scalar_from_canonical(&scalar_bytes(1)).expect("scalar one");
    let raw_odd = scalar_from_canonical(&scalar_bytes(6)).expect("scalar six");
    let (even, _) = normalized_secret_and_public_x(&scalar_bytes(1)).expect("even public key");
    let (odd, _) = normalized_secret_and_public_x(&scalar_bytes(6)).expect("odd public key");
    assert_eq!(even, raw_even);
    assert_eq!(odd, -raw_odd);
}

#[test]
fn adaptor_public_validation_rejects_each_malformed_point_and_scalar_boundary() {
    let sk = scalar_bytes(3);
    let (_, adaptor_x) = adaptor_point_from_secret(&scalar_bytes(7)).expect("adaptor point");
    let message = [0x61u8; 32];
    let session = [0x62u8; 16];
    let aux = [0x63u8; 32];
    let host = [0x64u8; 32];
    let base =
        adaptor_base_nonce_point(&sk, &message, &adaptor_x, &session, &aux).expect("base nonce");
    let presig = create_adaptor_presignature(&sk, &message, &adaptor_x, &session, &aux, &host)
        .expect("presignature");
    let (_, public_x) = normalized_secret_and_public_x(&sk).expect("public key");

    assert_eq!(
        adaptor_base_nonce_point(&[0u8; 32], &message, &adaptor_x, &session, &aux),
        Err(AdaptorError::InvalidPrivateKey),
    );
    assert_eq!(
        adaptor_base_nonce_point(&sk, &message, &[0xff; 32], &session, &aux),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
    assert_eq!(
        create_adaptor_presignature(&[0u8; 32], &message, &adaptor_x, &session, &aux, &host,),
        Err(AdaptorError::InvalidPrivateKey),
    );
    assert_eq!(
        create_adaptor_presignature(&sk, &message, &[0xff; 32], &session, &aux, &host,),
        Err(AdaptorError::InvalidAdaptorPoint),
    );

    assert_eq!(
        verify_adaptor_presignature(&[0xff; 32], &message, &presig, &adaptor_x),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
    assert_eq!(
        verify_adaptor_presignature(&public_x, &message, &presig, &[0xff; 32]),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
    let mut bad_r = presig;
    bad_r.bytes[..32].fill(0xff);
    assert_eq!(
        verify_adaptor_presignature(&public_x, &message, &bad_r, &adaptor_x),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
    let mut bad_s = presig;
    bad_s.bytes[32..].fill(0xff);
    assert_eq!(
        verify_adaptor_presignature(&public_x, &message, &bad_s, &adaptor_x),
        Err(AdaptorError::InvalidPreSignature),
    );

    let mut bad_base = base;
    bad_base[0] = 0x04;
    assert_eq!(
        verify_host_nonce_relation(
            &public_x, &message, &adaptor_x, &session, &host, &bad_base, &presig,
        ),
        Err(AdaptorError::InvalidNonce),
    );
    assert_eq!(
        verify_host_nonce_relation(
            &public_x,
            &message,
            &[0xff; 32],
            &session,
            &host,
            &base,
            &presig,
        ),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
    assert_eq!(
        verify_host_nonce_relation(
            &public_x,
            &message,
            &adaptor_x,
            &session,
            &[0x65; 32],
            &base,
            &presig,
        ),
        Err(AdaptorError::InvalidHostContribution),
    );

    let mut invalid_scalar_presig = presig;
    invalid_scalar_presig.bytes[32..].fill(0xff);
    assert_eq!(
        complete_adaptor_presignature(&invalid_scalar_presig, &scalar_bytes(1)),
        Err(AdaptorError::InvalidPreSignature),
    );
    assert_eq!(
        complete_adaptor_presignature(&presig, &[0xff; 32]),
        Err(AdaptorError::InvalidAdaptorPoint),
    );
}

#[test]
fn host_nonce_relation_requires_addition_of_the_committed_host_scalar() {
    let sk = scalar_bytes(3);
    let (_, adaptor_x) = adaptor_point_from_secret(&scalar_bytes(7)).expect("adaptor point");
    let message = [0x71u8; 32];
    let session = [0x72u8; 16];
    let aux = [0x73u8; 32];
    let host_secret = [0x74u8; 32];
    let base =
        adaptor_base_nonce_point(&sk, &message, &adaptor_x, &session, &aux).expect("base nonce");
    let presig =
        create_adaptor_presignature(&sk, &message, &adaptor_x, &session, &aux, &host_secret)
            .expect("presignature");
    let (_, public_x) = normalized_secret_and_public_x(&sk).expect("public key");

    let base_point = public_key_to_point(&base).expect("base point");
    let host = host_scalar(
        &session,
        &host_secret,
        &public_x,
        &base,
        &message,
        &adaptor_x,
    )
    .expect("host scalar");
    let added = base_point + ProjectivePoint::GENERATOR * host;
    let subtracted = base_point + (ProjectivePoint::GENERATOR * host).neg();
    assert!(!points_equal(&added, &subtracted));

    let adaptor = xonly_to_point(&adaptor_x).expect("adaptor point");
    let r = xonly_to_point(
        presig.bytes[..32]
            .try_into()
            .expect("presignature nonce x coordinate"),
    )
    .expect("presignature nonce");
    let signed_adaptor = if presig.negated {
        adaptor.neg()
    } else {
        adaptor
    };
    let recovered = if presig.negated {
        (r + signed_adaptor.neg()).neg()
    } else {
        r + signed_adaptor.neg()
    };
    assert!(points_equal(&added, &recovered));
    verify_host_nonce_relation(
        &public_x,
        &message,
        &adaptor_x,
        &session,
        &host_secret,
        &base,
        &presig,
    )
    .expect("addition-bound host nonce relation");
}
