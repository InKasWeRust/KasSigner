use super::{message_digest, sign_message_with_entropy};

#[test]
fn message_digest_is_domain_length_and_content_bound() {
    let base = message_digest(b"hello");
    let mut encoded = [0u8; 64];
    assert_eq!(
        shared_signer::bytes::encode_lower_hex(&base, &mut encoded),
        Some(64)
    );
    assert_eq!(
        &encoded,
        b"8801296b169c712eab1cfeb5f0710e361c130de7195adc1a1f7ce7d380cd0ebd"
    );
    assert_ne!(base, message_digest(b"hello!"));
    assert_ne!(base, message_digest(b"\0hello"));
    assert_ne!(base, crate::derivation::hmac::sha256(b"hello"));
}

#[test]
fn message_signature_verifies_only_against_domain_digest() {
    let private_key = [0x11u8; 32];
    let entropy = [0x22u8; 32];
    let signature = sign_message_with_entropy(&private_key, b"reviewed text", &entropy)
        .expect("domain-separated message signs");
    let public = k256::schnorr::SigningKey::from_bytes(&private_key)
        .expect("test key")
        .verifying_key()
        .to_bytes();
    let public: [u8; 32] = public.into();
    let digest = message_digest(b"reviewed text");
    assert!(crate::crypto::schnorr::schnorr_verify(&public, &digest, &signature).is_ok());
    let raw = crate::derivation::hmac::sha256(b"reviewed text");
    assert!(crate::crypto::schnorr::schnorr_verify(&public, &raw, &signature).is_err());
}
