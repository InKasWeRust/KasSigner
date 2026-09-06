use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};

use super::*;
use crate::protocol::pskt::PsktFormat;

fn h(byte: u8, len: usize) -> String {
    format!("{byte:02x}").repeat(len)
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("future unexpectedly pending"),
    }
}

struct AdaptorFixture {
    public_x: [u8; 32],
    message: [u8; 32],
    adaptor_point_x: [u8; 32],
    adaptor_secret: [u8; 32],
    session_id: [u8; 16],
    host_secret: [u8; 32],
    base_nonce_point: [u8; 33],
    presig: crate::protocol::private_swap::adaptor::AdaptorPreSignature,
}

fn adaptor_fixture() -> AdaptorFixture {
    let private_key = [3u8; 32];
    let message = [9u8; 32];
    let session_id = [4u8; 16];
    let aux = [5u8; 32];
    let host_secret = [6u8; 32];
    let (adaptor_secret, adaptor_point_x) =
        offline_signer::crypto::adaptor::adaptor_point_from_secret(&[7u8; 32])
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
        .expect("private key")
        .public_key();
    let encoded = public.to_encoded_point(true);
    let mut public_x = [0u8; 32];
    public_x.copy_from_slice(&encoded.as_bytes()[1..]);
    AdaptorFixture {
        public_x,
        message,
        adaptor_point_x,
        adaptor_secret,
        session_id,
        host_secret,
        base_nonce_point,
        presig: crate::protocol::private_swap::adaptor::AdaptorPreSignature {
            bytes: generated.bytes,
            negated: generated.negated,
        },
    }
}

#[test]
fn device_request_helpers_cover_every_private_swap_transport_kind() {
    let key = h(0x11, 32);
    let token = h(0x22, 32);
    let point = h(0x33, 32);
    let secret = h(0x44, 32);

    let key_request = private_swap_key_request_string().expect("key request");
    let key_bytes = hex::decode(key_request).expect("key request hex");
    assert_eq!(
        shared_signer::covenant_sign::private_swap::parse_request(&key_bytes)
            .unwrap()
            .kind,
        shared_signer::covenant_sign::private_swap::RequestKind::KeyInfo
    );

    let bind = private_swap_bind_request(&key, &point, "51").expect("bind wrapper");
    let bind_bytes = hex::decode(bind).unwrap();
    assert_eq!(
        shared_signer::covenant_sign::private_swap::parse_request(&bind_bytes)
            .unwrap()
            .kind,
        shared_signer::covenant_sign::private_swap::RequestKind::Bind
    );

    let presign_json =
        private_swap_presign_request(&key, &token, &point, "aa", &secret).expect("presign wrapper");
    let presign: Value = serde_json::from_str(&presign_json).unwrap();
    let presign_bytes = hex::decode(presign["request_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        shared_signer::covenant_sign::private_swap::parse_request(&presign_bytes)
            .unwrap()
            .kind,
        shared_signer::covenant_sign::private_swap::RequestKind::PreSign
    );

    let reveal = private_swap_reveal_request(&h(0x55, 16), &key, &h(0x66, 32), &secret)
        .expect("reveal wrapper");
    let reveal_bytes = hex::decode(reveal).unwrap();
    assert_eq!(
        shared_signer::covenant_sign::private_swap::parse_reveal(&reveal_bytes)
            .unwrap()
            .key_id,
        [0x11; 32]
    );

    let complete = private_swap_complete_request(&key, &token, &point, "aa", &h(0x77, 64), true)
        .expect("complete wrapper");
    let complete_bytes = hex::decode(complete).unwrap();
    let parsed =
        shared_signer::covenant_sign::private_swap::parse_request(&complete_bytes).unwrap();
    assert_eq!(
        parsed.kind,
        shared_signer::covenant_sign::private_swap::RequestKind::Complete
    );
    assert!(parsed.presignature_negated);

    assert!(private_swap_bind_request_string("00", &point, "51").is_err());
    assert!(private_swap_presign_request_string(&key, &token, &point, "zz", &secret).is_err());
    assert!(private_swap_reveal_request_string("00", &key, &h(0x66, 32), &secret).is_err());
    assert!(private_swap_complete_request_string(&key, &token, &point, "aa", "00", false).is_err());
}

#[test]
fn response_json_and_fixed_decoders_cover_success_and_fail_closed_shapes() {
    let response = shared_signer::covenant_sign::private_swap::PrivateSwapResponse {
        kind: shared_signer::covenant_sign::private_swap::ResponseKind::Binding,
        session_id: [0; 16],
        key_id: [1; 32],
        claim_pubkey: [2; 32],
        binding_token: [3; 32],
        adaptor_point: [4; 32],
        commitment: [5; 32],
        nonce_point: [0; 33],
        signature: [0; 64],
        negated: false,
    };
    let mut wire = [0u8; shared_signer::covenant_sign::private_swap::RESPONSE_LEN];
    shared_signer::covenant_sign::private_swap::encode_response(&response, &mut wire).unwrap();
    let document = private_swap_parse_response(&hex::encode(wire)).expect("response wrapper");
    let parsed: Value = serde_json::from_str(&document).unwrap();
    assert_eq!(parsed["kind"], 1);
    assert_eq!(parsed["binding_token"], hex::encode([3; 32]));

    assert!(private_swap_parse_response_string("zz").is_err());
    assert!(decode32("00", "short").is_err());
    assert!(decode32("zz", "bad").is_err());
    assert_eq!(decode16(&h(0x11, 16), "session").unwrap(), [0x11; 16]);
    assert_eq!(decode33(&h(0x12, 33), "nonce").unwrap(), [0x12; 33]);
    assert_eq!(decode64(&h(0x13, 64), "signature").unwrap(), [0x13; 64]);
    assert!(parse_presig("00", false).is_err());
}

#[test]
fn public_adaptor_wasm_helpers_cover_verify_complete_and_extract_paths() {
    let f = adaptor_fixture();
    let public = hex::encode(f.public_x);
    let message = hex::encode(f.message);
    let point = hex::encode(f.adaptor_point_x);
    let presig = hex::encode(f.presig.bytes);
    let session = hex::encode(f.session_id);
    let host = hex::encode(f.host_secret);
    let nonce = hex::encode(f.base_nonce_point);
    let secret = hex::encode(f.adaptor_secret);

    assert!(private_swap_verify_presignature(
        &public,
        &message,
        &presig,
        f.presig.negated,
        &point
    ));
    assert!(private_swap_verify_host_relation(
        &public,
        &message,
        &point,
        &session,
        &host,
        &nonce,
        &presig,
        f.presig.negated,
    ));
    let completed =
        private_swap_complete_public(&presig, f.presig.negated, &secret).expect("complete wrapper");
    assert!(private_swap_verify_completed(&public, &message, &completed));
    assert_eq!(
        private_swap_extract_secret(&presig, f.presig.negated, &completed)
            .expect("extract wrapper"),
        secret
    );

    assert!(!private_swap_verify_presignature(
        "00", &message, &presig, false, &point
    ));
    assert!(!private_swap_verify_host_relation(
        &public, &message, &point, "00", &host, &nonce, &presig, false
    ));
    assert!(!private_swap_verify_completed(&public, &message, "00"));
    assert!(private_swap_complete_public_string("00", false, &secret).is_err());
    assert!(private_swap_extract_secret_string(&presig, f.presig.negated, "00").is_err());
}

fn unsigned_pskt(input_count: usize, partial_sigs: Value) -> String {
    let inputs = (0..input_count)
        .map(|_| json!({"partialSigs": partial_sigs.clone()}))
        .collect::<Vec<_>>();
    crate::protocol::pskt::wire::encode_root(PsktFormat::PsktSingle, &json!({"inputs": inputs}))
        .unwrap()
}

#[test]
fn completed_signature_insertion_requires_one_unsigned_input_and_preserves_sighash_all() {
    let wire = unsigned_pskt(1, json!({}));
    let signed = private_swap_insert_completed_signature(&wire, &h(0x22, 32), &h(0x33, 64))
        .expect("insert wrapper");
    let (_, root) = crate::protocol::pskt::wire::decode_root(&signed).unwrap();
    let partial = root["inputs"][0]["partialSigs"].as_object().unwrap();
    let entry = partial.get(&format!("02{}", h(0x22, 32))).unwrap();
    assert_eq!(entry["sighashType"], 1);
    assert_eq!(entry["schnorr"], h(0x33, 64));

    assert!(private_swap_insert_completed_signature_string(&wire, "00", &h(0x33, 64)).is_err());
    assert!(private_swap_insert_completed_signature_string(&wire, &h(0x22, 32), "00").is_err());
    assert!(insert_completed_signature(&unsigned_pskt(0, json!({})), &[1; 32], &[2; 64]).is_err());
    assert!(insert_completed_signature(&unsigned_pskt(2, json!({})), &[1; 32], &[2; 64]).is_err());
    assert!(insert_completed_signature(
        &unsigned_pskt(1, json!({"02aa": {"schnorr": "00"}})),
        &[1; 32],
        &[2; 64]
    )
    .is_err());
    let missing =
        crate::protocol::pskt::wire::encode_root(PsktFormat::PsktSingle, &json!({"inputs": [{}]}))
            .unwrap();
    assert!(insert_completed_signature(&missing, &[1; 32], &[2; 64]).is_err());
}

#[test]
fn private_swap_claim_preparation_is_host_testable_without_network_or_wasm_values() {
    let source = crate::account::address::encode_p2pk_address(&[0x11; 32], "kaspa");
    let destination = crate::account::address::encode_p2pk_address(&[0x22; 32], "kaspa");
    let one = serde_json::json!([{
        "tx_id": "33".repeat(32), "index": 0, "amount": "1000000"
    }])
    .to_string();
    let (prepared, redeem) = prepare_private_swap_claim(&source, &destination, "51", &one, 1000)
        .expect("single selected UTXO");
    let pskb = ready(create_private_swap_claim(
        &source,
        &destination,
        "51",
        &one,
        1000,
    ))
    .expect("claim PSKB wrapper");
    assert!(!pskb.is_empty());
    assert_eq!(prepared.utxos.len(), 1);
    assert_eq!(redeem, vec![0x51]);

    let two = serde_json::json!([
        {"tx_id": "33".repeat(32), "index": 0, "amount": "1000000"},
        {"tx_id": "44".repeat(32), "index": 1, "amount": "1000000"}
    ])
    .to_string();
    assert!(prepare_private_swap_claim(&source, &destination, "51", &two, 1000).is_err());
    assert!(prepare_private_swap_claim(&source, &destination, "zz", &one, 1000).is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn private_swap_claim_sighash_wasm_boundary_rejects_malformed_wire() {
    assert!(private_swap_claim_sighash("zz").is_err());
    assert!(private_swap_claim_sighash("00").is_err());
}
