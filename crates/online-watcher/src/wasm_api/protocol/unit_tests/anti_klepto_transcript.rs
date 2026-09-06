mod commitment_cases;
mod fixture;
mod transcript_cases;

use fixture::TranscriptFixture;

#[test]
fn anti_klepto_native_boundary_accepts_complete_p2pk_and_p2sh_transcripts() {
    for fixture in [
        TranscriptFixture::p2pk_two_inputs(),
        TranscriptFixture::p2sh_multisig(),
    ] {
        assert_eq!(
            fixture
                .verify_public()
                .expect("valid anti-klepto transcript"),
            hex::encode(&fixture.signed_tx_wire)
        );
    }
}

#[test]
fn anti_klepto_begin_rejects_structurally_unsafe_compact_transactions() {
    let host_secret = [0x42u8; 32];
    for (label, wire, expected) in [
        (
            "no inputs",
            fixture::minimal_compact_transaction(0, 1, 0),
            "compact KSPT has no inputs",
        ),
        (
            "no outputs",
            fixture::minimal_compact_transaction(1, 0, 0),
            "compact KSPT has no outputs",
        ),
        (
            "unsupported flags",
            fixture::minimal_compact_transaction(1, 1, 0x02),
            "invalid KSPT flags",
        ),
    ] {
        let error = crate::wasm_api::protocol::anti_klepto::anti_klepto_begin_with_secret_string(
            &hex::encode(wire),
            &host_secret,
        )
        .expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
    }
}

#[test]
fn anti_klepto_public_boundary_rejects_malformed_hex_and_secret_width() {
    let fixture = TranscriptFixture::p2pk_two_inputs();
    assert!(
        crate::wasm_api::protocol::anti_klepto::anti_klepto_accept_commitment_string(
            &fixture.request_hex(),
            &fixture.commitment_hex(&fixture.commitment_records),
            "00",
        )
        .is_err()
    );
    assert!(
        crate::wasm_api::protocol::anti_klepto::anti_klepto_verify_signed_string(
            "zz",
            &fixture.commitment_hex(&fixture.commitment_records),
            &fixture.signed_message_hex(&fixture.proofs, &fixture.signed_tx_wire),
            &fixture.host_secret_hex(),
        )
        .is_err()
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn anti_klepto_wasm_facade_functions_are_exercised_on_native_error_paths() {
    use crate::wasm_api::protocol::anti_klepto::{
        anti_klepto_accept_commitment, anti_klepto_begin, anti_klepto_verify_signed,
    };

    assert!(anti_klepto_begin("00").is_err());
    assert!(anti_klepto_accept_commitment("zz", "00", &"11".repeat(32)).is_err());
    assert!(anti_klepto_verify_signed("zz", "00", "00", &"11".repeat(32)).is_err());
}
