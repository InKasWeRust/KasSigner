use alloc::vec;
use signer_firmware_core::qr::classification::{classify_qr_payload, QrPayloadKind};
use super::QrContext;

pub(super) fn exercise(ctx: &mut QrContext<'_, '_, '_>) -> bool {
    let Some(anti) = anti_request(ctx) else { return false; };
    let Some(pairing) = pairing_request() else { return false; };
    let mut firmware = vec![0u8; signer_firmware_core::update::manifest::MANIFEST_LEN];
    firmware[..4].copy_from_slice(b"KSFU");
    let cov_sign_raw = [b'C', b'V', b'R', b'V', shared_signer::covenant_sign::VERSION];
    let swap_raw = [b'P', b'S', b'W', b'R', shared_signer::covenant_sign::private_swap::VERSION];
    let cov_sign_hex = hex_envelope(b"43565256", shared_signer::covenant_sign::REVEAL_LEN * 2);
    let swap_hex = hex_envelope(b"50535752", shared_signer::covenant_sign::private_swap::REVEAL_LEN * 2);
    let cases: [(&[u8], QrPayloadKind); 16] = [
        (b"kaspa:test", QrPayloadKind::KaspaAddress),
        (b"KSPT\x04", QrPayloadKind::CompactKspt),
        (b"PSKT", QrPayloadKind::StandardPskt),
        (b"000000000000000000000000000000000000000000000000", QrPayloadKind::SeedQr),
        (&[0u8; 16], QrPayloadKind::RawSeedEntropy),
        (&[b'S', b'T', b'L', b'H', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], QrPayloadKind::StealthRequest),
        (&firmware, QrPayloadKind::FirmwareUpdate),
        (b"COVB\x01", QrPayloadKind::CovenantRaw),
        (b"434f564200", QrPayloadKind::CovenantHex),
        (&cov_sign_raw, QrPayloadKind::CovenantSignRaw),
        (&cov_sign_hex, QrPayloadKind::CovenantSignHex),
        (&swap_raw, QrPayloadKind::PrivateSwapRaw),
        (&swap_hex, QrPayloadKind::PrivateSwapHex),
        (&anti, QrPayloadKind::AntiKlepto),
        (&pairing, QrPayloadKind::PairingRequest),
        (b"not-a-kassigner-payload", QrPayloadKind::Unknown),
    ];
    if cases.iter().any(|(wire, expected)| classify_qr_payload(wire, wire.len()) != *expected) {
        return false;
    }
    let oversized = vec![b'X'; 20_000];
    let malformed = [b"KSPT\x03".as_slice(), b"KAKP\xff".as_slice(), b"KSFU".as_slice()];
    if classify_qr_payload(&oversized, usize::MAX) != QrPayloadKind::Unknown
        || malformed.iter().any(|wire| classify_qr_payload(wire, usize::MAX) != QrPayloadKind::Unknown)
    { return false; }
    if !stealth_request_boundaries() { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: QR CLASSIFIER 16/16 + MALFORMED/OVERSIZED PASS");
    true
}

fn pairing_request() -> Option<[u8; shared_signer::pairing::REQUEST_LEN]> {
    let request = shared_signer::pairing::AddressBatchRequest::new(
        [0xA5; shared_signer::pairing::NONCE_LEN],
        0,
        20,
        0,
        20,
    );
    let mut wire = [0u8; shared_signer::pairing::REQUEST_LEN];
    (shared_signer::pairing::encode_request(request, &mut wire)
        == Ok(shared_signer::pairing::REQUEST_LEN))
        .then_some(wire)
}

fn stealth_request_boundaries() -> bool {
    fn request(count: u8) -> alloc::vec::Vec<u8> {
        let mut wire = vec![0u8; 5usize.saturating_add(usize::from(count).saturating_mul(32))];
        wire[..4].copy_from_slice(b"STLH");
        wire[4] = count;
        wire
    }

    let minimum = request(1);
    let maximum = request(64);
    let zero = request(0);
    let above_maximum = request(65);
    let truncated = request(2);
    let too_short = [b'S', b'T', b'L', b'H'];

    let valid = crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
        &minimum, minimum.len(),
    ) == Ok(1)
        && crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
            &maximum, maximum.len(),
        ) == Ok(64);
    let invalid = crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
        &zero, zero.len(),
    ).is_err()
        && crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
            &above_maximum, above_maximum.len(),
        ).is_err()
        && crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
            &truncated, truncated.len().saturating_sub(1),
        ).is_err()
        && crate::runtime::interactions::camera_loop::workflow_validate_stealth_request(
            &too_short, too_short.len(),
        ).is_err();
    if valid && invalid {
        log!("KASSIGNER_WORKFLOW_TESTS: STEALTH REQUEST MIN/MAX/INVALID-COUNT/LENGTH PASS");
        true
    } else {
        false
    }
}

fn anti_request(ctx: &QrContext<'_, '_, '_>) -> Option<alloc::vec::Vec<u8>> {
    let tx = super::super::signing::fixture::wire(
        ctx.ad,
        super::super::signing::fixture::WireFormat::CompactKspt,
    )?;
    let mut output = vec![0u8; tx.len().saturating_add(192)];
    let len = shared_signer::anti_klepto::encode_request(&[0x33; 32], &tx, &mut output).ok()?;
    output.truncate(len);
    Some(output)
}

fn hex_envelope(prefix: &[u8; 8], len: usize) -> alloc::vec::Vec<u8> {
    let mut output = vec![b'0'; len];
    output[..8].copy_from_slice(prefix);
    output
}
