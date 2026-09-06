use crate::protocol::qr::{decode_frame, reset_decoder};

fn frame_hex(payload: &[u8], index: u8, total: u8, fragment: &[u8]) -> String {
    let identifier = shared_signer::qr_frame::session_id(payload);
    let mut encoded = [0u8; 64];
    let length =
        shared_signer::qr_frame::encode_frame(&identifier, index, total, fragment, &mut encoded)
            .expect("frame encoding");
    hex::encode(&encoded[..length])
}

#[test]
fn mixed_sessions_are_rejected_until_explicit_reset() {
    reset_decoder();
    let stale = b"stale-payload";
    let current = b"current-payload";

    assert_eq!(
        decode_frame(&frame_hex(stale, 1, 2, &stale[6..])).expect("first out-of-order stale frame"),
        None,
    );
    let error = decode_frame(&frame_hex(current, 0, 2, &current[..7]))
        .expect_err("foreign frame zero must not replace the active session");
    assert!(error.contains("Mixed multi-frame QR session"));

    reset_decoder();
    assert_eq!(
        decode_frame(&frame_hex(current, 0, 2, &current[..7]))
            .expect("explicit reset accepts the new session"),
        None,
    );
    let completed = decode_frame(&frame_hex(current, 1, 2, &current[7..]))
        .expect("current session completion")
        .expect("complete payload");
    assert_eq!(completed, hex::encode(current));
}

#[test]
fn conflicting_duplicate_frame_is_rejected() {
    reset_decoder();
    let payload = b"duplicate-frame-test";
    let first = frame_hex(payload, 0, 2, &payload[..9]);
    assert_eq!(decode_frame(&first).expect("first frame"), None);

    let identifier = shared_signer::qr_frame::session_id(payload);
    let mut conflicting = [0u8; 64];
    let length =
        shared_signer::qr_frame::encode_frame(&identifier, 0, 2, b"different", &mut conflicting)
            .expect("conflicting frame encoding");
    let error = decode_frame(&hex::encode(&conflicting[..length]))
        .expect_err("conflicting duplicate must fail");
    assert!(error.contains("Conflicting duplicate"));
}

#[test]
fn qr_generation_covers_invalid_empty_single_multi_and_oversized_payloads() {
    use crate::protocol::qr::generate_frames;

    assert!(generate_frames("zz").unwrap_err().contains("Invalid hex"));
    assert!(generate_frames("").unwrap_err().contains("Empty data"));

    let single = generate_frames(&hex::encode([0x11; 134])).expect("single frame");
    assert_eq!(single.len(), 1);
    assert_eq!(single[0].frame_num, 0);
    assert_eq!(single[0].total_frames, 1);
    assert!(single[0].svg.starts_with("<svg"));

    let payload = vec![0x22; 200];
    let multi = generate_frames(&hex::encode(&payload)).expect("multi frame");
    assert_eq!(multi.len(), 3);
    assert!(multi
        .iter()
        .enumerate()
        .all(|(index, frame)| frame.frame_num == index as u8 && frame.total_frames == 3));

    let oversized = vec![
        0x33;
        shared_signer::qr_frame::MAX_FRAMES
            .saturating_mul(91)
            .saturating_add(1)
    ];
    assert!(generate_frames(&hex::encode(oversized))
        .unwrap_err()
        .contains("Too large"));
}

#[test]
fn qr_progress_and_plain_text_svg_boundaries_are_covered() {
    use crate::protocol::qr::{decoder_progress, generate_svg_from_text};

    reset_decoder();
    assert_eq!(decoder_progress(), "0/0");
    let svg = generate_svg_from_text("KasSigner recovery").expect("plain text QR");
    assert!(svg.starts_with("<svg"));
    assert!(svg.contains("fill=\"black\""));
}

#[test]
fn plain_text_svg_matches_qr_module_geometry_exactly() {
    use crate::protocol::qr::generate_svg_from_text;
    use qrcode::{types::Color, QrCode};

    let text = "KasSigner mutation geometry";
    let svg = generate_svg_from_text(text).expect("plain text SVG");
    let code = QrCode::new(text.as_bytes()).expect("reference QR");
    let modules = code.to_colors();
    let size = code.width();
    let total = size + 4;
    assert!(svg.contains(&format!("viewBox=\"0 0 {total} {total}\"")));

    let mut dark_count = 0usize;
    for (index, color) in modules.iter().enumerate() {
        if *color != Color::Dark {
            continue;
        }
        dark_count += 1;
        let x = (index % size) + 2;
        let y = (index / size) + 2;
        let rect = format!("<rect x=\"{x}\" y=\"{y}\" width=\"1\" height=\"1\" fill=\"black\"/>");
        assert!(svg.contains(&rect), "missing dark module at ({x}, {y})");
    }
    assert_eq!(svg.matches("<rect x=").count(), dark_count);
}
