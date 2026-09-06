use std::fmt::Write;

use qrcode::{types::Color, QrCode};

use crate::protocol::qr::generate_frames;

fn reference_svg(data: &[u8]) -> String {
    let code = QrCode::new(data).expect("reference QR");
    let modules = code.to_colors();
    let size = code.width();
    let total = size + 4;
    let mut svg = String::with_capacity(total * total * 60);
    let _ = write!(
        svg,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\"><rect width=\"{total}\" height=\"{total}\" fill=\"white\"/>"
    );
    for (index, color) in modules.iter().enumerate() {
        if *color == Color::Dark {
            let x = (index % size) + 2;
            let y = (index / size) + 2;
            let _ = write!(
                svg,
                "<rect x=\"{x}\" y=\"{y}\" width=\"1\" height=\"1\" fill=\"black\"/>"
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

#[test]
fn qr_generation_accepts_exact_maximum_frame_count() {
    const MAX_FRAME_DATA: usize = 91;
    let payload = vec![0x5au8; shared_signer::qr_frame::MAX_FRAMES * MAX_FRAME_DATA];
    let frames = generate_frames(&hex::encode(payload)).expect("exact maximum frame count");
    assert_eq!(frames.len(), shared_signer::qr_frame::MAX_FRAMES);
    assert_eq!(frames.first().unwrap().frame_num, 0);
    assert_eq!(
        frames.last().unwrap().frame_num,
        (shared_signer::qr_frame::MAX_FRAMES - 1) as u8,
    );
    assert!(frames
        .iter()
        .all(|frame| usize::from(frame.total_frames) == shared_signer::qr_frame::MAX_FRAMES));
}

#[test]
fn qr_generation_slices_balanced_fragments_at_exact_offsets() {
    let payload: Vec<u8> = (0..200u16).map(|value| value as u8).collect();
    let frames = generate_frames(&hex::encode(&payload)).expect("balanced frames");
    assert_eq!(frames.len(), 3);

    let balanced_size = payload.len().div_ceil(frames.len());
    assert_eq!(balanced_size, 67);
    let frame_index = 1usize;
    let start = frame_index * balanced_size;
    let end = (start + balanced_size).min(payload.len());
    let identifier = shared_signer::qr_frame::session_id(&payload);
    let mut encoded = [0u8; 134];
    let written = shared_signer::qr_frame::encode_frame(
        &identifier,
        frame_index as u8,
        frames.len() as u8,
        &payload[start..end],
        &mut encoded,
    )
    .expect("reference frame");

    assert_eq!(frames[frame_index].svg, reference_svg(&encoded[..written]));
}
