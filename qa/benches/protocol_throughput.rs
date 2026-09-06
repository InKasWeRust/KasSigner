use kassigner_protocol::wire::qr_payload::{unwrap_v1_raw, wrap_v1_raw};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let payload = [0x5au8; 512];
    let mut framed = [0u8; 513];
    let written = wrap_v1_raw(&payload, &mut framed).expect("fixed buffer fits");
    let iterations = 100_000u32;
    let started = Instant::now();

    for _ in 0..iterations {
        let body = unwrap_v1_raw(black_box(&framed[..written]));
        assert_eq!(body.map(<[u8]>::len), Some(payload.len()));
    }

    println!("unwrapped {iterations} payloads in {:?}", started.elapsed());
}
