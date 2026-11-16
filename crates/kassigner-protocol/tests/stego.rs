// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The steganography carriers over `kassigner-jpeg`'s fixtures: payload
//! shapes, the walk, the Picture carrier, the EXIF builders, and exports read
//! back. The payloads are only shaped like sealed containers; opening is
//! `kassigner-crypto`'s.

use kassigner_jpeg::exif::{tag, Tiff};
use kassigner_jpeg::segment;
use kassigner_protocol::container::{self, Kdf, Layout, Purpose, MAGIC_V1, SALT_SIZE};
use kassigner_protocol::stego::blob::{self, BlobError, Shape};
use kassigner_protocol::stego::exif::{self, RANDOM};
use kassigner_protocol::stego::picture::{
    self, bitmap_len, PictureError, Tables, Window, RANK_WINDOW,
};
use kassigner_protocol::stego::walk::{Walk, KEY_SIZE};
use kassigner_protocol::stego::{
    self, descriptor_ok, export, extract, Carrier, Export, StegoError, PAYLOAD_MAX,
};

const GRAY: &[u8] = include_bytes!("../../kassigner-jpeg/tests/fixtures/gray.jpg");
const COLOR_RST: &[u8] = include_bytes!("../../kassigner-jpeg/tests/fixtures/color_rst.jpg");
const PROGRESSIVE: &[u8] = include_bytes!("../../kassigner-jpeg/tests/fixtures/progressive.jpg");
const EXIF_BE: &[u8] = include_bytes!("../../kassigner-jpeg/tests/fixtures/exif_pil.jpg");
const EXIF_LE: &[u8] = include_bytes!("../../kassigner-jpeg/tests/fixtures/exif_le.jpg");

const KEY: [u8; KEY_SIZE] = [7u8; KEY_SIZE];
const WRONG: [u8; KEY_SIZE] = [8u8; KEY_SIZE];
const RND: [u8; RANDOM] = [3, 5, 9, 11, 13, 17, 2, 0];
const DESC: &[u8] = b"Rocky at the beach, summer 2024";

/// A window of the device's size.
struct Buffers {
    coefficients: Vec<i16>,
    filled: Vec<u8>,
    changed: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Buffers {
            coefficients: vec![0; RANK_WINDOW],
            filled: vec![0; bitmap_len(RANK_WINDOW)],
            changed: vec![0; bitmap_len(RANK_WINDOW)],
        }
    }
    fn window(&mut self) -> Window<'_> {
        Window {
            coefficients: &mut self.coefficients,
            filled: &mut self.filled,
            changed: &mut self.changed,
        }
    }
}

/// A fresh set of the photo's Huffman tables, as a device keeps one.
fn tables() -> Tables {
    Tables::EMPTY
}

/// A `KAS\x06` stego container: a header, `n` bytes of unencrypted
/// "ciphertext", a tag.
fn v3_container(n: usize) -> Vec<u8> {
    let salt = [0xA5u8; SALT_SIZE];
    let mut head = [0u8; 32];
    let h = container::write_header(Purpose::Stego, Kdf::Pbkdf2Sha256, n, &salt, &mut head)
        .unwrap()
        .to_vec();
    let mut f = h;
    f.extend((0..12).map(|i| 0x30 + i as u8)); // nonce
    f.extend((0..n).map(|i| (i * 7 + 1) as u8)); // ciphertext
    f.extend([0xEEu8; 16]); // tag
    assert_eq!(f.len(), container::file_size(n));
    f
}

/// Its v3 payload.
fn v3_payload(n: usize) -> Vec<u8> {
    let c = v3_container(n);
    let mut out = vec![0u8; 256];
    let k = blob::strip(&c, &mut out).unwrap();
    out.truncate(k);
    out
}

/// A `KAS\x04` container as v1.0.7 sealed one, `n` bytes of plaintext.
fn legacy_container(purpose: Purpose, n: u8) -> Vec<u8> {
    let mut f = vec![b'K', b'A', b'S', 0x04, 3, purpose as u8, 1, n];
    f.extend([0x5Au8; SALT_SIZE]);
    f.extend([0x77u8; 12]);
    f.extend((0..n).map(|i| i.wrapping_mul(3)));
    f.extend([0xCCu8; 16]);
    f
}

fn base64(bytes: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for c in bytes.chunks(3) {
        let mut v = 0u32;
        for i in 0..3 {
            v = (v << 8) | u32::from(*c.get(i).unwrap_or(&0));
        }
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((v >> (18 - 6 * i)) & 63) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

// ── blob ────────────────────────────────────────────────────────────────────

#[test]
fn a_v3_payload_starts_at_the_kdf_byte_and_rebuilds_its_container() {
    let c = v3_container(113);
    let p = v3_payload(113);
    assert_eq!(p.len(), c.len() - blob::V3_HEAD);
    assert_eq!(p[0], Kdf::Pbkdf2Sha256 as u8);
    assert_eq!(&p[1..3], &113u16.to_le_bytes());
    assert_eq!(blob::shape(&p), Ok(Shape::V3));
    let mut out = vec![0u8; 256];
    let u = blob::unpack(&p, &mut out).unwrap();
    assert_eq!(u.shape, Shape::V3);
    assert_eq!(u.hint, None);
    assert_eq!(&out[u.seed.clone()], &c[..]);
    let parsed = container::parse(&out[u.seed]).unwrap();
    assert_eq!(parsed.purpose, Purpose::Stego);
    assert_eq!(parsed.layout, Layout::V1);
    assert_eq!(parsed.len, 113);
}

#[test]
fn strip_takes_only_a_current_container() {
    let mut out = [0u8; 256];
    assert_eq!(
        blob::strip(&legacy_container(Purpose::Seed, 24), &mut out),
        Err(BlobError::Unknown)
    );
    let mut c = v3_container(24);
    c[4] = 2;
    assert_eq!(blob::strip(&c, &mut out), Err(BlobError::Unknown));
    assert_eq!(
        blob::strip(&v3_container(24), &mut [0u8; 10]),
        Err(BlobError::BufferTooSmall)
    );
    assert_eq!(&c[..4], &MAGIC_V1);
}

#[test]
fn a_v107_raw_payload_rebuilds_seed_and_hint_containers() {
    let seed = legacy_container(Purpose::Seed, 48);
    let hint = legacy_container(Purpose::Raw, 26);
    let mut p = seed[blob::V2_HEAD..].to_vec();
    p.extend_from_slice(&hint[blob::V2_HEAD..]);
    assert_eq!(p[0], 48);
    assert_eq!(blob::shape(&p), Ok(Shape::V2));
    let mut out = vec![0u8; 512];
    let u = blob::unpack(&p, &mut out).unwrap();
    assert_eq!(u.shape, Shape::V2);
    assert_eq!(&out[u.seed.clone()], &seed[..]);
    assert_eq!(&out[u.hint.clone().unwrap()], &hint[..]);
    assert_eq!(
        container::parse(&out[u.seed]).unwrap().purpose,
        Purpose::Seed
    );
    assert_eq!(
        container::parse(&out[u.hint.unwrap()]).unwrap().purpose,
        Purpose::Raw
    );

    // Seed alone, 12 words.
    let seed = legacy_container(Purpose::Seed, 24);
    let u = blob::unpack(&seed[blob::V2_HEAD..], &mut out).unwrap();
    assert_eq!(u.hint, None);
    assert_eq!(&out[u.seed], &seed[..]);

    // Cut short.
    assert_eq!(blob::unpack(&p[..40], &mut out), Err(BlobError::Short));
}

#[test]
fn a_v105_base64_payload_rebuilds_too() {
    let seed = legacy_container(Purpose::Seed, 24);
    let hint = legacy_container(Purpose::Raw, 20);
    let mut p = base64(&seed);
    assert!(p.starts_with(b"S0FT"));
    p.push(b'|');
    p.extend(base64(&hint));
    assert_eq!(blob::shape(&p), Ok(Shape::V1));
    let mut out = vec![0u8; 512];
    let u = blob::unpack(&p, &mut out).unwrap();
    assert_eq!(u.shape, Shape::V1);
    assert_eq!(&out[u.seed.clone()], &seed[..]);
    assert_eq!(&out[u.hint.unwrap()], &hint[..]);
    let u = blob::unpack(&base64(&seed), &mut out).unwrap();
    assert_eq!(u.hint, None);
    assert_eq!(&out[u.seed], &seed[..]);
    assert_eq!(blob::unpack(b"S0FT!!", &mut out), Err(BlobError::Encoding));
}

#[test]
fn anything_else_is_no_payload() {
    for p in [&b""[..], b"hello", &[0u8, 1, 2], &[200u8; 40], b"S0F"] {
        assert_eq!(blob::shape(p), Err(BlobError::Unknown));
    }
}

// ── walk ────────────────────────────────────────────────────────────────────

#[test]
fn the_walk_is_a_bijection_that_scatters() {
    for n in [2u32, 63, 1_000, 45_359, 453_600] {
        let w = Walk::new(n, &KEY).unwrap();
        let mut seen = vec![false; n as usize];
        for p in 0..n {
            let r = w.rank(p);
            assert!(r < n);
            assert!(!seen[r as usize], "n {n}: rank {r} twice");
            seen[r as usize] = true;
        }
    }
    // The first ranks land across the whole file, not at its head.
    let n = 453_600u32;
    let w = Walk::new(n, &KEY).unwrap();
    let mut first_decile = 0;
    let mut low = 0;
    for p in 0..n {
        if w.rank(p) < 2_000 {
            low += 1;
            if p < n / 10 {
                first_decile += 1;
            }
        }
    }
    assert_eq!(low, 2_000);
    assert!(
        (150..=250).contains(&first_decile),
        "{first_decile} of 2000 in the first tenth"
    );
    // Another key is another walk.
    let w2 = Walk::new(n, &WRONG).unwrap();
    assert_ne!(
        (0..100).map(|p| w.rank(p)).collect::<Vec<_>>(),
        (0..100).map(|p| w2.rank(p)).collect::<Vec<_>>()
    );
    assert!(Walk::new(1, &KEY).is_none());
}

// ── picture ─────────────────────────────────────────────────────────────────

#[test]
fn the_picture_carrier_round_trips_and_a_wrong_key_reads_nothing() {
    let payload = v3_payload(113);
    let mut b = Buffers::new();
    let cap = picture::capacity(COLOR_RST, &KEY, &mut b.window(), &mut tables()).unwrap();
    assert!(cap > (payload.len() + 2) * 8, "capacity {cap} bits");
    let mut out = vec![0u8; COLOR_RST.len() + 4096];
    let n = picture::embed(
        COLOR_RST,
        &payload,
        &KEY,
        &mut b.window(),
        &mut tables(),
        &mut out,
    )
    .unwrap();
    assert!((n as i64 - COLOR_RST.len() as i64).abs() < 400);
    assert_eq!(
        &out[..segment::scan_start(COLOR_RST).unwrap()],
        &COLOR_RST[..segment::scan_start(COLOR_RST).unwrap()],
        "the head is untouched"
    );
    let mut back = [0u8; PAYLOAD_MAX];
    let m = picture::extract(&out[..n], &KEY, &mut b.window(), &mut tables(), &mut back).unwrap();
    assert_eq!(&back[..m], &payload[..]);
    match picture::extract(&out[..n], &WRONG, &mut b.window(), &mut tables(), &mut back) {
        Err(PictureError::NoPayload) => {}
        Ok(m) => assert_ne!(&back[..m], &payload[..]),
        Err(e) => panic!("{e:?}"),
    }
    // A re-run with another payload replaces the first.
    let other = v3_payload(60);
    let mut out2 = vec![0u8; n + 4096];
    let n2 = picture::embed(
        &out[..n],
        &other,
        &KEY,
        &mut b.window(),
        &mut tables(),
        &mut out2,
    )
    .unwrap();
    let m = picture::extract(&out2[..n2], &KEY, &mut b.window(), &mut tables(), &mut back).unwrap();
    assert_eq!(&back[..m], &other[..]);
}

#[test]
fn a_picture_too_small_or_not_baseline_is_refused_by_name() {
    let mut b = Buffers::new();
    let mut out = vec![0u8; 8192];
    // 48 by 32 grayscale: 24 blocks, 915 usable bits, against the 1,976 a
    // 245-byte payload and its length need.
    assert_eq!(
        picture::embed(
            GRAY,
            &v3_payload(198),
            &KEY,
            &mut b.window(),
            &mut tables(),
            &mut out
        ),
        Err(PictureError::NoCapacity)
    );
    assert!(matches!(
        picture::embed(
            PROGRESSIVE,
            &v3_payload(24),
            &KEY,
            &mut b.window(),
            &mut tables(),
            &mut out
        ),
        Err(PictureError::Jpeg(kassigner_jpeg::Error::NotBaseline))
    ));
    let mut tiny = Buffers::new();
    tiny.coefficients.truncate(16);
    assert_eq!(
        picture::embed(
            COLOR_RST,
            &v3_payload(24),
            &KEY,
            &mut tiny.window(),
            &mut tables(),
            &mut out
        ),
        Err(PictureError::NoCapacity)
    );
    tiny.filled.truncate(1);
    assert_eq!(
        picture::extract(COLOR_RST, &KEY, &mut tiny.window(), &mut tables(), &mut out),
        Err(PictureError::Window)
    );
}

// ── exif ────────────────────────────────────────────────────────────────────

fn built(file: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut app1 = vec![0u8; 8192];
    let n = exif::build(file, DESC, payload, &RND, &mut app1).unwrap();
    app1.truncate(n);
    app1
}

#[test]
fn a_host_block_is_carried_forward_with_our_two_tags() {
    let payload = v3_payload(113);
    for (file, le) in [(EXIF_BE, false), (EXIF_LE, true)] {
        let app1 = built(file, &payload);
        let t = Tiff::of_app1(&app1).unwrap();
        assert_eq!(t.little_endian, le, "the host's byte order is kept");
        assert_eq!(t.ascii(tag::IMAGE_DESCRIPTION), Some(DESC));
        assert_eq!(t.user_comment(), Some(&payload[..]));
        let host = Tiff::of_app1(
            &file[segment::exif_app1(file).unwrap().start..segment::exif_app1(file).unwrap().end],
        )
        .unwrap();
        // Every host tag but ours is still there, with its value.
        for e in host.entries(host.ifd0().unwrap()) {
            if e.tag == tag::IMAGE_DESCRIPTION || e.tag == tag::USER_COMMENT {
                continue;
            }
            let mine = t.find(t.ifd0().unwrap(), e.tag).expect("kept");
            assert_eq!(t.value(&mine), host.value(&e), "tag {:#06x}", e.tag);
        }
        assert!(t.ascii(tag::MAKE).is_some());
        // Ascending tag order.
        let tags: Vec<u16> = t.entries(t.ifd0().unwrap()).map(|e| e.tag).collect();
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        assert_eq!(tags, sorted);
        // The sub-directory still reads through the copied block.
        let sub = t
            .field_u32(&t.find(t.ifd0().unwrap(), tag::EXIF_IFD).unwrap())
            .unwrap() as usize;
        assert!(t.entry_count(sub).unwrap() >= 2);
    }
}

#[test]
fn a_photo_with_no_block_gets_a_software_export_one() {
    let payload = v3_payload(24);
    let app1 = built(GRAY, &payload);
    let t = Tiff::of_app1(&app1).unwrap();
    let ifd0 = t.ifd0().unwrap();
    assert_eq!(t.entry_count(ifd0), Some(9));
    assert_eq!(t.ascii(tag::IMAGE_DESCRIPTION), Some(DESC));
    assert_eq!(t.user_comment(), Some(&payload[..]));
    assert!(t.ascii(tag::MAKE).is_none(), "no camera is claimed");
    assert_eq!(t.ascii(tag::SOFTWARE), Some(exif::SOFTWARE[2].as_bytes()));
    assert_eq!(t.ascii(tag::DATE_TIME), Some(&exif::date_time(&RND)[..]));
    let sub = t.field_u32(&t.find(ifd0, tag::EXIF_IFD).unwrap()).unwrap() as usize;
    assert_eq!(t.entry_count(sub), Some(5));
    assert_eq!(
        t.field_u32(&t.find(sub, tag::PIXEL_X_DIMENSION).unwrap()),
        Some(48)
    );
    assert_eq!(
        t.field_u32(&t.find(sub, tag::PIXEL_Y_DIMENSION).unwrap()),
        Some(32)
    );
    // Other random bytes, other program and date.
    let mut app1b = vec![0u8; 8192];
    let n = exif::build(GRAY, DESC, &payload, &[9, 8, 7, 6, 5, 4, 3, 2], &mut app1b).unwrap();
    let tb = Tiff::of_app1(&app1b[..n]).unwrap();
    assert_ne!(tb.ascii(tag::SOFTWARE), t.ascii(tag::SOFTWARE));
    assert_ne!(tb.ascii(tag::DATE_TIME), t.ascii(tag::DATE_TIME));
}

#[test]
fn a_short_descriptor_goes_inline_and_still_reads() {
    let payload = v3_payload(24);
    for d in [&b"ab"[..], b"abc", b"abcd", b"abcde"] {
        for file in [GRAY, EXIF_LE] {
            let mut app1 = vec![0u8; 8192];
            let n = exif::build(file, d, &payload, &RND, &mut app1).unwrap();
            let t = Tiff::of_app1(&app1[..n]).unwrap();
            assert_eq!(t.ascii(tag::IMAGE_DESCRIPTION), Some(d), "{:?}", d);
            assert_eq!(t.user_comment(), Some(&payload[..]));
        }
    }
}

#[test]
fn the_date_is_well_formed_for_any_bytes() {
    for b in [[0u8; 8], [255u8; 8], RND] {
        let d = exif::date_time(&b);
        let s = core::str::from_utf8(&d).unwrap();
        assert_eq!(s.len(), 19);
        assert_eq!(&s[4..5], ":");
        assert_eq!(&s[10..11], " ");
        let y: u32 = s[..4].parse().unwrap();
        assert!((2019..=2025).contains(&y));
    }
}

#[test]
fn place_puts_one_block_after_app0_in_place() {
    let payload = v3_payload(24);
    let app1 = built(EXIF_LE, &payload);
    let mut buf = EXIF_LE.to_vec();
    buf.resize(EXIF_LE.len() + app1.len(), 0);
    let n = exif::place(&mut buf, EXIF_LE.len(), &app1).unwrap();
    let exifs = segment::segments(&buf[..n])
        .filter(|s| segment::is_exif(&buf[..n], s))
        .count();
    assert_eq!(exifs, 1);
    assert_eq!(exif::read_payload(&buf[..n]), Some(&payload[..]));
    assert_eq!(exif::read_descriptor(&buf[..n]), Some(DESC));
    let segs: Vec<_> = segment::segments(&buf[..n]).collect();
    assert_eq!(segs[0].marker, segment::APP0);
    assert!(segment::is_exif(&buf[..n], &segs[1]));
    assert_eq!(
        &buf[segment::scan_start(&buf[..n]).unwrap()..n],
        &EXIF_LE[segment::scan_start(EXIF_LE).unwrap()..]
    );
    let mut small = EXIF_LE.to_vec();
    assert_eq!(
        exif::place(&mut small, EXIF_LE.len(), &app1),
        Err(exif::ExifError::BufferTooSmall)
    );
}

// ── carriers ────────────────────────────────────────────────────────────────

fn run(file: &[u8], carrier: Carrier, payload: &[u8]) -> Vec<u8> {
    let mut b = Buffers::new();
    let mut app1 = vec![0u8; 8192];
    let mut out = vec![0u8; file.len() + stego::carrier::OUT_EXTRA + 8192];
    let e = Export {
        descriptor: DESC,
        payload,
        key: &KEY,
        random: &RND,
    };
    let n = export(
        file,
        carrier,
        &e,
        &mut b.window(),
        &mut tables(),
        &mut app1,
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

fn read(file: &[u8], key: &[u8; KEY_SIZE]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut b = Buffers::new();
    let mut p = [0u8; PAYLOAD_MAX];
    let mut d = [0u8; PAYLOAD_MAX];
    let x = extract(file, key, &mut b.window(), &mut tables(), &mut p, &mut d).unwrap();
    (
        x.picture.map(|n| p[..n].to_vec()),
        x.descriptor.map(|n| d[..n].to_vec()),
    )
}

#[test]
fn each_carrier_exports_and_is_read_back() {
    // The 40 by 40 photo carries 1,280 bits, so it gets a 12-word seed's
    // payload.
    for (file, payload) in [(COLOR_RST, v3_payload(113)), (EXIF_BE, v3_payload(24))] {
        let d = run(file, Carrier::Descriptor, &payload);
        assert_eq!(read(&d, &KEY), (None, Some(payload.clone())));
        assert_eq!(
            &d[segment::scan_start(&d).unwrap()..],
            &file[segment::scan_start(file).unwrap()..],
            "Descriptor leaves the picture alone"
        );

        let p = run(file, Carrier::Picture, &payload);
        assert_eq!(read(&p, &KEY), (Some(payload.clone()), None));
        assert_eq!(
            segment::exif_app1(&p).is_some(),
            segment::exif_app1(file).is_some(),
            "Picture leaves the metadata alone"
        );
        assert_eq!(exif::read_descriptor(&p), exif::read_descriptor(file));

        let both = run(file, Carrier::Both, &payload);
        assert_eq!(
            read(&both, &KEY),
            (Some(payload.clone()), Some(payload.clone()))
        );
        // A wrong key still gets the metadata's payload, not the picture's.
        assert_eq!(read(&both, &WRONG).1, Some(payload.clone()));
        assert_eq!(read(&both, &WRONG).0, None);
    }
}

#[test]
fn both_survives_either_loss_and_a_rerun_of_one_carrier() {
    let payload = v3_payload(113);
    let both = run(COLOR_RST, Carrier::Both, &payload);
    // Metadata stripped: the picture still carries it.
    let seg = segment::exif_app1(&both).unwrap();
    let mut stripped = both[..seg.start].to_vec();
    stripped.extend_from_slice(&both[seg.end..]);
    assert_eq!(read(&stripped, &KEY), (Some(payload.clone()), None));
    // The picture re-run with a new payload: metadata keeps the old one.
    let other = v3_payload(60);
    let again = run(&both, Carrier::Picture, &other);
    assert_eq!(
        read(&again, &KEY),
        (Some(other.clone()), Some(payload.clone()))
    );
    // The metadata re-run: replaced, not doubled.
    let again = run(&both, Carrier::Descriptor, &other);
    assert_eq!(read(&again, &KEY), (Some(payload.clone()), Some(other)));
    assert_eq!(
        segment::segments(&again)
            .filter(|s| segment::is_exif(&again, s))
            .count(),
        1
    );
}

#[test]
fn an_export_is_refused_by_name() {
    let payload = v3_payload(198);
    let mut b = Buffers::new();
    let mut app1 = vec![0u8; 8192];
    let mut out = vec![0u8; 65536];
    let e = Export {
        descriptor: DESC,
        payload: &payload,
        key: &KEY,
        random: &RND,
    };
    assert_eq!(
        export(
            PROGRESSIVE,
            Carrier::Picture,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::Progressive)
    );
    assert_eq!(
        export(
            PROGRESSIVE,
            Carrier::Both,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::Progressive)
    );
    assert_eq!(
        export(
            GRAY,
            Carrier::Picture,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::TooSmall)
    );
    assert!(
        export(
            GRAY,
            Carrier::Descriptor,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        )
        .is_ok(),
        "the metadata needs no capacity"
    );
    assert!(
        export(
            PROGRESSIVE,
            Carrier::Descriptor,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        )
        .is_ok(),
        "nor baseline"
    );
    assert_eq!(
        export(
            b"\x89PNG",
            Carrier::Descriptor,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::NotJpeg)
    );
    let cut = &COLOR_RST[..COLOR_RST.len() - 400];
    assert_eq!(
        export(
            cut,
            Carrier::Picture,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::Damaged)
    );
    let bad = Export {
        descriptor: b"caf\xc3\xa9",
        ..e
    };
    assert_eq!(
        export(
            COLOR_RST,
            Carrier::Descriptor,
            &bad,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::Bounds)
    );
    let bad = Export {
        descriptor: &[b'a'; stego::DESCRIPTOR_WRITE_MAX + 1],
        ..e
    };
    assert_eq!(
        export(
            COLOR_RST,
            Carrier::Descriptor,
            &bad,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut out
        ),
        Err(StegoError::Bounds)
    );
    let mut small = vec![0u8; COLOR_RST.len()];
    assert_eq!(
        export(
            COLOR_RST,
            Carrier::Descriptor,
            &e,
            &mut b.window(),
            &mut tables(),
            &mut app1,
            &mut small
        ),
        Err(StegoError::Bounds)
    );
}

#[test]
fn a_photo_with_nothing_in_it_reads_as_nothing() {
    for file in [GRAY, COLOR_RST, EXIF_BE, EXIF_LE, PROGRESSIVE] {
        let (p, d) = read(file, &KEY);
        assert_eq!((p, d), (None, None), "a plain photo");
    }
    let mut b = Buffers::new();
    let mut p = [0u8; PAYLOAD_MAX];
    let mut d = [0u8; PAYLOAD_MAX];
    assert_eq!(
        extract(
            b"nope",
            &KEY,
            &mut b.window(),
            &mut tables(),
            &mut p,
            &mut d
        ),
        Err(StegoError::NotJpeg)
    );
    // A damaged picture still gives up its metadata.
    let payload = v3_payload(24);
    let both = run(COLOR_RST, Carrier::Both, &payload);
    let cut = &both[..both.len() - 300];
    assert_eq!(read(cut, &KEY), (None, Some(payload)));
}

#[test]
fn the_descriptor_rules_are_the_keyboards() {
    assert!(descriptor_ok(DESC));
    assert!(descriptor_ok(&[b'~'; 64]));
    assert!(!descriptor_ok(&[b'~'; 65]));
    assert!(!descriptor_ok(b""));
    assert!(!descriptor_ok(b"tab\there"));
    assert!(!descriptor_ok("café".as_bytes()));
    assert_eq!(stego::DESCRIPTOR_READ_MAX, 128);
}

#[test]
fn the_carrier_cards_say_what_they_are() {
    assert_eq!(Carrier::ALL.len(), 3);
    for c in Carrier::ALL {
        assert!(!c.label().is_empty() && !c.description().is_empty());
    }
    assert_eq!(Carrier::Both.label(), "Both");
}
