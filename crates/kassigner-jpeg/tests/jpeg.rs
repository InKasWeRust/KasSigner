// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The crate against five small files in `tests/fixtures`: grayscale with
//! JFIF only, 4:2:0 colour with restart markers, progressive, big-endian
//! EXIF (Pillow), and little-endian EXIF with a sub-directory and a
//! `UserComment` (by hand).

use kassigner_jpeg::exif::{self, tag, Field, Kind, Tiff};
use kassigner_jpeg::scan::{self, Tables, Visit, BLOCK};
use kassigner_jpeg::segment;
use kassigner_jpeg::Error;

const GRAY: &[u8] = include_bytes!("fixtures/gray.jpg");
const COLOR_RST: &[u8] = include_bytes!("fixtures/color_rst.jpg");
const PROGRESSIVE: &[u8] = include_bytes!("fixtures/progressive.jpg");
const EXIF_BE: &[u8] = include_bytes!("fixtures/exif_pil.jpg");
const EXIF_LE: &[u8] = include_bytes!("fixtures/exif_le.jpg");

const MAX_BLOCKS: u32 = 1_200_000;

/// A fresh set of tables, for a parse whose frame is not kept.
fn tables() -> Tables {
    Tables::EMPTY
}

/// Changes nothing.
struct Keep;
impl Visit for Keep {
    fn block(&mut self, _: u32, _: &mut [i16; BLOCK]) {}
}

/// Counts blocks and non-zero AC coefficients.
#[derive(Default)]
struct Count {
    blocks: u32,
    nonzero: u32,
}
impl Visit for Count {
    fn block(&mut self, index: u32, c: &mut [i16; BLOCK]) {
        assert_eq!(index, self.blocks);
        self.blocks += 1;
        self.nonzero += c[1..].iter().filter(|&&v| v != 0).count() as u32;
    }
}

fn identity(file: &[u8]) {
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(file, MAX_BLOCKS, &mut tables_f).expect("baseline");
    let mut out = vec![0u8; file.len() + 64];
    let n = scan::rewrite(file, &f, &mut Keep, &mut out).expect("rewrite");
    assert_eq!(&out[..n], file, "decode then encode is the same bytes");
}

#[test]
fn a_grayscale_file_rewrites_to_itself() {
    identity(GRAY);
}

#[test]
fn a_colour_file_with_restart_markers_rewrites_to_itself() {
    identity(COLOR_RST);
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(COLOR_RST, MAX_BLOCKS, &mut tables_f).unwrap();
    assert_eq!(f.restart_interval, 2);
    assert_eq!(f.count, 3);
    // 4:2:0: four luma blocks and one of each chroma per MCU.
    assert_eq!(f.blocks_per_mcu, 6);
    assert_eq!((f.mcus_x, f.mcus_y), (4, 3));
}

#[test]
fn the_files_with_exif_rewrite_to_themselves() {
    identity(EXIF_BE);
    identity(EXIF_LE);
}

#[test]
fn dimensions_come_from_the_frame_header() {
    assert_eq!(segment::dimensions(GRAY), Some((48, 32)));
    assert_eq!(segment::dimensions(COLOR_RST), Some((64, 48)));
    assert_eq!(segment::dimensions(EXIF_BE), Some((40, 40)));
    assert_eq!(segment::dimensions(b"not a jpeg"), None);
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(GRAY, MAX_BLOCKS, &mut tables_f).unwrap();
    assert_eq!((f.width, f.height), (48, 32));
    assert_eq!(f.blocks(), 6 * 4);
    assert_eq!(f.ac_positions(), 24 * 63);
}

#[test]
fn every_block_is_visited_once_in_order() {
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(COLOR_RST, MAX_BLOCKS, &mut tables_f).unwrap();
    let mut c = Count::default();
    scan::read(COLOR_RST, &f, &mut c).unwrap();
    assert_eq!(c.blocks, f.blocks());
    assert!(c.nonzero > 100, "a noisy picture has AC coefficients");
}

#[test]
fn a_changed_coefficient_is_written_and_read_back() {
    struct Dec;
    impl Visit for Dec {
        fn block(&mut self, i: u32, c: &mut [i16; BLOCK]) {
            if i == 3 {
                // The first non-zero AC coefficient, one step toward zero.
                if let Some(v) = c[1..].iter_mut().find(|v| **v != 0) {
                    *v -= v.signum();
                }
            }
        }
    }
    struct Grab(Vec<[i16; BLOCK]>);
    impl Visit for Grab {
        fn block(&mut self, _: u32, c: &mut [i16; BLOCK]) {
            self.0.push(*c);
        }
    }
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(COLOR_RST, MAX_BLOCKS, &mut tables_f).unwrap();
    let mut before = Grab(Vec::new());
    scan::read(COLOR_RST, &f, &mut before).unwrap();
    let mut out = vec![0u8; COLOR_RST.len() + 64];
    let n = scan::rewrite(COLOR_RST, &f, &mut Dec, &mut out).unwrap();
    assert_ne!(&out[..n], COLOR_RST);
    let mut tables_g = Tables::EMPTY;
    let g = scan::parse(&out[..n], MAX_BLOCKS, &mut tables_g).unwrap();
    let mut after = Grab(Vec::new());
    scan::read(&out[..n], &g, &mut after).unwrap();
    assert_eq!(before.0.len(), after.0.len());
    for (i, (b, a)) in before.0.iter().zip(&after.0).enumerate() {
        if i == 3 {
            let k = b[1..].iter().position(|&v| v != 0).unwrap() + 1;
            assert_eq!(a[k], b[k] - b[k].signum());
            let mut fixed = *b;
            fixed[k] = a[k];
            assert_eq!(*a, fixed, "only that coefficient changed");
        } else {
            assert_eq!(a, b, "block {i} untouched");
        }
    }
}

#[test]
fn a_progressive_file_is_refused_by_name() {
    assert_eq!(
        scan::parse(PROGRESSIVE, MAX_BLOCKS, &mut tables()).err(),
        Some(Error::NotBaseline)
    );
}

#[test]
fn a_frame_past_the_block_limit_is_too_large() {
    assert_eq!(
        scan::parse(GRAY, 23, &mut tables()).err(),
        Some(Error::TooLarge)
    );
    assert!(scan::parse(GRAY, 24, &mut tables()).is_ok());
}

#[test]
fn a_scan_cut_short_is_truncated() {
    let cut = &GRAY[..GRAY.len() - 300];
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(cut, MAX_BLOCKS, &mut tables_f).expect("the header is whole");
    assert_eq!(scan::read(cut, &f, &mut Keep).err(), Some(Error::Truncated));
    let mut out = vec![0u8; GRAY.len()];
    assert_eq!(
        scan::rewrite(cut, &f, &mut Keep, &mut out).err(),
        Some(Error::Truncated)
    );
}

#[test]
fn a_file_that_is_not_a_jpeg_is_refused() {
    assert_eq!(
        scan::parse(b"\x89PNG\r\n", MAX_BLOCKS, &mut tables()).err(),
        Some(Error::NotJpeg)
    );
    assert!(!segment::is_jpeg(b"\xff"));
    assert_eq!(segment::segments(b"\xff\xd8\xff").count(), 0);
}

#[test]
fn a_short_output_buffer_is_refused() {
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(GRAY, MAX_BLOCKS, &mut tables_f).unwrap();
    let mut out = vec![0u8; GRAY.len() - 10];
    assert_eq!(
        scan::rewrite(GRAY, &f, &mut Keep, &mut out).err(),
        Some(Error::BufferTooSmall)
    );
}

#[test]
fn segments_walk_to_start_of_scan() {
    let segs: Vec<_> = segment::segments(GRAY).collect();
    assert_eq!(segs.first().map(|s| s.marker), Some(segment::APP0));
    assert_eq!(segs.last().map(|s| s.marker), Some(segment::SOS));
    assert!(segs.iter().any(|s| s.marker == segment::DHT));
    assert_eq!(segment::scan_start(GRAY), segs.last().map(|s| s.start));
    assert!(segment::exif_app1(GRAY).is_none());
}

#[test]
fn a_big_endian_exif_block_reads() {
    let seg = segment::exif_app1(EXIF_BE).expect("Pillow wrote one");
    let t = Tiff::of_app1(&EXIF_BE[seg.start..seg.end]).unwrap();
    assert!(!t.little_endian);
    assert_eq!(t.ascii(tag::MAKE), Some(&b"KasSigner"[..]));
    assert_eq!(t.ascii(tag::MODEL), Some(&b"Fixture"[..]));
    assert_eq!(t.ascii(tag::DATE_TIME), Some(&b"2024:08:01 10:20:30"[..]));
    assert_eq!(
        t.ascii(tag::IMAGE_DESCRIPTION),
        Some(&b"A test picture"[..])
    );
    assert!(t.user_comment().is_none());
    let ifd0 = t.ifd0().unwrap();
    let e = t.find(ifd0, tag::EXIF_IFD).unwrap();
    let sub = t.field_u32(&e).unwrap() as usize;
    let x = t.find(sub, tag::PIXEL_X_DIMENSION).unwrap();
    assert_eq!(t.field_u32(&x), Some(40));
    // Ascending tag order, as the specification requires.
    let tags: Vec<u16> = t.entries(ifd0).map(|e| e.tag).collect();
    let mut sorted = tags.clone();
    sorted.sort_unstable();
    assert_eq!(tags, sorted);
}

#[test]
fn a_little_endian_exif_block_reads() {
    let seg = segment::exif_app1(EXIF_LE).unwrap();
    let t = Tiff::of_app1(&EXIF_LE[seg.start..seg.end]).unwrap();
    assert!(t.little_endian);
    assert_eq!(t.ascii(tag::MAKE), Some(&b"IICamera"[..]));
    assert_eq!(t.ascii(tag::DATE_TIME), Some(&b"2023:03:04 05:06:07"[..]));
    assert_eq!(t.user_comment(), Some(&b"hello comment"[..]));
    let ifd0 = t.ifd0().unwrap();
    let o = t.find(ifd0, tag::ORIENTATION).unwrap();
    assert_eq!(o.kind(), Some(Kind::Short));
    assert_eq!(t.field_u32(&o), Some(1));
    assert_eq!(t.value(&o), Some(&[1u8, 0][..]));
    assert_eq!(t.next_ifd(ifd0), Some(0));
    let sub = t.field_u32(&t.find(ifd0, tag::EXIF_IFD).unwrap()).unwrap() as usize;
    assert_eq!(t.entry_count(sub), Some(2));
    assert_eq!(
        t.value(&t.find(sub, tag::EXIF_VERSION).unwrap()),
        Some(&b"0232"[..])
    );
}

#[test]
fn a_damaged_block_gives_none_not_a_panic() {
    let seg = segment::exif_app1(EXIF_LE).unwrap();
    let mut bad = EXIF_LE[seg.start..seg.end].to_vec();
    // The first directory past the end; the last two wrap with the count's
    // two bytes where `usize` is 32 bits, as on a unit.
    for off in [0xFFFF_FFF0u32, 0xFFFF_FFFE, 0xFFFF_FFFF] {
        bad[14..18].copy_from_slice(&off.to_le_bytes());
        let t = Tiff::of_app1(&bad).unwrap();
        assert!(t.ifd0().is_none(), "{off:#x}");
        assert!(t.user_comment().is_none(), "{off:#x}");
        assert!(t.ascii(tag::IMAGE_DESCRIPTION).is_none(), "{off:#x}");
    }
    // Not a TIFF header at all.
    bad[10..12].copy_from_slice(b"XX");
    assert!(Tiff::of_app1(&bad).is_none());
    assert!(Tiff::of_app1(&bad[..8]).is_none());
}

/// An offset at the top of the address range gives `None`, not a panic,
/// for an entry read or built by hand.
#[test]
fn an_offset_at_the_top_of_memory_gives_none() {
    let seg = segment::exif_app1(EXIF_LE).unwrap();
    let t = Tiff::of_app1(&EXIF_LE[seg.start..seg.end]).unwrap();
    for at in [usize::MAX, usize::MAX - 1, usize::MAX - 3] {
        assert_eq!(t.u16_at(at), None, "{at:#x}");
        assert_eq!(t.u32_at(at), None, "{at:#x}");
        assert_eq!(t.entry_count(at), None, "{at:#x}");
        assert_eq!(t.next_ifd(at), None, "{at:#x}");
        assert!(t.find(at, tag::ORIENTATION).is_none(), "{at:#x}");
    }
    // One entry whose value sits inline, one whose value is at an offset.
    let ifd0 = t.ifd0().unwrap();
    let inline = t.find(ifd0, tag::ORIENTATION).unwrap();
    let away = t.find(ifd0, tag::USER_COMMENT).unwrap();
    assert!(t.value(&inline).is_some() && t.value(&away).is_some());
    for real in [inline, away] {
        for at in [usize::MAX, usize::MAX - 4, usize::MAX - 8] {
            let e = exif::Entry { at, ..real };
            assert_eq!(t.value(&e), None, "{at:#x}");
            assert_eq!(t.field_u32(&e), None, "{at:#x}");
        }
    }
}

/// A segment that is not the file's has an empty payload.
#[test]
fn a_segment_from_another_file_has_an_empty_payload() {
    let seg = segment::exif_app1(EXIF_LE).unwrap();
    assert!(!seg.payload(EXIF_LE).is_empty());
    assert!(seg.payload(&EXIF_LE[..seg.end - 1]).is_empty());
    let wild = segment::Segment {
        marker: segment::APP1,
        start: usize::MAX,
        end: usize::MAX,
    };
    assert!(wild.payload(EXIF_LE).is_empty());
}

/// A longer file's frame, given another file, is `Malformed`.
#[test]
fn a_frame_from_another_file_is_malformed() {
    let mut tables_f = Tables::EMPTY;
    let f = scan::parse(COLOR_RST, MAX_BLOCKS, &mut tables_f).unwrap();
    assert!(
        f.scan_end > GRAY.len(),
        "the frame ends past the other file"
    );
    assert_eq!(
        scan::read(GRAY, &f, &mut Keep).err(),
        Some(Error::Malformed)
    );
    let mut out = vec![0u8; COLOR_RST.len() + 64];
    assert_eq!(
        scan::rewrite(GRAY, &f, &mut Keep, &mut out).err(),
        Some(Error::Malformed)
    );
}

/// A block of two entries, one inline and one at an offset, in `le` order.
fn two_tag_block(le: bool, comment: &[u8], out: &mut [u8]) -> usize {
    let mut w = exif::Writer::new(out, le).unwrap();
    let ifd0 = w.offset() as u32;
    w.ifd(2).unwrap();
    w.short(tag::ORIENTATION, 1).unwrap();
    let data = ifd0 as usize + 2 + 2 * 12 + 4;
    let uc_len = (exif::USER_COMMENT_CHARSET + comment.len()) as u32;
    w.entry(
        tag::USER_COMMENT,
        Kind::Undefined,
        uc_len,
        Field::Offset(data as u32),
    )
    .unwrap();
    w.next_ifd(0).unwrap();
    assert_eq!(w.offset(), data);
    w.put(&[0u8; exif::USER_COMMENT_CHARSET]).unwrap();
    w.put(comment).unwrap();
    w.set_ifd0(ifd0);
    w.finish().unwrap()
}

#[test]
fn a_written_block_reads_back_in_both_orders() {
    for le in [true, false] {
        let mut buf = [0u8; 256];
        let n = two_tag_block(le, b"payload bytes \x00\xff", &mut buf);
        let t = Tiff::of_app1(&buf[..n]).unwrap();
        assert_eq!(t.little_endian, le);
        assert_eq!(t.user_comment(), Some(&b"payload bytes \x00\xff"[..]));
        let o = t.find(t.ifd0().unwrap(), tag::ORIENTATION).unwrap();
        assert_eq!(t.field_u32(&o), Some(1));
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]) as usize, n - 2);
    }
}

#[test]
fn a_writer_refuses_what_does_not_fit() {
    let mut small = [0u8; 20];
    let mut w = exif::Writer::new(&mut small, true).unwrap();
    assert_eq!(w.put(&[0u8; 3]).err(), Some(Error::BufferTooSmall));
    let mut tiny = [0u8; 12];
    assert!(exif::Writer::new(&mut tiny, true).is_err());
}

#[test]
fn replacing_exif_puts_one_block_after_app0_and_keeps_the_scan() {
    let mut app1 = [0u8; 128];
    let n = two_tag_block(true, b"new", &mut app1);
    // A file with none gains one.
    let mut out = vec![0u8; GRAY.len() + n];
    let m = segment::replace_exif(GRAY, &app1[..n], &mut out).unwrap();
    assert_eq!(m, GRAY.len() + n);
    let segs: Vec<_> = segment::segments(&out[..m]).collect();
    assert_eq!(segs[0].marker, segment::APP0);
    assert!(segment::is_exif(&out[..m], &segs[1]));
    let sos = segment::scan_start(&out[..m]).unwrap();
    assert_eq!(&out[sos..m], &GRAY[segment::scan_start(GRAY).unwrap()..]);
    let t = Tiff::of_app1(&out[segs[1].start..segs[1].end]).unwrap();
    assert_eq!(t.user_comment(), Some(&b"new"[..]));

    // A file with one has it replaced, not doubled.
    let mut out = vec![0u8; EXIF_LE.len() + n];
    let m = segment::replace_exif(EXIF_LE, &app1[..n], &mut out).unwrap();
    let exifs = segment::segments(&out[..m])
        .filter(|s| segment::is_exif(&out[..m], s))
        .count();
    assert_eq!(exifs, 1);
    let seg = segment::exif_app1(&out[..m]).unwrap();
    let t = Tiff::of_app1(&out[seg.start..seg.end]).unwrap();
    assert_eq!(t.user_comment(), Some(&b"new"[..]));
    assert!(scan::parse(&out[..m], MAX_BLOCKS, &mut tables()).is_ok());
    identity(&out[..m]);

    let mut short = vec![0u8; GRAY.len()];
    assert_eq!(
        segment::replace_exif(GRAY, &app1[..n], &mut short).err(),
        Some(Error::BufferTooSmall)
    );
    assert_eq!(
        segment::replace_exif(b"nope", &app1[..n], &mut short).err(),
        Some(Error::NotJpeg)
    );
}

/// The Huffman tables are the caller's [`Tables`], the frame stays small,
/// and one set serves file after file.
#[test]
fn the_tables_are_the_callers_and_the_frame_is_small() {
    assert!(core::mem::size_of::<Tables>() > 9_000);
    assert!(core::mem::size_of::<scan::Frame<'_>>() < 256);
    let mut tables = Tables::EMPTY;
    for file in [GRAY, COLOR_RST, GRAY] {
        let f = scan::parse(file, MAX_BLOCKS, &mut tables).unwrap();
        let mut out = vec![0u8; file.len() + 64];
        let n = scan::rewrite(file, &f, &mut Keep, &mut out).unwrap();
        assert_eq!(&out[..n], file);
    }
}
