// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A card a v1.0.7 unit formatted and wrote, read here.
//!
//! `spec/vectors/v107/card.sectors` is v1.0.7's `do_format_fat32` on a blank
//! card of 70,000 sectors, then every file of `cards/` written in order with
//! its `create_file`. Stored sparse: a header line, then each sector not all
//! zeros, as its number (`u32`, little-endian) and its 512 bytes.

use kassigner_fat32::block::{Memory, BLOCK_SIZE};
use kassigner_fat32::fat32::{
    create_file, find_file_in_root, list_root_dir, mount_fat32, read_file, to_83_name,
};

/// A corpus file, built into the test.
macro_rules! corpus {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}

/// The files 1.0.7 wrote to the card, in the order it wrote them.
const FILES: [(&str, &[u8]); 10] = [
    ("SD000001.KAS", corpus!("cards/SD000001.KAS")),
    ("SD000002.KAS", corpus!("cards/SD000002.KAS")),
    ("SD000003.KAS", corpus!("cards/SD000003.KAS")),
    ("XP000001.KAS", corpus!("cards/XP000001.KAS")),
    ("RAWHINT.KAS", corpus!("cards/RAWHINT.KAS")),
    ("KP000001.TXT", corpus!("cards/KP000001.TXT")),
    ("KP000002.TXT", corpus!("cards/KP000002.TXT")),
    ("KP000003.TXT", corpus!("cards/KP000003.TXT")),
    ("TX000001.KSP", corpus!("cards/TX000001.KSP")),
    ("TX000002.KSP", corpus!("cards/TX000002.KSP")),
];

/// The card, laid back out from its sparse form.
fn card() -> Memory<Vec<[u8; BLOCK_SIZE]>> {
    let image: &[u8] = corpus!("card.sectors");
    let end = image
        .iter()
        .position(|&b| b == b'\n')
        .expect("a header line");
    let header = core::str::from_utf8(&image[..end]).expect("text");
    let sectors: usize = header
        .strip_prefix("KASSIGNER-CARD sectors=")
        .expect("the header")
        .parse()
        .expect("a count");
    let mut blocks = vec![[0u8; BLOCK_SIZE]; sectors];
    let records = &image[end + 1..];
    assert_eq!(records.len() % (4 + BLOCK_SIZE), 0, "whole records");
    for r in records.chunks_exact(4 + BLOCK_SIZE) {
        let at = u32::from_le_bytes(r[..4].try_into().unwrap()) as usize;
        blocks[at].copy_from_slice(&r[4..]);
    }
    Memory::new(blocks)
}

/// The root lists exactly the files 1.0.7 wrote, in its order, at their
/// sizes.
#[test]
fn a_card_from_1_0_7_mounts_and_lists_what_it_wrote() {
    let mut dev = card();
    let fat = mount_fat32(&mut dev).expect("mounts");
    let mut listed = Vec::new();
    list_root_dir(&mut dev, &fat, |e| {
        listed.push((e.name, e.file_size as usize));
        true
    })
    .expect("lists");
    let want: Vec<_> = FILES
        .iter()
        .map(|(n, b)| (to_83_name(n.as_bytes()), b.len()))
        .collect();
    assert_eq!(listed, want);
}

/// Every file reads back as the bytes 1.0.7 wrote.
#[test]
fn every_file_on_a_1_0_7_card_reads_back() {
    let mut dev = card();
    let fat = mount_fat32(&mut dev).expect("mounts");
    for (name, bytes) in FILES {
        let (entry, _, _) =
            find_file_in_root(&mut dev, &fat, &to_83_name(name.as_bytes())).expect(name);
        let mut out = vec![0u8; bytes.len().next_multiple_of(BLOCK_SIZE)];
        let n = read_file(&mut dev, &fat, &entry, &mut out).expect(name);
        assert_eq!(&out[..n], bytes, "{name}");
    }
}

/// A file this crate writes onto a 1.0.7 card leaves its files as they
/// were, and reads back itself.
#[test]
fn a_file_written_onto_a_1_0_7_card_leaves_its_files_alone() {
    let mut dev = card();
    let fat = mount_fat32(&mut dev).expect("mounts");
    let new = [0x5au8; 1500];
    create_file(&mut dev, &fat, &to_83_name(b"NEWFILE.KAS"), &new).expect("written");
    let fat = mount_fat32(&mut dev).expect("still mounts");
    for (name, bytes) in FILES.iter().copied().chain([("NEWFILE.KAS", &new[..])]) {
        let (entry, _, _) =
            find_file_in_root(&mut dev, &fat, &to_83_name(name.as_bytes())).expect(name);
        let mut out = vec![0u8; bytes.len().next_multiple_of(BLOCK_SIZE)];
        let n = read_file(&mut dev, &fat, &entry, &mut out).expect(name);
        assert_eq!(&out[..n], bytes, "{name}");
    }
}
