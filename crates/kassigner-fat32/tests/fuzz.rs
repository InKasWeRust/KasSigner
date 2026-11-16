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

//! A card, fuzzed (`testkit/mutate.rs`): whatever its boot sector, FAT and
//! directory hold, mounting it, listing it, reading its files and writing
//! one all return. A card is fed as `card.sectors` stores one: each sector
//! not all zeros, as its number (`u32`, little-endian) and its 512 bytes.

#[path = "../../../testkit/mutate.rs"]
mod mutate;

use std::collections::BTreeMap;

use kassigner_fat32::block::{BlockDevice, Error, BLOCK_SIZE};
use kassigner_fat32::fat32::{
    create_file, delete_file, do_format_fat32, file_holds, find_file_in_root, list_root_dir,
    list_root_dir_lfn, mount_fat32, overwrite_file, read_fat_entry, read_file, DirEntry,
};

/// The recorded card's size, in sectors.
const SECTORS: u32 = 70_000;

/// The largest buffer a read gets: past any file a unit reads.
const READ_MAX: usize = 1 << 20;

/// A card of [`SECTORS`] held sparse: the sectors written, zeros elsewhere.
struct Sparse(BTreeMap<u32, [u8; BLOCK_SIZE]>);

impl Sparse {
    /// The card `data` describes; a record cut short or past the card is
    /// dropped.
    fn of(data: &[u8]) -> Self {
        let mut map = BTreeMap::new();
        for r in data.chunks_exact(4 + BLOCK_SIZE) {
            let at = u32::from_le_bytes(r[..4].try_into().unwrap());
            if at < SECTORS {
                map.insert(at, r[4..].try_into().unwrap());
            }
        }
        Self(map)
    }

    fn records(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (at, block) in &self.0 {
            if block.iter().any(|&b| b != 0) {
                out.extend_from_slice(&at.to_le_bytes());
                out.extend_from_slice(block);
            }
        }
        out
    }
}

impl BlockDevice for Sparse {
    fn blocks(&self) -> u32 {
        SECTORS
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= SECTORS {
            return Err(Error::OutOfRange {
                block,
                blocks: SECTORS,
            });
        }
        *buf = self.0.get(&block).copied().unwrap_or([0; BLOCK_SIZE]);
        Ok(())
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        if block >= SECTORS {
            return Err(Error::OutOfRange {
                block,
                blocks: SECTORS,
            });
        }
        self.0.insert(block, *data);
        Ok(())
    }
}

/// The seed cards: the recorded one, and one this crate formats and fills.
fn cards() -> Vec<Vec<u8>> {
    let recorded = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../spec/vectors/v107/card.sectors"),
    )
    .unwrap();
    let end = recorded.iter().position(|&b| b == b'\n').unwrap();
    let mut out = vec![recorded[end + 1..].to_vec()];

    let mut ours = Sparse(BTreeMap::new());
    do_format_fat32(&mut ours).unwrap();
    let info = mount_fat32(&mut ours).unwrap();
    for (i, len) in [0usize, 1, 511, 512, 513, 5000].into_iter().enumerate() {
        let name = *b"FILE0000TXT";
        let mut name = name;
        name[7] = b'0' + i as u8;
        let data: Vec<u8> = (0..len).map(|k| (k * 31 + i) as u8).collect();
        create_file(&mut ours, &info, &name, &data).unwrap();
    }
    out.push(ours.records());
    out
}

/// Mount and list the card, then find, read and check the root's first 64
/// entries.
fn read_all(card: &mut Sparse) {
    let Ok(info) = mount_fat32(card) else {
        return;
    };
    let mut entries: Vec<DirEntry> = Vec::new();
    let _ = list_root_dir(card, &info, |e| {
        entries.push(*e);
        entries.len() < 64
    });
    let _ = list_root_dir_lfn(card, &info, |_, _, _| true);
    for e in &entries {
        let _ = find_file_in_root(card, &info, &e.name);
        let mut out = vec![0u8; (e.file_size as usize).min(READ_MAX)];
        if let Ok(n) = read_file(card, &info, e, &mut out) {
            let _ = file_holds(card, &info, e, &out[..n]);
        }
        let first = u32::from(e.cluster_hi) << 16 | u32::from(e.cluster_lo);
        let _ = read_fat_entry(card, &info, first);
    }
}

fn reads(data: &[u8]) {
    read_all(&mut Sparse::of(data));
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn reading_any_card() {
    mutate::run("card read", 4000, cards(), reads);
}

/// A file created, written over and deleted, then the card read back.
fn writes(data: &[u8]) {
    let mut card = Sparse::of(data);
    let Ok(info) = mount_fat32(&mut card) else {
        return;
    };
    let name = *b"KS000001KAS";
    let _ = create_file(&mut card, &info, &name, &[0x42; 700]);
    let _ = overwrite_file(&mut card, &info, &name, &[0x24; 1500]);
    let _ = delete_file(&mut card, &info, &name);
    read_all(&mut card);
}

#[test]
#[ignore = "fuzz: run with cargo +esp195 fuzz-all"]
fn writing_to_any_card() {
    mutate::run("card write", 2500, cards(), writes);
}
