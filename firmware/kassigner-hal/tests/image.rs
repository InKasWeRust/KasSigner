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

//! The running image's hash, over images built as espflash writes them.
//!
//! ```text
//! IMAGE_BIN=kassigner.bin cargo +esp195 test -p kassigner-hal --test image
//! ```
//!
//! also hashes a real `.bin`, unsigned or signed, and prints what the
//! verification screen shows for it.

use kassigner_hal::image::{self, Error, Hashed, Image, ReadFailed, CHUNK, MAGIC, MAX_SEGMENTS};
use sha2::{Digest, Sha256};

/// Flash as a buffer, from the image's first byte; remembers the furthest
/// byte read.
struct Flash {
    bytes: Vec<u8>,
    furthest: usize,
    fail_at: Option<u32>,
}

impl Flash {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            furthest: 0,
            fail_at: None,
        }
    }
}

impl Image for Flash {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), ReadFailed> {
        let from = offset as usize;
        let to = from + buf.len();
        if self
            .fail_at
            .is_some_and(|at| (from..to).contains(&(at as usize)))
            || to > self.bytes.len()
        {
            return Err(ReadFailed);
        }
        buf.copy_from_slice(&self.bytes[from..to]);
        self.furthest = self.furthest.max(to);
        Ok(())
    }

    fn limit(&self) -> u32 {
        self.bytes.len() as u32
    }
}

/// An image as espflash writes it: header, segments, zeros and checksum to
/// a 16-byte boundary, and the SHA-256 of all that if `appended`.
fn build(segments: &[&[u8]], appended: bool) -> Vec<u8> {
    let mut v = vec![0u8; 24];
    v[0] = MAGIC;
    v[1] = segments.len() as u8;
    v[2] = 2; // DIO
    v[3] = 0x40; // 16 MB, 40 MHz
    v[4..8].copy_from_slice(&0x4037_86c8u32.to_le_bytes());
    v[12..14].copy_from_slice(&9u16.to_le_bytes()); // the S3's chip id
    v[23] = u8::from(appended);
    let mut checksum = 0xEFu8;
    for (i, seg) in segments.iter().enumerate() {
        v.extend_from_slice(&(0x3C00_0020u32 + 0x1_0000 * i as u32).to_le_bytes());
        v.extend_from_slice(&(seg.len() as u32).to_le_bytes());
        v.extend_from_slice(seg);
        checksum = seg.iter().fold(checksum, |c, b| c ^ b);
    }
    while v.len() % 16 != 15 {
        v.push(0);
    }
    v.push(checksum);
    if appended {
        let digest = Sha256::digest(&v);
        v.extend_from_slice(&digest);
    }
    v
}

/// Three segments, sized so the image crosses several chunks.
fn segments() -> Vec<Vec<u8>> {
    [1000usize, 3, 2 * CHUNK + 17]
        .iter()
        .enumerate()
        .map(|(i, &n)| (0..n).map(|j| (j * 7 + i * 13) as u8).collect())
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The hash is the unsigned file's, and only its bytes are read.
#[test]
fn the_hash_is_the_files() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let file = build(&parts, true);
    let mut flash = Flash::new(file.clone());
    let hashed = image::hash(&mut flash).unwrap();
    assert_eq!(
        hashed,
        Hashed {
            len: file.len() as u32,
            sha256: sha256(&file)
        }
    );
    assert_eq!(flash.furthest, file.len(), "nothing past the image is read");
    assert_eq!(file.len() % 16, 0);
}

/// A signed image hashes as its unsigned file: padding and signature sector
/// are neither read nor hashed.
#[test]
fn a_signed_image_hashes_as_the_unsigned_file() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let unsigned = build(&parts, true);
    let mut signed = unsigned.clone();
    signed.resize(unsigned.len().div_ceil(4096) * 4096, 0xFF);
    let mut sector = vec![0xFFu8; 4096];
    sector[0] = 0xE7;
    sector[1] = 0x02;
    signed.extend_from_slice(&sector);
    let mut flash = Flash::new(signed);
    let hashed = image::hash(&mut flash).unwrap();
    assert_eq!(hashed.len as usize, unsigned.len());
    assert_eq!(hashed.sha256, sha256(&unsigned));
    assert_eq!(flash.furthest, unsigned.len());
}

/// An image with no appended digest is hashed to its checksum byte.
#[test]
fn an_image_without_its_digest_ends_at_the_checksum() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let file = build(&parts, false);
    let mut bytes = file.clone();
    bytes.extend_from_slice(&[0xAB; 100]);
    let hashed = image::hash(&mut Flash::new(bytes)).unwrap();
    assert_eq!(hashed.len as usize, file.len());
    assert_eq!(hashed.sha256, sha256(&file));
}

/// A byte misread or changed is a mismatch, never a hash.
#[test]
fn a_changed_byte_is_a_mismatch() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let file = build(&parts, true);
    for at in [40, 1100, file.len() - 40, file.len() - 1] {
        let mut bytes = file.clone();
        bytes[at] ^= 0x01;
        assert_eq!(
            image::hash(&mut Flash::new(bytes)),
            Err(Error::Mismatch),
            "byte {at}"
        );
    }
}

#[test]
fn what_is_not_an_image_is_refused() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let file = build(&parts, true);

    let mut erased = file.clone();
    erased[0] = 0xFF;
    assert_eq!(image::hash(&mut Flash::new(erased)), Err(Error::NotAnImage));

    let mut many = file.clone();
    many[1] = MAX_SEGMENTS + 1;
    assert_eq!(image::hash(&mut Flash::new(many)), Err(Error::Segments));

    // A segment running past the end of the flash.
    let mut long = file.clone();
    long[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(image::hash(&mut Flash::new(long)), Err(Error::TooLong));

    // The image cut short by the flash's end.
    let short = file[..file.len() - 1].to_vec();
    assert_eq!(image::hash(&mut Flash::new(short)), Err(Error::TooLong));
}

#[test]
fn a_read_that_fails_is_said() {
    let segs = segments();
    let parts: Vec<&[u8]> = segs.iter().map(Vec::as_slice).collect();
    let file = build(&parts, true);
    for at in [0, 25, 5000, file.len() as u32 - 1] {
        let mut flash = Flash::new(file.clone());
        flash.fail_at = Some(at);
        assert_eq!(image::hash(&mut flash), Err(Error::Read), "byte {at}");
    }
}

/// What the console prints: the length and all 64 digits.
#[test]
fn the_console_line_is_sha256sums_digits() {
    let hashed = Hashed {
        len: 912_000,
        sha256: [0xab; 32],
    };
    assert_eq!(
        hashed.to_string(),
        format!("912000 bytes, sha256 {}", "ab".repeat(32))
    );
}

/// With `IMAGE_BIN` set, hashes a real `.bin`: an unsigned file's hash must
/// be its own SHA-256; a signed one must have a signature sector at the next
/// 4 KB.
#[test]
fn a_real_bin() {
    let Some(path) = std::env::var_os("IMAGE_BIN") else {
        return;
    };
    let bytes = std::fs::read(&path).unwrap();
    let hashed = image::hash(&mut Flash::new(bytes.clone())).unwrap();
    println!("{}: {hashed}", path.to_string_lossy());
    if hashed.len as usize == bytes.len() {
        assert_eq!(hashed.sha256, sha256(&bytes), "an unsigned file's own hash");
    } else {
        assert_eq!(
            bytes[(hashed.len as usize).div_ceil(4096) * 4096],
            0xE7,
            "a signature sector"
        );
    }
}
