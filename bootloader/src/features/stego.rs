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

// features/stego.rs — Steganography codec (JPEG EXIF)
//
// Hides encrypted seed data inside JPEG EXIF metadata fields.
// The image pixels are untouched — survives recompression, resizing,
// filters, cloud upload (if metadata is preserved).
//
// EXIF layout:
//   ImageDescription = plain cover text (innocent photo caption)
//   UserComment      = base64(encrypted_seed) [| base64(encrypted_hint)]
//
// Encryption: AES-256-GCM with PBKDF2-derived key (100K iterations).
// Recovery hint is encrypted separately with the descriptor as password.

// ─── Recovery Hint Presets ──────────────────────────────────────────

/// Preset recovery hints for JPEG EXIF stego export.
/// The answer to the hint IS the user's BIP39 passphrase.
pub const HINT_PRESETS: [&str; 3] = [
    "My favorite place I lived?",
    "Name of my loved one?",
    "Song I can't stop humming?",
];

/// Total hint options: 3 presets + 1 custom
pub const HINT_OPTION_COUNT: u8 = 4;
// ═══════════════════════════════════════════════════════════════════
// Stego Mode Enum
// ═══════════════════════════════════════════════════════════════════

/// Available steganography modes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StegoMode {
    /// JPEG EXIF metadata — hide seed in photo metadata fields
    JpegExif,
}

impl StegoMode {
pub fn label(&self) -> &'static str {
    match self {
        StegoMode::JpegExif => "JPEG Metadata (SD)",
    }
}
pub fn description(&self) -> &'static str {
    match self {
        StegoMode::JpegExif => "Hide seed in photo metadata. Needs SD with JPEG image.",
    }
}
}

pub const ALL_MODES: [StegoMode; 1] = [
    StegoMode::JpegExif,
];

// ═══════════════════════════════════════════════════════════════════
// MODE 6: JPEG EXIF Metadata Steganography (SD Card)
// ═══════════════════════════════════════════════════════════════════
//
// Hides encrypted seed data inside JPEG EXIF metadata fields.
// The image pixels are completely untouched — survives recompression,
// resizing, filters, cloud upload, email, social media (if metadata
// is preserved).
//
// Approach (BetterHumanz "The Vault" style):
//   1. Read JPEG from SD card
//   2. Encrypt seed with passphrase (AES-256-CBC via PBKDF2)
//   3. Base64-encode the encrypted blob
//   4. Write into JPEG EXIF fields:
//      - UserComment (tag 0x9286): base64 encrypted data
//      - ImageDescription (tag 0x010E): innocent cover text
//   5. Write modified JPEG back to SD card
//
// Recovery:
//   1. Read JPEG from SD card
//   2. Extract base64 from UserComment EXIF field
//   3. Decode base64 → encrypted blob
//   4. Decrypt with passphrase → validate BIP39 checksum
//
// JPEG structure:
//   [FFD8] SOI
//   [FFE1] APP1 marker (EXIF)
//     [length: 2B BE]
//     "Exif\0\0"
//     TIFF header (II or MM + 0x002A + offset to IFD0)
//     IFD0 entries (tag, type, count, value/offset)
//   [FFE0] APP0 (JFIF) — optional
//   [FFDB] DQT, [FFC0] SOF, [FFC4] DHT, [FFDA] SOS + image data
//   [FFD9] EOI

/// JPEG markers
const JPEG_SOI: [u8; 2] = [0xFF, 0xD8];
const JPEG_APP1: [u8; 2] = [0xFF, 0xE1];
const JPEG_EOI: [u8; 2] = [0xFF, 0xD9];

/// EXIF header: "Exif\0\0"
const EXIF_HEADER: [u8; 6] = [0x45, 0x78, 0x69, 0x66, 0x00, 0x00];

/// TIFF byte order: little-endian "II"
const TIFF_LE: [u8; 2] = [0x49, 0x49];

/// TIFF magic: 0x002A (LE)
const TIFF_MAGIC_LE: [u8; 2] = [0x2A, 0x00];

/// EXIF IFD tag for ImageDescription
const TAG_IMAGE_DESCRIPTION: u16 = 0x010E;

/// EXIF IFD tag for UserComment (in Exif IFD)
const TAG_USER_COMMENT: u16 = 0x9286;

/// Maximum EXIF APP1 segment we'll generate (keep it small)
const MAX_EXIF_SIZE: usize = 2048;

/// Base64 encoding table
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 encode a byte slice into output buffer. Returns bytes written.
pub fn base64_encode(input: &[u8], input_len: usize, output: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let mut i = 0usize;

    while i + 2 < input_len {
        if pos + 4 > output.len() { break; }
        let a = input[i] as u32;
        let b = input[i + 1] as u32;
        let c = input[i + 2] as u32;
        let triple = (a << 16) | (b << 8) | c;
        output[pos] = B64[((triple >> 18) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[((triple >> 12) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[((triple >> 6) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[(triple & 0x3F) as usize]; pos += 1;
        i += 3;
    }

    let remaining = input_len - i;
    if remaining == 1 && pos + 4 <= output.len() {
        let a = input[i] as u32;
        output[pos] = B64[((a >> 2) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[((a << 4) & 0x3F) as usize]; pos += 1;
        output[pos] = b'='; pos += 1;
        output[pos] = b'='; pos += 1;
    } else if remaining == 2 && pos + 4 <= output.len() {
        let a = input[i] as u32;
        let b = input[i + 1] as u32;
        output[pos] = B64[((a >> 2) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[(((a << 4) | (b >> 4)) & 0x3F) as usize]; pos += 1;
        output[pos] = B64[((b << 2) & 0x3F) as usize]; pos += 1;
        output[pos] = b'='; pos += 1;
    }

    pos
}

/// Base64 decode. Returns bytes written to output, or 0 on error.
pub fn base64_decode(input: &[u8], input_len: usize, output: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for i in 0..input_len {
        let ch = input[i];
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            b'\n' | b'\r' | b' ' => continue,
            _ => return 0, // invalid char
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if pos < output.len() {
                output[pos] = (buf >> bits) as u8;
                pos += 1;
            }
            buf &= (1 << bits) - 1;
        }
    }

    pos
}

/// Build a minimal EXIF APP1 segment containing ImageDescription and UserComment.
/// Returns the complete APP1 segment bytes (including FF E1 marker) written to `output`.
///
/// `description`: visible text for ImageDescription (innocent cover text)
/// `user_comment`: base64 encrypted seed data for UserComment
pub fn build_exif_app1(
    description: &[u8],
    desc_len: usize,
    user_comment: &[u8],
    comment_len: usize,
    output: &mut [u8],
) -> usize {
    if output.len() < MAX_EXIF_SIZE { return 0; }

    let mut pos = 0usize;

    // APP1 marker (will fill length later)
    output[pos] = 0xFF; pos += 1;
    output[pos] = 0xE1; pos += 1;
    let length_pos = pos;
    pos += 2; // placeholder for length

    // "Exif\0\0"
    output[pos..pos + 6].copy_from_slice(&EXIF_HEADER);
    pos += 6;

    let tiff_start = pos;

    // TIFF header: little-endian
    output[pos..pos + 2].copy_from_slice(&TIFF_LE);
    pos += 2;
    output[pos..pos + 2].copy_from_slice(&TIFF_MAGIC_LE);
    pos += 2;
    // Offset to IFD0: 8 (immediately after TIFF header)
    output[pos..pos + 4].copy_from_slice(&8u32.to_le_bytes());
    pos += 4;

    // IFD0: 2 entries (ImageDescription + UserComment)
    let ifd_start = pos;
    let num_entries: u16 = 2;
    output[pos..pos + 2].copy_from_slice(&num_entries.to_le_bytes());
    pos += 2;

    // Entry 1: ImageDescription (tag=0x010E, type=2=ASCII, count=desc_len+1)
    let desc_store_len = desc_len + 1; // include null terminator
    output[pos..pos + 2].copy_from_slice(&TAG_IMAGE_DESCRIPTION.to_le_bytes());
    pos += 2;
    output[pos..pos + 2].copy_from_slice(&2u16.to_le_bytes()); // type=ASCII
    pos += 2;
    output[pos..pos + 4].copy_from_slice(&(desc_store_len as u32).to_le_bytes());
    pos += 4;
    // Value offset (will be after IFD entries + next IFD pointer)
    let desc_data_offset = (ifd_start - tiff_start) + 2 + num_entries as usize * 12 + 4;
    output[pos..pos + 4].copy_from_slice(&(desc_data_offset as u32).to_le_bytes());
    pos += 4;

    // Entry 2: UserComment (tag=0x9286, type=7=UNDEFINED, count=8+comment_len)
    // UserComment format: 8-byte charset ID ("ASCII\0\0\0") + text
    let uc_store_len = 8 + comment_len;
    output[pos..pos + 2].copy_from_slice(&TAG_USER_COMMENT.to_le_bytes());
    pos += 2;
    output[pos..pos + 2].copy_from_slice(&7u16.to_le_bytes()); // type=UNDEFINED
    pos += 2;
    output[pos..pos + 4].copy_from_slice(&(uc_store_len as u32).to_le_bytes());
    pos += 4;
    let uc_data_offset = desc_data_offset + desc_store_len;
    output[pos..pos + 4].copy_from_slice(&(uc_data_offset as u32).to_le_bytes());
    pos += 4;

    // Next IFD pointer: 0 (no more IFDs)
    output[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
    pos += 4;

    // Data area: ImageDescription
    output[pos..pos + desc_len].copy_from_slice(&description[..desc_len]);
    pos += desc_len;
    output[pos] = 0; // null terminator
    pos += 1;

    // Data area: UserComment (charset "ASCII\0\0\0" + base64 data)
    output[pos..pos + 5].copy_from_slice(b"ASCII");
    output[pos + 5] = 0;
    output[pos + 6] = 0;
    output[pos + 7] = 0;
    pos += 8;
    output[pos..pos + comment_len].copy_from_slice(&user_comment[..comment_len]);
    pos += comment_len;

    // Fill in APP1 length (everything after the 2-byte marker)
    let app1_length = (pos - 2) as u16; // subtract FF E1
    output[length_pos] = (app1_length >> 8) as u8;
    output[length_pos + 1] = (app1_length & 0xFF) as u8;

    pos
}

/// Find the APP1 (EXIF) segment in a JPEG byte stream.
/// Returns (offset_of_app1_data, length) or None.
pub fn find_exif_app1(jpeg: &[u8], jpeg_len: usize) -> Option<(usize, usize)> {
    if jpeg_len < 4 { return None; }
    if jpeg[0] != 0xFF || jpeg[1] != 0xD8 { return None; } // not JPEG

    let mut pos = 2;
    while pos + 4 < jpeg_len {
        if jpeg[pos] != 0xFF { pos += 1; continue; }
        let marker = jpeg[pos + 1];
        let seg_len = ((jpeg[pos + 2] as usize) << 8) | jpeg[pos + 3] as usize;

        if marker == 0xE1 && pos + 10 < jpeg_len && jpeg[pos + 4..pos + 10] == EXIF_HEADER {
            return Some((pos, seg_len.checked_add(2).unwrap_or(0)));
        }

        if marker == 0xDA { break; }
        // Checked advance — prevent infinite loop on seg_len=0 or overflow
        match pos.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
            Some(next) if next > pos => pos = next,
            _ => break, // overflow or no progress = bail
        }
    }
    None
}

/// Extract UserComment value from an EXIF APP1 segment.
/// Returns the comment bytes (after 8-byte charset header) and length.
pub fn extract_user_comment(
    exif_data: &[u8],
    exif_len: usize,
    output: &mut [u8],
) -> usize {
    // Skip marker (2B) + length (2B) + "Exif\0\0" (6B) = 10 bytes to TIFF header
    if exif_len < 20 { return 0; }
    let tiff_start = 10;

    // Read byte order
    let le = exif_data[tiff_start] == 0x49; // 'I' = little-endian
    if !le { return 0; } // only support LE for now

    // IFD0 offset — use checked arithmetic to prevent wrapping
    let ifd_offset = u32::from_le_bytes([
        exif_data[tiff_start + 4], exif_data[tiff_start + 5],
        exif_data[tiff_start + 6], exif_data[tiff_start + 7],
    ]) as usize;

    let ifd_pos = match tiff_start.checked_add(ifd_offset) {
        Some(v) => v,
        None => return 0, // overflow = malicious data
    };
    if ifd_pos + 2 > exif_len { return 0; }

    let num_entries = u16::from_le_bytes([exif_data[ifd_pos], exif_data[ifd_pos + 1]]) as usize;
    // Cap entries to prevent CPU time attack (no legit EXIF has >100 entries)
    let max_entries = num_entries.min(100);

    for e in 0..max_entries {
        let entry_pos = match ifd_pos.checked_add(2 + e * 12) {
            Some(v) => v,
            None => break,
        };
        if entry_pos + 12 > exif_len { break; }

        let tag = u16::from_le_bytes([exif_data[entry_pos], exif_data[entry_pos + 1]]);
        let count = u32::from_le_bytes([
            exif_data[entry_pos + 4], exif_data[entry_pos + 5],
            exif_data[entry_pos + 6], exif_data[entry_pos + 7],
        ]) as usize;
        let value_offset = u32::from_le_bytes([
            exif_data[entry_pos + 8], exif_data[entry_pos + 9],
            exif_data[entry_pos + 10], exif_data[entry_pos + 11],
        ]) as usize;

        if tag == TAG_USER_COMMENT && count > 8 {
            // Checked arithmetic for all offset calculations
            let data_pos = match tiff_start.checked_add(value_offset)
                .and_then(|v| v.checked_add(8)) {
                Some(v) => v,
                None => continue, // overflow = skip this entry
            };
            let data_len = count - 8;
            let copy_len = data_len.min(output.len());
            if data_pos.checked_add(copy_len).is_some_and(|end| end <= exif_len) {
                output[..copy_len].copy_from_slice(&exif_data[data_pos..data_pos + copy_len]);
                return copy_len;
            }
        }
    }

    0
}
/// Inject an EXIF APP1 segment into a JPEG file.
/// If the JPEG already has APP1, replaces it. Otherwise inserts after SOI.
///
/// `jpeg_in`: original JPEG data
/// `jpeg_len`: length of original JPEG
/// `app1`: the new APP1 segment (from build_exif_app1)
/// `app1_len`: length of new APP1
/// `jpeg_out`: output buffer (must be >= jpeg_len + app1_len)
///
/// Returns total output JPEG length.
pub fn inject_exif_into_jpeg(
    jpeg_in: &[u8],
    jpeg_len: usize,
    app1: &[u8],
    app1_len: usize,
    jpeg_out: &mut [u8],
) -> usize {
    if jpeg_len < 2 || jpeg_out.len() < jpeg_len.saturating_add(app1_len) { return 0; }

    // Copy SOI
    jpeg_out[0] = 0xFF;
    jpeg_out[1] = 0xD8;
    let mut out_pos = 2usize;

    // Insert new APP1
    jpeg_out[out_pos..out_pos + app1_len].copy_from_slice(&app1[..app1_len]);
    out_pos += app1_len;

    // Copy rest of JPEG, skipping any existing APP1
    let mut in_pos = 2;
    while in_pos + 3 < jpeg_len {
        if jpeg_in[in_pos] == 0xFF && jpeg_in[in_pos + 1] == 0xE1 {
            let seg_len = ((jpeg_in[in_pos + 2] as usize) << 8) | jpeg_in[in_pos + 3] as usize;
            match in_pos.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
                Some(next) if next > in_pos => in_pos = next,
                _ => break,
            }
            continue;
        }
        break; // reached non-APP1 segment, copy the rest
    }

    // Copy remaining JPEG data
    let remaining = jpeg_len - in_pos;
    jpeg_out[out_pos..out_pos + remaining].copy_from_slice(&jpeg_in[in_pos..jpeg_len]);
    out_pos += remaining;

    out_pos
}
