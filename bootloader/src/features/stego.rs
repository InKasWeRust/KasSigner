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
//   ImageDescription = the password (documented design, see docs/STEGANOGRAPHY.md)
//   UserComment      = embedded blob v2: raw seed container [|| raw hint container]
//
// Encryption: AES-256-GCM with PBKDF2-derived key (100K iterations).
// Recovery hint is encrypted separately with the descriptor as password.
//
// ─── Embedded blob format v2 (D-01) ─────────────────────────────────
//
// v1 stored base64(container). Every artifact therefore began with the
// ASCII "S0FT", because the shared v3 container magic KAS\x04 sits at
// offset 0 and base64-encodes to S0FTB (KAS\x01 on pre-v3 artifacts gave
// S0FTA; both share the first four characters). `grep -rl S0FT` over a
// photo dump located the needle in a 200-file haystack with zero false
// positives. That is not statistical analysis, it is a string match, and
// it ended Layer 1 on its own.
//
// v2 removes the constant prefix instead of changing the container. The
// container is SHARED with SD-card backups (hw/sd_backup.rs), where a
// magic is correct and wanted; only the stego layer needs it gone. So the
// stego layer strips the seven bytes that are identical in every artifact
// (magic 4, version 1, purpose 1, kdf_id 1) on the way in, and rebuilds
// them from constants on the way out. The bytes that remain begin with the
// container's own payload-length byte, followed by the per-file TRNG salt:
// high-entropy from byte 1 onward, no fixed string anywhere.
//
//   embedded = [len:1][salt:16][nonce:12][ciphertext:len][tag:16]
//
// Seed and hint blobs concatenate with NO separator. The leading length
// byte delimits them, which is why v1's '|' is gone: with raw bytes a
// literal '|' can occur inside ciphertext, and a separator scan would
// split the payload at the wrong place.
//
// Stored raw, not base64: UserComment is EXIF type 7 (UNDEFINED), so
// binary is legal, and the charset field is set to UNDEFINED (eight zero
// bytes) rather than "ASCII", which is both correct and less anomalous.
//
// KDF NOTE, must be read before M-02 is picked up: the rebuild writes
// `kdf_id = KDF_PBKDF2_SHA256_100K`, a compile-time constant. The moment a
// memory-hard KDF ships as `kdf_id = 2`, this format needs a revision to
// carry the value, or v2 artifacts made with the new KDF will rebuild to
// the wrong header, fail AAD, and be unreadable.
//
// Legacy artifacts stay importable forever. The discriminator is exact and
// needs no key derivation: v1 payloads begin with the ASCII "S0FT", v2
// payloads begin with a small binary length byte.

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

/// Available steganography modes.
///
/// The two carriers fail on OPPOSITE operations, which is the whole reason
/// both exist and the only thing that should drive the user's choice:
///
///   Descriptor  payload in EXIF metadata. Survives recompression; destroyed
///               the moment anything strips metadata, which every messaging
///               app and most social platforms do as a matter of course.
///   Picture     payload in the image's own quantized DCT coefficients.
///               Ignores metadata stripping entirely; destroyed by
///               recompression.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StegoMode {
    /// JPEG EXIF metadata.
    JpegExif,
    /// JPEG DCT coefficients. Named "Picture" for the user, but note it does
    /// NOT alter pixels and never runs an IDCT: it edits the compressed
    /// coefficients directly. Pixel-domain LSB was measured and rejected —
    /// it does not survive being saved as a JPEG at all.
    JpegPicture,
}

impl StegoMode {
pub fn label(&self) -> &'static str {
    match self {
        StegoMode::JpegExif => "Descriptor",
        StegoMode::JpegPicture => "Picture",
    }
}
pub fn description(&self) -> &'static str {
    match self {
        StegoMode::JpegExif => "In the photo's metadata",
        StegoMode::JpegPicture => "In the photo itself",
    }
}
/// The tradeoff, shown under the label so the choice is informed.
pub fn tradeoff(&self) -> &'static str {
    match self {
        StegoMode::JpegExif => "Lost if metadata is stripped",
        StegoMode::JpegPicture => "Lost if photo is re-saved",
    }
}
}

pub const ALL_MODES: [StegoMode; 2] = [
    StegoMode::JpegExif,
    StegoMode::JpegPicture,
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

    // Data area: UserComment. Charset field = UNDEFINED (eight zero bytes),
    // not "ASCII": the payload is raw binary under blob format v2. EXIF type
    // 7 permits this and it is what a camera writing opaque bytes does.
    for b in output.iter_mut().skip(pos).take(8) { *b = 0; }
    pos += 8;
    output[pos..pos + comment_len].copy_from_slice(&user_comment[..comment_len]);
    pos += comment_len;

    // Fill in APP1 length (everything after the 2-byte marker)
    let app1_length = (pos - 2) as u16; // subtract FF E1
    output[length_pos] = (app1_length >> 8) as u8;
    output[length_pos + 1] = (app1_length & 0xFF) as u8;

    pos
}

// ─── Embedded blob v2: container prefix strip / rebuild (D-01) ──────

/// Bytes at the head of a v3 container that are identical in every stego
/// artifact: magic(4) + version(1) + purpose(1) + kdf_id(1). Byte 7 (the
/// payload length) is NOT included: it varies with word count and it is what
/// delimits concatenated blobs.
pub const V3_CONST_PREFIX_LEN: usize = 7;

/// Strip the constant prefix from a v3 container for embedding.
/// Returns bytes written to `out`, or 0 if the input is too short or `out`
/// is too small.
pub fn strip_v3_prefix(container: &[u8], out: &mut [u8]) -> usize {
    if container.len() <= V3_CONST_PREFIX_LEN { return 0; }
    let n = container.len() - V3_CONST_PREFIX_LEN;
    if out.len() < n { return 0; }
    out[..n].copy_from_slice(&container[V3_CONST_PREFIX_LEN..]);
    n
}

/// Rebuild a full v3 container from an embedded blob.
///
/// `purpose` must be the value the blob was encrypted under
/// (`PURPOSE_SEED` for the seed, `PURPOSE_RAW` for the hint): it is
/// authenticated as part of the AAD and mixed into the key derivation, so a
/// wrong value fails to decrypt rather than returning wrong plaintext.
///
/// `kdf_id` is written as the compile-time constant. See the KDF NOTE in the
/// module header before changing the KDF.
pub fn restore_v3_prefix(blob: &[u8], purpose: u8, out: &mut [u8]) -> usize {
    use crate::hw::sd_backup;
    if blob.is_empty() { return 0; }
    let n = blob.len() + V3_CONST_PREFIX_LEN;
    if out.len() < n { return 0; }
    out[0..4].copy_from_slice(&sd_backup::V3_MAGIC);
    out[4] = sd_backup::V3_VERSION;
    out[5] = purpose;
    out[6] = sd_backup::KDF_PBKDF2_SHA256_100K;
    out[V3_CONST_PREFIX_LEN..n].copy_from_slice(blob);
    n
}

/// Total length of the embedded blob starting at `blob[0]`, read from its
/// own leading payload-length byte. This is what separates the seed blob
/// from the hint blob in a concatenated payload. Returns 0 if the slice is
/// empty or the declared length is zero.
pub fn embedded_blob_len(blob: &[u8]) -> usize {
    use crate::hw::sd_backup;
    if blob.is_empty() { return 0; }
    let payload_len = blob[0] as usize;
    if payload_len == 0 || payload_len > sd_backup::MAX_V3_PAYLOAD { return 0; }
    sd_backup::V3_OVERHEAD - V3_CONST_PREFIX_LEN + payload_len
}

/// True if a UserComment payload is a v1 (base64) artifact rather than v2.
///
/// Every v1 artifact begins with the ASCII "S0FT": base64 of the container
/// magic KAS\x04 (or KAS\x01 pre-v3). v2 payloads begin with a binary
/// length byte. The test costs nothing and never touches a key.
pub fn is_legacy_b64_payload(payload: &[u8]) -> bool {
    payload.len() >= 4 && &payload[..4] == b"S0FT"
}

// ─── Byte-order-aware TIFF reading (D-01, fingerprint 2) ────────────
//
// EXIF may be little-endian ("II") or big-endian ("MM"). Both are common in
// the field: several major camera vendors write MM, and so does PIL. The
// codec used to build only II and read only II, which was self-consistent
// while it also discarded the host photo's EXIF. Copy-forward inherits the
// host's byte order, so both orders must now be read AND written.

/// TIFF byte order of an APP1 segment: `true` = little-endian.
/// `None` if the segment is not a readable EXIF APP1.
fn tiff_order(app1: &[u8], app1_len: usize) -> Option<bool> {
    if app1_len < 20 { return None; }
    if app1[0] != 0xFF || app1[1] != 0xE1 { return None; }
    if app1[4..10] != EXIF_HEADER { return None; }
    match (app1[10], app1[11]) {
        (0x49, 0x49) => Some(true),
        (0x4D, 0x4D) => Some(false),
        _ => None,
    }
}

#[inline]
fn rd_u16(b: &[u8], le: bool) -> u16 {
    if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) }
}

#[inline]
fn rd_u32(b: &[u8], le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

#[inline]
fn wr_u16(out: &mut [u8], v: u16, le: bool) {
    let b = if le { v.to_le_bytes() } else { v.to_be_bytes() };
    out[..2].copy_from_slice(&b);
}

#[inline]
fn wr_u32(out: &mut [u8], v: u32, le: bool) {
    let b = if le { v.to_le_bytes() } else { v.to_be_bytes() };
    out[..4].copy_from_slice(&b);
}

/// Build an APP1 that carries the HOST PHOTO'S OWN EXIF plus our two tags.
///
/// This closes fingerprint 2 (D-01): a two-entry IFD0 containing only
/// ImageDescription and UserComment. No camera produces that. Real
/// photographs carry fifteen to forty IFD0 tags plus an Exif sub-IFD, so an
/// artifact built by `build_exif_app1` was identifiable by entry count alone,
/// with no statistics and no key material, and it silently stripped the
/// photo's Make, Model and DateTime in the process — a Canon JPEG that has
/// lost its Make tag is visible to the owner, never mind an analyst.
///
/// METHOD: nothing is ever moved.
///
/// The naive approach is to insert our entries into the host's IFD0 array,
/// which shifts every byte after it and invalidates every value offset in
/// the file, including the Exif sub-IFD pointer, the GPS IFD, and the
/// thumbnail offsets in IFD1 — a recursive TIFF rewriter, and a bug in it
/// corrupts the user's photo.
///
/// Instead the host's whole TIFF block is copied VERBATIM, so every existing
/// offset remains correct by construction, and a NEW IFD0 entry array is
/// appended at the end which re-lists the host's original entries (their
/// value offsets still point at the untouched data) followed by ours. The
/// TIFF header is then repointed at the new array. The host's original entry
/// array is left in place, orphaned and unreferenced: a few dead bytes that
/// no parser reads and no fingerprint sees.
///
/// Entries are emitted in ascending tag order, as TIFF requires.
///
/// Returns 0 if the host has no usable EXIF, uses an unknown byte order, or
/// the result would not fit. The caller MUST fall back to `build_exif_app1`
/// and must verify the result before writing (see `handlers/stego.rs`).
pub fn build_exif_app1_copyforward(
    host_app1: &[u8],
    host_len: usize,
    description: &[u8],
    user_comment: &[u8],
    output: &mut [u8],
) -> usize {
    let le = match tiff_order(host_app1, host_len) { Some(v) => v, None => return 0 };

    let tiff = &host_app1[10..host_len];
    let tiff_len = tiff.len();
    if tiff_len < 8 { return 0; }

    let ifd0 = rd_u32(&tiff[4..8], le) as usize;
    if ifd0.checked_add(2).map_or(true, |v| v > tiff_len) { return 0; }
    let n = rd_u16(&tiff[ifd0..ifd0 + 2], le) as usize;
    // A real IFD0 is well under 200 entries; anything more is malformed.
    if n > 200 { return 0; }
    let arr_end = match ifd0.checked_add(2).and_then(|v| v.checked_add(n * 12)) {
        Some(v) if v + 4 <= tiff_len => v,
        _ => return 0,
    };

    // Count host entries we keep: everything except the two we supply.
    let mut kept = 0usize;
    for e in 0..n {
        let p = ifd0 + 2 + e * 12;
        let tag = rd_u16(&tiff[p..p + 2], le);
        if tag != TAG_IMAGE_DESCRIPTION && tag != TAG_USER_COMMENT { kept += 1; }
    }
    let total = kept + 2;

    // Lay out the new segment.
    if output.len() < 10 { return 0; }
    output[0] = 0xFF; output[1] = 0xE1;
    let length_pos = 2;
    // Marker (2) + length placeholder (2); the length is filled in at the end.
    let mut pos = 4usize;
    output[pos..pos + 6].copy_from_slice(&EXIF_HEADER);
    pos += 6;
    let tiff_out = pos;

    // Host TIFF block, verbatim.
    if pos + tiff_len > output.len() { return 0; }
    output[pos..pos + tiff_len].copy_from_slice(tiff);
    pos += tiff_len;
    // TIFF offsets are even-aligned by convention; keep it that way.
    if (pos - tiff_out) % 2 == 1 {
        if pos >= output.len() { return 0; }
        output[pos] = 0;
        pos += 1;
    }

    let new_ifd0 = pos - tiff_out; // TIFF-relative
    let desc_store = description.len() + 1;      // + NUL
    let uc_store = 8 + user_comment.len();       // + charset field
    let data_off = new_ifd0 + 2 + total * 12 + 4;
    let desc_off = data_off;
    let uc_off = data_off + desc_store;

    let need = tiff_out + data_off + desc_store + uc_store;
    if need > output.len() { return 0; }

    wr_u16(&mut output[pos..], total as u16, le);
    pos += 2;

    // Merge host entries with ours, ascending by tag.
    let mut hi = 0usize;          // host entry cursor
    let mut wrote_desc = false;
    let mut wrote_uc = false;
    for _ in 0..total {
        // Next host tag we intend to keep.
        let mut host_tag = 0xFFFFu16;
        let mut host_p = 0usize;
        let mut scan = hi;
        while scan < n {
            let p = ifd0 + 2 + scan * 12;
            let t = rd_u16(&tiff[p..p + 2], le);
            if t != TAG_IMAGE_DESCRIPTION && t != TAG_USER_COMMENT {
                host_tag = t; host_p = p; break;
            }
            scan += 1;
        }
        let cand_desc = if wrote_desc { 0xFFFFu16 } else { TAG_IMAGE_DESCRIPTION };
        let cand_uc = if wrote_uc { 0xFFFFu16 } else { TAG_USER_COMMENT };

        if cand_desc <= host_tag && cand_desc <= cand_uc {
            wr_u16(&mut output[pos..], TAG_IMAGE_DESCRIPTION, le);
            wr_u16(&mut output[pos + 2..], 2, le);              // ASCII
            wr_u32(&mut output[pos + 4..], desc_store as u32, le);
            if desc_store <= 4 {
                // Short values live inline in the entry, not at an offset.
                output[pos + 8..pos + 12].copy_from_slice(&[0u8; 4]);
                output[pos + 8..pos + 8 + description.len()].copy_from_slice(description);
            } else {
                wr_u32(&mut output[pos + 8..], desc_off as u32, le);
            }
            pos += 12;
            wrote_desc = true;
        } else if cand_uc <= host_tag {
            wr_u16(&mut output[pos..], TAG_USER_COMMENT, le);
            wr_u16(&mut output[pos + 2..], 7, le);              // UNDEFINED
            wr_u32(&mut output[pos + 4..], uc_store as u32, le);
            wr_u32(&mut output[pos + 8..], uc_off as u32, le);
            pos += 12;
            wrote_uc = true;
        } else {
            // Host entry copied byte for byte: its value offset still points
            // into the verbatim block, so it stays correct.
            output[pos..pos + 12].copy_from_slice(&tiff[host_p..host_p + 12]);
            pos += 12;
            hi = (host_p - ifd0 - 2) / 12 + 1;
        }
    }

    // Next-IFD pointer, copied from the host so IFD1 (thumbnail) survives.
    output[pos..pos + 4].copy_from_slice(&tiff[arr_end..arr_end + 4]);
    pos += 4;

    // Data area.
    if desc_store > 4 {
        output[pos..pos + description.len()].copy_from_slice(description);
        pos += description.len();
        output[pos] = 0;
        pos += 1;
    } else {
        // Value went inline; still reserve the slot the offsets assumed.
        for b in output.iter_mut().skip(pos).take(desc_store) { *b = 0; }
        pos += desc_store;
    }
    for b in output.iter_mut().skip(pos).take(8) { *b = 0; }   // UNDEFINED charset
    pos += 8;
    output[pos..pos + user_comment.len()].copy_from_slice(user_comment);
    pos += user_comment.len();

    // Repoint the TIFF header at the new IFD0.
    wr_u32(&mut output[tiff_out + 4..], new_ifd0 as u32, le);

    // APP1 length covers everything after the 2-byte marker and must fit u16.
    let app1_length = pos - 2;
    if app1_length > 0xFFFF { return 0; }
    output[length_pos] = (app1_length >> 8) as u8;
    output[length_pos + 1] = (app1_length & 0xFF) as u8;

    pos
}

// ─── Template EXIF for cover photos that carry none (D-01) ──────────
//
// Screenshots, anything through a messaging app, most social downloads and
// many editor exports have no EXIF at all, and they are common on an SD
// card. For those the copy-forward builder has nothing to carry forward and
// falls back, which used to mean a two-entry IFD0 — the most identifying
// single feature in Kee/Johnson/Farid's 1.3M-image study, where EXIF count
// ranked above image dimensions and quantization tables for distinctiveness.
//
// WHAT THIS DELIBERATELY DOES NOT DO: claim a camera. That same study builds
// its signature JOINTLY from EXIF, quantization tables, Huffman codes and
// thumbnails, and finds 99% of signatures unique to a single manufacturer.
// Writing "Canon EOS 6D" onto a file whose quantization tables came from a
// messaging app produces a combination matching no camera in a 773-camera
// corpus, which is a cleaner detection than the small EXIF block it replaced.
// So there is no Make and no Model here.
//
// WHAT IT CLAIMS INSTEAD is what the file almost certainly is: something a
// piece of software wrote. `Software` is a far safer field to populate than
// `Make`, because re-encoding chains are ordinary — a file routinely carries
// the name of one tool while its quantization tables came from the next one
// downstream — so a mismatch there is unremarkable rather than anomalous.
//
// Every varying value is drawn per export, so two artifacts never share a
// constant: the caller picks `software` from `SOFTWARE_TABLE` by TRNG and
// supplies a TRNG-derived `datetime`. Dimensions come from the file's own
// SOF marker, so they always agree with the image.
//
// The Exif sub-IFD is real, not decorative: IFD0 tags with no sub-IFD is
// itself an anomaly no ordinary pipeline produces.

/// Plausible `Software` values, drawn per export.
///
/// Deliberately generic re-encoders rather than anything with a distinctive
/// header signature of its own. A fixed string here would be the one
/// remaining constant across every artifact a user creates, which is the
/// exact defect class this whole change set exists to remove.
pub const SOFTWARE_TABLE: [&str; 8] = [
    "GIMP 2.10.34",
    "ImageMagick 6.9.12",
    "Paint.NET 5.0.13",
    "IrfanView 4.62",
    "XnView MP 1.4.2",
    "Photos 1.0",
    "Image Editor 2.4",
    "PhotoScape X 4.2",
];

/// Read image dimensions from the JPEG's own SOF marker.
///
/// Returns `(width, height)`. Used so `PixelXDimension`/`PixelYDimension` in
/// the synthesized Exif sub-IFD agree with the actual image, which is a
/// consistency an examiner can and does check.
pub fn jpeg_dimensions(jpeg: &[u8], jpeg_len: usize) -> Option<(u16, u16)> {
    if jpeg_len < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8 { return None; }
    let mut pos = 2usize;
    while pos + 9 < jpeg_len {
        if jpeg[pos] != 0xFF { pos += 1; continue; }
        let marker = jpeg[pos + 1];
        // SOF0..SOF15 carry the frame header. C4 (DHT), C8 (JPG) and CC (DAC)
        // share the range but are not frame headers.
        if (0xC0..=0xCF).contains(&marker)
            && marker != 0xC4 && marker != 0xC8 && marker != 0xCC
        {
            let h = u16::from_be_bytes([jpeg[pos + 5], jpeg[pos + 6]]);
            let w = u16::from_be_bytes([jpeg[pos + 7], jpeg[pos + 8]]);
            if w == 0 || h == 0 { return None; }
            return Some((w, h));
        }
        if marker == 0xDA { break; }
        let seg_len = ((jpeg[pos + 2] as usize) << 8) | jpeg[pos + 3] as usize;
        match pos.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
            Some(next) if next > pos => pos = next,
            _ => break,
        }
    }
    None
}

/// Format an EXIF `DateTime` ("YYYY:MM:DD HH:MM:SS", 19 bytes) from random
/// bytes, inside a plausible window.
///
/// The device has no trusted wall clock, and the FAT32 directory timestamp
/// would be a better source (it would agree with the filesystem); plumbing it
/// through both board SD drivers is deferred. Randomised is still correct on
/// the property that matters here: it differs per export.
pub fn format_exif_datetime(rnd: &[u8], out: &mut [u8; 19]) {
    let b = |i: usize| -> u32 { if i < rnd.len() { rnd[i] as u32 } else { 0 } };
    let year = 2019 + (b(0) % 7);           // 2019..2025
    let month = 1 + (b(1) % 12);
    let day = 1 + (b(2) % 28);              // valid in every month
    let hour = 6 + (b(3) % 17);             // 06..22, daylight-ish
    let min = b(4) % 60;
    let sec = b(5) % 60;
    let d2 = |v: u32, o: &mut [u8]| {
        o[0] = b'0' + ((v / 10) % 10) as u8;
        o[1] = b'0' + (v % 10) as u8;
    };
    out[0] = b'0' + ((year / 1000) % 10) as u8;
    out[1] = b'0' + ((year / 100) % 10) as u8;
    out[2] = b'0' + ((year / 10) % 10) as u8;
    out[3] = b'0' + (year % 10) as u8;
    out[4] = b':';
    d2(month, &mut out[5..7]);
    out[7] = b':';
    d2(day, &mut out[8..10]);
    out[10] = b' ';
    d2(hour, &mut out[11..13]);
    out[13] = b':';
    d2(min, &mut out[14..16]);
    out[16] = b':';
    d2(sec, &mut out[17..19]);
}

/// Build a software-export-shaped EXIF APP1 for a cover photo with none.
///
/// IFD0: ImageDescription, Orientation, XResolution, YResolution,
/// ResolutionUnit, Software, DateTime, ExifIFD pointer, UserComment.
/// Exif sub-IFD: ExifVersion, FlashpixVersion, ColorSpace, PixelXDimension,
/// PixelYDimension.
///
/// Little-endian: this block is ours, so the byte order is a free choice.
pub fn build_exif_app1_template(
    description: &[u8],
    user_comment: &[u8],
    width: u16,
    height: u16,
    software: &[u8],
    datetime: &[u8; 19],
    output: &mut [u8],
) -> usize {
    const LE: bool = true;
    let desc_store = description.len() + 1;
    let sw_store = software.len() + 1;
    let uc_store = 8 + user_comment.len();
    let desc_ext = if desc_store > 4 { desc_store } else { 0 };

    let n0 = 9usize;
    let n1 = 5usize;
    let ifd0_off = 8usize;
    let data_off = ifd0_off + 2 + n0 * 12 + 4;
    let data_len = desc_ext + 8 + 8 + sw_store + 20 + uc_store;
    let mut exif_ifd_off = data_off + data_len;
    if exif_ifd_off % 2 == 1 { exif_ifd_off += 1; }
    let tiff_len = exif_ifd_off + 2 + n1 * 12 + 4;
    let total = 4 + 6 + tiff_len;
    if output.len() < total { return 0; }
    if tiff_len + 6 + 2 > 0xFFFF { return 0; }

    for b in output.iter_mut().take(total) { *b = 0; }

    output[0] = 0xFF; output[1] = 0xE1;
    output[4..10].copy_from_slice(&EXIF_HEADER);
    let t = 10usize; // TIFF base

    output[t..t + 2].copy_from_slice(&TIFF_LE);
    output[t + 2..t + 4].copy_from_slice(&TIFF_MAGIC_LE);
    wr_u32(&mut output[t + 4..], ifd0_off as u32, LE);

    // Data-area cursor, assigning offsets in write order.
    let mut dp = data_off;
    let desc_o = if desc_ext > 0 { let o = dp; dp += desc_store; o } else { 0 };
    let xres_o = dp; dp += 8;
    let yres_o = dp; dp += 8;
    let sw_o = dp; dp += sw_store;
    let dt_o = dp; dp += 20;
    let uc_o = dp;

    // ── IFD0, ascending tag order ──
    let mut p = t + ifd0_off;
    wr_u16(&mut output[p..], n0 as u16, LE); p += 2;
    let ent = |out: &mut [u8], p: &mut usize, tag: u16, typ: u16, count: u32, val: u32| {
        wr_u16(&mut out[*p..], tag, LE);
        wr_u16(&mut out[*p + 2..], typ, LE);
        wr_u32(&mut out[*p + 4..], count, LE);
        wr_u32(&mut out[*p + 8..], val, LE);
        *p += 12;
    };
    if desc_ext > 0 {
        ent(output, &mut p, TAG_IMAGE_DESCRIPTION, 2, desc_store as u32, desc_o as u32);
    } else {
        wr_u16(&mut output[p..], TAG_IMAGE_DESCRIPTION, LE);
        wr_u16(&mut output[p + 2..], 2, LE);
        wr_u32(&mut output[p + 4..], desc_store as u32, LE);
        output[p + 8..p + 8 + description.len()].copy_from_slice(description);
        p += 12;
    }
    ent(output, &mut p, 0x0112, 3, 1, 1);                 // Orientation = normal
    ent(output, &mut p, 0x011A, 5, 1, xres_o as u32);     // XResolution
    ent(output, &mut p, 0x011B, 5, 1, yres_o as u32);     // YResolution
    ent(output, &mut p, 0x0128, 3, 1, 2);                 // ResolutionUnit = inch
    ent(output, &mut p, 0x0131, 2, sw_store as u32, sw_o as u32);
    ent(output, &mut p, 0x0132, 2, 20, dt_o as u32);
    ent(output, &mut p, 0x8769, 4, 1, exif_ifd_off as u32);
    ent(output, &mut p, TAG_USER_COMMENT, 7, uc_store as u32, uc_o as u32);
    wr_u32(&mut output[p..], 0, LE); // no IFD1

    // ── IFD0 data area ──
    if desc_ext > 0 {
        let o = t + desc_o;
        output[o..o + description.len()].copy_from_slice(description);
    }
    let o = t + xres_o;
    wr_u32(&mut output[o..], 72, LE);
    wr_u32(&mut output[o + 4..], 1, LE);
    let o = t + yres_o;
    wr_u32(&mut output[o..], 72, LE);
    wr_u32(&mut output[o + 4..], 1, LE);
    let o = t + sw_o;
    output[o..o + software.len()].copy_from_slice(software);
    let o = t + dt_o;
    output[o..o + 19].copy_from_slice(datetime);
    let o = t + uc_o + 8; // charset field already zeroed = UNDEFINED
    output[o..o + user_comment.len()].copy_from_slice(user_comment);

    // ── Exif sub-IFD (all values inline) ──
    let mut p = t + exif_ifd_off;
    wr_u16(&mut output[p..], n1 as u16, LE); p += 2;
    wr_u16(&mut output[p..], 0x9000, LE);
    wr_u16(&mut output[p + 2..], 7, LE);
    wr_u32(&mut output[p + 4..], 4, LE);
    output[p + 8..p + 12].copy_from_slice(b"0232");
    p += 12;
    wr_u16(&mut output[p..], 0xA000, LE);
    wr_u16(&mut output[p + 2..], 7, LE);
    wr_u32(&mut output[p + 4..], 4, LE);
    output[p + 8..p + 12].copy_from_slice(b"0100");
    p += 12;
    ent(output, &mut p, 0xA001, 3, 1, 1);                 // ColorSpace = sRGB
    ent(output, &mut p, 0xA002, 4, 1, width as u32);
    ent(output, &mut p, 0xA003, 4, 1, height as u32);
    wr_u32(&mut output[p..], 0, LE);

    let app1_length = total - 2;
    output[2] = (app1_length >> 8) as u8;
    output[3] = (app1_length & 0xFF) as u8;
    total
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

    // Byte order. BOTH are now supported: this used to bail on anything that
    // was not "II", which was self-consistent only while the codec also threw
    // the host photo's EXIF away and built its own little-endian block. With
    // copy-forward the segment inherits the host's byte order, and plenty of
    // real cameras write big-endian, so a big-endian artifact would otherwise
    // export fine and then refuse to import.
    let le = match (exif_data[tiff_start], exif_data[tiff_start + 1]) {
        (0x49, 0x49) => true,
        (0x4D, 0x4D) => false,
        _ => return 0,
    };

    // IFD0 offset — use checked arithmetic to prevent wrapping
    let ifd_offset = rd_u32(&exif_data[tiff_start + 4..tiff_start + 8], le) as usize;

    let ifd_pos = match tiff_start.checked_add(ifd_offset) {
        Some(v) => v,
        None => return 0, // overflow = malicious data
    };
    if ifd_pos + 2 > exif_len { return 0; }

    let num_entries = rd_u16(&exif_data[ifd_pos..ifd_pos + 2], le) as usize;
    // Cap entries to prevent CPU time attack (no legit EXIF has >100 entries)
    let max_entries = num_entries.min(100);

    for e in 0..max_entries {
        let entry_pos = match ifd_pos.checked_add(2 + e * 12) {
            Some(v) => v,
            None => break,
        };
        if entry_pos + 12 > exif_len { break; }

        let tag = rd_u16(&exif_data[entry_pos..entry_pos + 2], le);
        let count = rd_u32(&exif_data[entry_pos + 4..entry_pos + 8], le) as usize;
        let value_offset = rd_u32(&exif_data[entry_pos + 8..entry_pos + 12], le) as usize;

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
    let mut in_pos = 2usize;

    // ── Phase 1: copy leading APP0/JFIF segments BEFORE our APP1 (D-01) ──
    //
    // This used to write the new APP1 immediately after SOI unconditionally,
    // pushing the host photo's APP0 behind it. Cameras and standard encoders
    // write APP0 first, so APP1-before-APP0 was an ordering anomaly that
    // identified the artifact on its own, with no statistics needed.
    while in_pos + 3 < jpeg_len
        && jpeg_in[in_pos] == 0xFF
        && jpeg_in[in_pos + 1] == 0xE0
    {
        let seg_len = ((jpeg_in[in_pos + 2] as usize) << 8) | jpeg_in[in_pos + 3] as usize;
        let end = match in_pos.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
            Some(e) if e > in_pos && e <= jpeg_len => e,
            _ => break,
        };
        if out_pos + (end - in_pos) > jpeg_out.len() { return 0; }
        jpeg_out[out_pos..out_pos + (end - in_pos)].copy_from_slice(&jpeg_in[in_pos..end]);
        out_pos += end - in_pos;
        in_pos = end;
    }

    // ── Phase 2: our APP1, now correctly positioned after APP0 ──
    if out_pos + app1_len > jpeg_out.len() { return 0; }
    jpeg_out[out_pos..out_pos + app1_len].copy_from_slice(&app1[..app1_len]);
    out_pos += app1_len;

    // ── Phase 3: copy the rest, dropping EVERY pre-SOS APP1 (L-02) ──
    //
    // The old loop stopped at the first non-APP1 segment, so it only ever
    // stripped a stale APP1 that sat immediately after SOI. A host photo with
    // APP0 first kept its original APP1 further down the file, which meant a
    // re-export left the PREVIOUS encrypted seed in the output alongside the
    // new one, and produced a two-APP1 file that no camera writes. Both the
    // retention and the fingerprint are closed by scanning to SOS.
    while in_pos + 3 < jpeg_len {
        if jpeg_in[in_pos] != 0xFF { break; }
        let marker = jpeg_in[in_pos + 1];
        // SOS: entropy-coded data follows, which is not segment-structured.
        // Stop parsing and copy the remainder verbatim.
        if marker == 0xDA { break; }
        let seg_len = ((jpeg_in[in_pos + 2] as usize) << 8) | jpeg_in[in_pos + 3] as usize;
        let end = match in_pos.checked_add(2).and_then(|v| v.checked_add(seg_len)) {
            Some(e) if e > in_pos && e <= jpeg_len => e,
            _ => break,
        };
        if marker == 0xE1 {
            in_pos = end; // stale EXIF: drop it
            continue;
        }
        if out_pos + (end - in_pos) > jpeg_out.len() { return 0; }
        jpeg_out[out_pos..out_pos + (end - in_pos)].copy_from_slice(&jpeg_in[in_pos..end]);
        out_pos += end - in_pos;
        in_pos = end;
    }

    // Copy remaining JPEG data (SOS onward, or whatever is left)
    let remaining = jpeg_len - in_pos;
    if out_pos + remaining > jpeg_out.len() { return 0; }
    jpeg_out[out_pos..out_pos + remaining].copy_from_slice(&jpeg_in[in_pos..jpeg_len]);
    out_pos += remaining;

    out_pos
}
