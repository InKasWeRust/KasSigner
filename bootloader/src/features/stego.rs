// features/stego.rs — Steganography codec (JPEG EXIF)

// KasSigner — Steganography Mode 4: Zero-Width Text Steganography
// 100% Rust, no-std, no-alloc
//
// Hides encrypted seed data as invisible Unicode characters between
// visible text characters. The result looks like an innocent message
// but contains the full encrypted seed payload.
//
// Encoding: 2 bits per zero-width character
//   U+200B (zero-width space)         = 00
//   U+200C (zero-width non-joiner)    = 01
//   U+200D (zero-width joiner)        = 10
//   U+FEFF (zero-width no-break space) = 11
//
// Flow (encode):
//   1. Encrypt CompactSeedQR payload (16 or 32 bytes) with AES-256-CBC
//   2. Prepend salt (16B) + iv (16B) = total 48 or 64 bytes
//   3. Encode as zero-width chars (4 chars per byte = 192 or 256 chars)
//   4. Interleave between visible template text characters
//   5. Display combined string as QR code
//
// Flow (decode):
//   1. Scan QR containing the stego text
//   2. Extract zero-width chars from between visible characters
//   3. Decode 2-bit pairs back to bytes
//   4. Split into salt + iv + ciphertext
//   5. Derive AES key from passphrase + salt
//   6. Decrypt → validate BIP39 checksum

/// Zero-width character encodings (UTF-8 byte sequences)
/// U+200B = E2 80 8B (zero-width space)
/// U+200C = E2 80 8C (zero-width non-joiner)
/// U+200D = E2 80 8D (zero-width joiner)
/// U+FEFF = EF BB BF (zero-width no-break space / BOM)
const ZW_00: [u8; 3] = [0xE2, 0x80, 0x8B]; // U+200B
const ZW_01: [u8; 3] = [0xE2, 0x80, 0x8C]; // U+200C
const ZW_10: [u8; 3] = [0xE2, 0x80, 0x8D]; // U+200D
const ZW_11: [u8; 3] = [0xEF, 0xBB, 0xBF]; // U+FEFF

/// Maximum payload: 64 bytes (24-word seed: salt 16 + iv 16 + ciphertext 32)
pub const MAX_STEGO_PAYLOAD: usize = 128;

/// Maximum output buffer: visible text + zero-width chars
/// 200 visible chars + 256 ZW chars * 3 bytes each = ~968 bytes
pub const MAX_STEGO_OUTPUT: usize = 1536;

/// Template messages — innocent-looking text for interleaving
/// Each must be >= 193 visible chars (to provide 192+ insertion points for 12-word seed)
/// For 24-word seed we need 257 insertion points (256 ZW chars + visible chars)
const TEMPLATES: [&str; 4] = [
    "Hey thanks so much for the amazing dinner last weekend it was really great to catch up with everyone and the paella recipe you shared was incredible I tried making it yesterday and it turned out pretty well the kids loved it too hope we can do it again soon maybe next month",
    "Just wanted to let you know that the hotel in Barcelona was absolutely wonderful the room had an amazing view of the sea and the breakfast buffet was the best we have ever had I would definitely recommend it to anyone visiting the city the staff were so friendly and helpful too",
    "The quarterly report looks good overall but I think we should review the marketing budget numbers before the board meeting next Tuesday also please send me the updated spreadsheet with the regional breakdown when you get a chance I want to double check the totals before presenting",
    "Happy birthday to the most amazing person I know wishing you all the best on your special day may this year bring you joy happiness and everything you have been dreaming of sending lots of love and warm hugs from the whole family we miss you and hope to see you very soon take care",
];

/// Encode a byte payload into zero-width characters interleaved with visible text.
/// Returns the number of bytes written to `output`, or 0 on error.
///
/// `payload`: encrypted data bytes
/// `payload_len`: actual payload length
/// `template`: visible text bytes to interleave with
/// `template_len`: length of visible text
/// `output`: buffer to write the stego text into (must be >= MAX_STEGO_OUTPUT)
pub fn encode_stego_text(
    payload: &[u8],
    payload_len: usize,
    template: &[u8],
    template_len: usize,
    output: &mut [u8],
) -> usize {
    if payload_len > MAX_STEGO_PAYLOAD || output.len() < MAX_STEGO_OUTPUT {
        return 0;
    }

    // We need payload_len * 4 zero-width chars (4 per byte, 2 bits each)
    let zw_count = payload_len * 4;

    // We need at least zw_count + 1 visible characters to interleave
    if template_len < zw_count + 1 {
        return 0;
    }

    let mut pos = 0usize;

    // Interleave: visible char, then ZW char(s), then next visible char...
    // Spread ZW chars evenly across the template
    let mut zw_idx = 0usize; // which ZW char we're inserting next

    for (i, &visible_byte) in template[..template_len].iter().enumerate() {
        // Write visible character
        if pos >= output.len() { break; }
        output[pos] = visible_byte;
        pos += 1;

        // After each visible char (except last), potentially insert ZW char(s)
        if i < template_len - 1 && zw_idx < zw_count {
            // How many ZW chars to insert here?
            // Spread evenly: remaining_zw / remaining_positions
            let remaining_positions = template_len - 1 - i;
            let remaining_zw = zw_count - zw_idx;
            let insert_count = if remaining_positions > 0 {
                (remaining_zw + remaining_positions - 1) / remaining_positions
            } else {
                remaining_zw
            };
            let insert_count = insert_count.min(remaining_zw);

            for _ in 0..insert_count {
                if zw_idx >= zw_count || pos + 3 > output.len() { break; }

                // Extract 2 bits from payload
                let byte_idx = zw_idx / 4;
                let bit_pair = (zw_idx % 4) as u8;
                let bits = (payload[byte_idx] >> (6 - bit_pair * 2)) & 0x03;

                let zw = match bits {
                    0b00 => &ZW_00,
                    0b01 => &ZW_01,
                    0b10 => &ZW_10,
                    _    => &ZW_11,
                };
                output[pos..pos + 3].copy_from_slice(zw);
                pos += 3;
                zw_idx += 1;
            }
        }
    }

    pos
}

/// Decode zero-width characters from a stego text back into payload bytes.
/// Returns the number of payload bytes extracted, or 0 on error.
///
/// `input`: the stego text (visible + zero-width chars)
/// `input_len`: length of input
/// `payload`: output buffer for extracted bytes (must be >= MAX_STEGO_PAYLOAD)
pub fn decode_stego_text(
    input: &[u8],
    input_len: usize,
    payload: &mut [u8],
) -> usize {
    if payload.len() < MAX_STEGO_PAYLOAD {
        return 0;
    }

    let mut bits_collected: usize = 0;
    let mut current_byte: u8 = 0;
    let mut byte_count: usize = 0;
    let mut i: usize = 0;

    while i < input_len {
        // Check for 3-byte zero-width character sequences
        if i + 2 < input_len {
            let b0 = input[i];
            let b1 = input[i + 1];
            let b2 = input[i + 2];

            let bits = if b0 == 0xE2 && b1 == 0x80 && b2 == 0x8B {
                Some(0b00u8) // U+200B
            } else if b0 == 0xE2 && b1 == 0x80 && b2 == 0x8C {
                Some(0b01u8) // U+200C
            } else if b0 == 0xE2 && b1 == 0x80 && b2 == 0x8D {
                Some(0b10u8) // U+200D
            } else if b0 == 0xEF && b1 == 0xBB && b2 == 0xBF {
                Some(0b11u8) // U+FEFF
            } else {
                None
            };

            if let Some(pair) = bits {
                current_byte = (current_byte << 2) | pair;
                bits_collected += 2;

                if bits_collected == 8 {
                    if byte_count < MAX_STEGO_PAYLOAD {
                        payload[byte_count] = current_byte;
                        byte_count += 1;
                    }
                    current_byte = 0;
                    bits_collected = 0;
                }

                i += 3; // consumed 3-byte ZW char
                continue;
            }
        }

        // Not a ZW char — skip visible character
        i += 1;
    }

    byte_count
}

/// Check if a byte sequence contains zero-width steganography markers.
/// Quick detection: scan for any of the 4 ZW character sequences.
pub fn contains_stego(data: &[u8], len: usize) -> bool {
    let mut i = 0;
    while i + 2 < len {
        if data[i] == 0xE2 && data[i + 1] == 0x80 &&
            (data[i + 2] == 0x8B || data[i + 2] == 0x8C || data[i + 2] == 0x8D) {
            return true;
        }
        if data[i] == 0xEF && data[i + 1] == 0xBB && data[i + 2] == 0xBF {
            return true;
        }
        i += 1;
    }
    false
}

/// Get a template message by index (for UI display)
pub fn get_template(idx: usize) -> &'static str {
    TEMPLATES[idx % TEMPLATES.len()]
}

/// Number of available templates
pub const TEMPLATE_COUNT: usize = 4;

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

/// Get a preset hint by index (0-3), or None for custom (4+)
pub fn get_hint_preset(idx: u8) -> Option<&'static str> {
    if (idx as usize) < HINT_PRESETS.len() {
        Some(HINT_PRESETS[idx as usize])
    } else {
        None
    }
}

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

pub fn needs_sd(&self) -> bool {
    true
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

        if marker == 0xE1 {
            if pos + 10 < jpeg_len && &jpeg[pos + 4..pos + 10] == &EXIF_HEADER {
                return Some((pos, seg_len.checked_add(2).unwrap_or(0)));
            }
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
            if data_pos.checked_add(copy_len).map_or(false, |end| end <= exif_len) {
                output[..copy_len].copy_from_slice(&exif_data[data_pos..data_pos + copy_len]);
                return copy_len;
            }
        }
    }

    0
}

/// Extract ImageDescription from EXIF APP1 data (raw bytes including ZW chars).
/// Returns number of bytes written to `output`.
pub fn extract_image_description(
    exif_data: &[u8],
    exif_len: usize,
    output: &mut [u8],
) -> usize {
    if exif_len < 20 { return 0; }
    let tiff_start = 10;
    let le = exif_data[tiff_start] == 0x49;
    if !le { return 0; }

    let ifd_offset = u32::from_le_bytes([
        exif_data[tiff_start + 4], exif_data[tiff_start + 5],
        exif_data[tiff_start + 6], exif_data[tiff_start + 7],
    ]) as usize;

    let ifd_pos = match tiff_start.checked_add(ifd_offset) {
        Some(v) => v,
        None => return 0,
    };
    if ifd_pos + 2 > exif_len { return 0; }

    let num_entries = u16::from_le_bytes([exif_data[ifd_pos], exif_data[ifd_pos + 1]]) as usize;
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

        if tag == TAG_IMAGE_DESCRIPTION && count > 0 {
            let data_pos = match tiff_start.checked_add(value_offset) {
                Some(v) => v,
                None => continue,
            };
            // count includes null terminator — copy without it
            let data_len = if count > 0
                && data_pos.checked_add(count).map_or(false, |end| end <= exif_len)
                && exif_data[data_pos + count - 1] == 0 { count - 1 } else { count };
            let copy_len = data_len.min(output.len());
            if data_pos.checked_add(copy_len).map_or(false, |end| end <= exif_len) {
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
