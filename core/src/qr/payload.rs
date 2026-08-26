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

// ═══════════════════════════════════════════════════════════════════════
// qr/payload.rs — Versioned payload framing for QR exchange
//
// Motivation:
//   Historically QRs from KasSigner carried data in ASCII form —
//   base58 ("kpub..." strings), hex, or raw text. Byte-mode QRs already
//   existed for signed transactions (already binary), but anything
//   human-readable went through alphanumeric-friendly ASCII, wasting
//   ~40-50% of QR capacity vs raw bytes.
//
//   This module introduces a 1-byte version header that prefixes any
//   QR payload to declare its format. Legacy payloads are identified
//   as PAYLOAD_V0 (implicit — no header, recognized by absence of a
//   known leading byte). New compact payloads are PAYLOAD_V1_RAW —
//   header 0x01 followed by a raw byte sequence whose interpretation
//   depends on the payload type (kpub, signature, descriptor, etc.)
//   which the caller tracks out-of-band.
//
// Compatibility:
//   Header byte 0x01 was chosen because no legacy ASCII payload starts
//   with it. Base58 starts with '1'-'9','A'-'Z','a'-'z' (0x31-0x7A).
//   ASCII hex starts with '0'-'9','a'-'f' (0x30-0x66). BIP39 mnemonics
//   start with 'a'-'z' (0x61-0x7A). No ambiguity.
//
//   Receivers therefore detect format by peeking the first byte:
//     blob[0] == 0x01  →  PAYLOAD_V1_RAW, parse blob[1..] as raw bytes
//     otherwise        →  PAYLOAD_V0, parse entire blob as legacy ASCII
//
// Future versions:
//   0x02..=0xFF reserved for later additions (compressed, encrypted,
//   multi-chunk framing, etc.). Each new version MUST preserve the
//   "peek byte 0" discrimination rule.
// ═══════════════════════════════════════════════════════════════════════

/// Legacy ASCII payload. Not actually stored as a byte — rather,
/// the absence of a recognized header indicates legacy.
#[allow(dead_code)]
pub const PAYLOAD_V0: u8 = 0x00;

/// V1: raw binary payload. Header `0x01` followed by the raw bytes.
/// Caller knows the semantic type (kpub / signature / descriptor /
/// signed-KSPT / etc.) from context — this module is format-agnostic.
pub const PAYLOAD_V1_RAW: u8 = 0x01;

/// Maximum reasonable payload size for the output buffer sizing.
/// Matches the encoder's V40 byte-mode capacity ceiling.
pub const MAX_RAW_LEN: usize = 2_953;

/// Result of inspecting a received QR blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind<'a> {
    /// Legacy payload (no header, full blob is the ASCII content).
    Legacy(&'a [u8]),
    /// V1 raw-binary payload (header stripped, body is raw bytes).
    V1Raw(&'a [u8]),
}

/// Peek the first byte of a blob and classify its format.
///
/// Empty blobs are classified as `Legacy` (empty). Callers should
/// reject empty payloads at a higher level.
#[inline]
pub fn classify(blob: &[u8]) -> PayloadKind<'_> {
    if blob.is_empty() {
        return PayloadKind::Legacy(blob);
    }
    if blob[0] == PAYLOAD_V1_RAW {
        return PayloadKind::V1Raw(&blob[1..]);
    }
    PayloadKind::Legacy(blob)
}

/// Wrap a raw byte sequence with the V1_RAW header into `out`.
///
/// `out` must be at least `data.len() + 1` bytes. Returns the number
/// of bytes written (always `data.len() + 1`), or `None` if the
/// output buffer is too small or the payload exceeds MAX_RAW_LEN.
pub fn wrap_v1_raw(data: &[u8], out: &mut [u8]) -> Option<usize> {
    if data.len() > MAX_RAW_LEN {
        return None;
    }
    let needed = data.len() + 1;
    if out.len() < needed {
        return None;
    }
    out[0] = PAYLOAD_V1_RAW;
    out[1..needed].copy_from_slice(data);
    Some(needed)
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(not(feature = "skip-tests"))]
#[allow(dead_code)]
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 6u32;

    // Test 1: classify legacy kpub (base58 "kpub...")
    {
        let blob = b"kpub2EXm...";
        if matches!(classify(blob), PayloadKind::Legacy(b) if b == blob) {
            passed += 1;
        }
    }

    // Test 2: classify legacy hex ("0123abcd...")
    {
        let blob = b"0123abcd";
        if matches!(classify(blob), PayloadKind::Legacy(b) if b == blob) {
            passed += 1;
        }
    }

    // Test 3: classify V1 raw (header 0x01)
    {
        let blob = [0x01u8, 0xAA, 0xBB, 0xCC];
        if matches!(classify(&blob), PayloadKind::V1Raw(b) if b == [0xAA, 0xBB, 0xCC]) {
            passed += 1;
        }
    }

    // Test 4: classify empty blob → Legacy(empty)
    {
        let blob: &[u8] = &[];
        if matches!(classify(blob), PayloadKind::Legacy(b) if b.is_empty()) {
            passed += 1;
        }
    }

    // Test 5: wrap_v1_raw roundtrip
    {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = [0u8; 8];
        if let Some(n) = wrap_v1_raw(&data, &mut out) {
            if n == 5 && out[0] == PAYLOAD_V1_RAW && out[1..5] == data {
                // Round-trip through classify
                if matches!(classify(&out[..n]), PayloadKind::V1Raw(b) if b == data) {
                    passed += 1;
                }
            }
        }
    }

    // Test 6: wrap_v1_raw rejects undersized output
    {
        let data = [0u8; 100];
        let mut out = [0u8; 50];
        if wrap_v1_raw(&data, &mut out).is_none() {
            passed += 1;
        }
    }

    (passed, total)
}
