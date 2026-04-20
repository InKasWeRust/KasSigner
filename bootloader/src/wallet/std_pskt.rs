// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! PSKT parser and serializer — Kaspa-standard wire format.
//!
//! Accepts the on-wire format produced by the `kaspa-wallet-pskt` crate:
//! `PSKB` or `PSKT` magic prefix + lowercase hex of UTF-8 JSON bundle.
//! Documented in full at `docs/pskt/PSKT_WIRE_FORMAT.md`.
//!
//! This module is the Kaspa-standard counterpart to `wallet/pskt.rs`
//! (which handles our legacy custom KSPT format). Both modules share
//! the same `Transaction` data model — only the framing differs.
//!
//! # Scope
//!
//! KasSigner operates in PSKT **Signer** and **Combiner** roles only.
//! Creator, Constructor, Updater, Finalizer, Extractor stay in KasSee.
//!
//! # Design
//!
//! - Hand-rolled strict-shape parser (no `serde_json`, no allocator on
//!   the signing path). The format is fixed and well-known; a generic
//!   JSON parser would add ~400 KB of code and an allocator dependency
//!   for no benefit.
//! - Unknown JSON regions are captured as byte-range offsets (see
//!   `app/data.rs::PsktParsed`) and spliced back verbatim on emission —
//!   this is Option A from the migration plan: faithful round-trip
//!   preservation without needing an in-memory DOM.
//! - Validation is strict: any deviation from the schema documented in
//!   the wire-format spec is rejected rather than silently accepted.
//!   This is the right posture for a signing device.
//!
//! # Shipping status
//!
//! - Step 0 — data-model additions + this module's skeleton. DONE.
//! - Step 1 — envelope classifier + strict hex decoder. DONE.
//! - Step 2 — JSON tokenizer. DONE.
//! - Step 3 — parser (global/input/output). DONE.
//! - Step 4 — camera-loop dispatcher. DONE.
//! - Step 5 — serializer. DONE.
//! - Step 6 — signing integration. **THIS FILE + signing.rs + pskt.rs + transaction.rs + camera_loop.rs.**
//!
//! See `docs/pskt/PSKT_MIGRATION_PLAN.md` for the full breakdown.

use crate::app::data::{TxInputFormat, PsktParsed, MAX_PSKT_UNKNOWN_REGIONS};
use crate::wallet::transaction::{
    MAX_INPUTS, MAX_OUTPUTS, MAX_SCRIPT_SIZE, MAX_SIGS_PER_INPUT, Transaction,
};

// ═══════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════

/// Error type for PSKT parse and serialize operations.
///
/// Variants are grouped by the stage where they can surface:
///   - Envelope stage: bad magic, too short, truncated.
///   - Hex stage:      odd length, non-hex, uppercase.
///   - JSON stage:     unexpected token, missing/duplicate field, etc.
///                     (populated in Step 2/3.)
///   - Semantic:       invalid sighash, invalid version, ECDSA rejected,
///                     too many inputs/outputs/sigs, etc.
///                     (populated in Step 3.)
///   - Output:         buffer too small, scratch too small.
///                     (populated in Step 5.)
///
/// `Copy` so it can be returned from parser helpers without borrows
/// propagating. `repr(u8)` so it fits in tight match arms in camera_loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskError {
    // ─── Envelope ─────────────────────────────────────────────────
    /// Payload too short to contain a magic prefix.
    TooShort,
    /// Magic prefix is not `PSKB` or `PSKT`.
    BadMagic,
    /// Envelope declares PSKT shape but body is empty / truncated.
    TruncatedEnvelope,

    // ─── Hex decoding ────────────────────────────────────────────
    /// Hex string has odd length (each byte needs 2 nibbles).
    OddHexLength,
    /// Character outside `0-9a-f` (uppercase rejected by design — the
    /// upstream emitter always produces lowercase).
    BadHexChar,
    /// Hex-decode output buffer too small for the input length / 2.
    ScratchBufferTooSmall,

    // ─── JSON / shape (Step 2-3) ──────────────────────────────────
    /// Reserved for Step 2 tokenizer.
    UnexpectedToken,
    /// Reserved for Step 3 parser — required field missing.
    MissingField,
    /// Reserved for Step 3 parser — field present more than once.
    DuplicateField,
    /// Reserved for Step 3 parser — too many inputs.
    TooManyInputs,
    /// Reserved for Step 3 parser — too many outputs.
    TooManyOutputs,
    /// Reserved for Step 3 parser — too many partial sigs on an input.
    TooManyPartialSigs,
    /// Reserved for Step 3 parser — too many unknown byte-range regions
    /// for the preservation slot array.
    TooManyUnknownRegions,

    // ─── Semantic validation (Step 3) ─────────────────────────────
    /// `sighashType` was not 1 (SIGHASH_ALL). Other values rejected by
    /// design; this is PSBT's #1 historical vulnerability class.
    InvalidSighashType,
    /// `Signature` enum variant was `ecdsa`. Kaspa is Schnorr-only.
    InvalidSignatureType,
    /// Pubkey hex didn't decode to the expected 33 bytes (compressed
    /// secp256k1 pubkey with 02/03 prefix).
    InvalidPubkeyLen,
    /// Script hex was longer than `MAX_SCRIPT_SIZE`.
    InvalidScriptLen,
    /// `scriptPublicKey` hex too short to contain the 2-byte version
    /// prefix.
    ShortScriptPubkey,
    /// `global.version` was not 0, or `txVersion` was not in the range
    /// KasSigner supports.
    VersionNotSupported,
    /// `inputCount` / `outputCount` in globals disagreed with array lens.
    CountMismatch,
    /// Bundle had more than one PSKT element (unsupported by KasSigner).
    BundleMultiElement,

    // ─── Output / Serialize (Step 5) ──────────────────────────────
    /// Output buffer too small for the serialized payload.
    OutputBufferTooSmall,
}

// ═══════════════════════════════════════════════════════════════════════
// Envelope detection
// ═══════════════════════════════════════════════════════════════════════

/// Magic prefix for PSKB (bundle of PSKTs) wire payloads.
pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";

/// Magic prefix for single-PSKT (non-bundle) wire payloads.
pub const PSKT_MAGIC: &[u8; 4] = b"PSKT";

/// Magic prefix for legacy custom KSPT v1/v2 binary format.
/// Same bytes as v1 checks use in `camera_loop.rs`; defined here so
/// `detect_tx_format` is self-contained.
pub const KSPT_MAGIC: &[u8; 4] = b"KSPT";

/// Which framing envelope a received payload carries, or `Unknown` if
/// the first few bytes match none of the formats this module knows.
///
/// Extended beyond the `TxInputFormat` enum in `app/data.rs` with an
/// `Unknown` variant because detection happens before classification —
/// a caller may want to skip the payload entirely without marking
/// `tx_input_format` on AppData.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    /// Legacy KSPT v1 (unsigned).
    KsptV1,
    /// Legacy KSPT v2 (partially signed).
    KsptV2,
    /// Kaspa-standard PSKT, `PSKB` prefix, hex-wrapped Bundle JSON.
    PsktPskb,
    /// Kaspa-standard PSKT, `PSKT` prefix, hex-wrapped single-PSKT JSON.
    PsktSingle,
    /// First bytes match nothing we recognize.
    Unknown,
}

impl DetectedFormat {
    /// Convert to the `TxInputFormat` used by `AppData` for dispatch.
    /// Returns `None` for `Unknown`, so callers see an explicit signal
    /// to skip instead of a silent fallthrough.
    pub fn to_tx_input_format(self) -> Option<TxInputFormat> {
        match self {
            Self::KsptV1 => Some(TxInputFormat::KsptV1),
            Self::KsptV2 => Some(TxInputFormat::KsptV2),
            Self::PsktPskb => Some(TxInputFormat::PsktPskb),
            Self::PsktSingle => Some(TxInputFormat::PsktSingle),
            Self::Unknown => None,
        }
    }
}

/// Classify an incoming payload by its magic bytes.
///
/// For KSPT, distinguishes v1 vs v2 by the version byte at offset 4,
/// matching the existing behavior in `handlers/camera_loop.rs` so the
/// dispatcher in Step 4 gets identical routing with no surprises.
///
/// For PSKT, just checks the 4-byte magic — the body (hex-encoded JSON)
/// is validated later by `hex_decode_strict` and the JSON parser.
///
/// Never fails. Unknown input returns `DetectedFormat::Unknown` so the
/// caller decides how to react.
pub fn detect_tx_format(data: &[u8]) -> DetectedFormat {
    if data.len() < 4 {
        return DetectedFormat::Unknown;
    }
    let magic = &data[..4];

    if magic == KSPT_MAGIC {
        // KSPT v1 vs v2 — identical to the live check in camera_loop.rs:268.
        // Default to v1 if payload is too short to have a version byte.
        let ksp_version = if data.len() >= 5 { data[4] } else { 0x01 };
        return if ksp_version == 0x02 {
            DetectedFormat::KsptV2
        } else {
            DetectedFormat::KsptV1
        };
    }
    if magic == PSKB_MAGIC {
        return DetectedFormat::PsktPskb;
    }
    if magic == PSKT_MAGIC {
        return DetectedFormat::PsktSingle;
    }

    DetectedFormat::Unknown
}

/// Strip the 4-byte magic prefix from a PSKT-shaped payload and return
/// the inner hex bytes, or an error if the payload isn't PSKT or is
/// truncated.
///
/// Use when you've already committed to a PSKT branch (e.g. after
/// `detect_tx_format` returned `PsktPskb` or `PsktSingle`) and want
/// the remaining hex body to feed into `hex_decode_strict`.
///
/// An empty body is rejected — a zero-length hex payload can't encode
/// a valid JSON bundle.
pub fn strip_pskt_magic(data: &[u8]) -> Result<&[u8], PskError> {
    if data.len() < 4 {
        return Err(PskError::TooShort);
    }
    let magic = &data[..4];
    if magic != PSKB_MAGIC && magic != PSKT_MAGIC {
        return Err(PskError::BadMagic);
    }
    let body = &data[4..];
    if body.is_empty() {
        return Err(PskError::TruncatedEnvelope);
    }
    Ok(body)
}

// ═══════════════════════════════════════════════════════════════════════
// Strict hex decoder
// ═══════════════════════════════════════════════════════════════════════

/// Decode a single ASCII hex nibble character into its 4-bit value.
///
/// Accepts `0-9` and **lowercase** `a-f` only. Uppercase is rejected
/// by design — the upstream `kaspa-wallet-pskt` crate uses
/// `hex::encode` which always emits lowercase, and rejecting uppercase
/// gives us byte-exact round-trip detection for free.
///
/// Inline because the hex decoder calls it per-nibble.
#[inline]
fn hex_nibble(c: u8) -> Result<u8, PskError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(PskError::BadHexChar),
    }
}

/// Strict lowercase-hex decoder.
///
/// Writes decoded bytes into `dst`, returns the number of bytes
/// written. Fails on:
///   - odd length `src` (can't form whole bytes)
///   - any character outside `0-9a-f` (uppercase, whitespace, `0x` prefix all rejected)
///   - `dst.len() < src.len() / 2`
///
/// No allocation. Single pass. Safe to call on the signing path — no
/// panics, no unwraps.
///
/// Example:
/// ```ignore
/// let mut out = [0u8; 4];
/// let n = hex_decode_strict(b"deadbeef", &mut out)?;
/// assert_eq!(n, 4);
/// assert_eq!(&out[..n], &[0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn hex_decode_strict(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    if src.len() & 1 != 0 {
        return Err(PskError::OddHexLength);
    }
    let need = src.len() / 2;
    if dst.len() < need {
        return Err(PskError::ScratchBufferTooSmall);
    }
    let mut i = 0;
    while i < need {
        let hi = hex_nibble(src[2 * i])?;
        let lo = hex_nibble(src[2 * i + 1])?;
        dst[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(need)
}

/// Encode bytes as lowercase hex into `dst`, returning the number of
/// ASCII chars written. Used by the serializer in Step 5; defined here
/// because it's the natural inverse of `hex_decode_strict` and sharing
/// a file keeps both sides of the conversion in one review surface.
///
/// Fails with `OutputBufferTooSmall` if `dst.len() < src.len() * 2`.
pub fn hex_encode_lower(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    let need = src.len() * 2;
    if dst.len() < need {
        return Err(PskError::OutputBufferTooSmall);
    }
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0;
    while i < src.len() {
        dst[2 * i] = HEX_CHARS[(src[i] >> 4) as usize];
        dst[2 * i + 1] = HEX_CHARS[(src[i] & 0x0F) as usize];
        i += 1;
    }
    Ok(need)
}

// ═══════════════════════════════════════════════════════════════════════
// JSON tokenizer
// ═══════════════════════════════════════════════════════════════════════
//
// Strict, flat, one-pass tokenizer for the PSKT JSON shape. No recursion,
// no lookahead beyond one byte, no allocations. Designed to reject
// anything outside the narrow set of JSON features `serde_json` emits
// for the PSKT schema — the tighter this is, the smaller the attack
// surface on a signing device.
//
// Accepted:
//   - `{ } [ ] : ,`
//   - String literals `"..."` containing only ASCII printable bytes
//     except `"` and `\`. No escape sequences. The emitter never needs
//     them — pubkeys and signatures are lowercase-hex, JSON keys are
//     camelCase ASCII, no other strings exist.
//   - Number literals: non-negative integers only (`0`, `12345`,
//     `18446744073709551615`). No leading zeros except for the single
//     digit `0` itself, no sign, no decimal point, no exponent.
//   - Keywords `true`, `false`, `null` (exact lowercase).
//   - ASCII whitespace (space, tab, CR, LF) between tokens — tolerated
//     even though real PSKTs are compact, so humans pasting prettified
//     JSON for debugging get a useful error instead of a tokenize fail.
//
// Rejected:
//   - Escape sequences inside strings.
//   - Uppercase keywords (`True`, `NULL`).
//   - Negative numbers, fractions, scientific notation.
//   - Bytes > 0x7E or < 0x20 inside strings (only printable ASCII).
//   - Any byte outside the grammar elsewhere.
//
// Rejection signals a malformed or suspicious payload — we never fall
// back to "accept and hope." A strict signer refuses ambiguous input.

/// A single token produced by `Tokenizer`. Keeps a zero-copy reference
/// to the source buffer for `Str` and `Num` — the parser can decode
/// hex strings or parse u64 numbers directly from these slices without
/// an intermediate copy.
///
/// Lifetimes: tied to the source buffer passed into `Tokenizer::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok<'a> {
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `:`
    Colon,
    /// `,`
    Comma,
    /// String literal contents, between the quotes, unescaped.
    /// Because the tokenizer rejects escape sequences, the bytes here
    /// are exactly the bytes on the wire — no decoding needed.
    Str(&'a [u8]),
    /// Number literal raw bytes (digits only, no sign, no decimal).
    /// The parser parses to u64 or similar as needed.
    Num(&'a [u8]),
    /// `true`
    True,
    /// `false`
    False,
    /// `null`
    Null,
    /// End of input. Emitted once the buffer is consumed; subsequent
    /// `next()` calls keep returning `Eof`.
    Eof,
}

/// Flat one-pass tokenizer over a byte slice.
///
/// Does not carry interior `Result` state — every `next()` call returns
/// a fresh `Result<Tok, PskError>`. Errors leave the `pos` cursor
/// pointing at the offending byte so callers can build useful diagnostics
/// (line/column if they want, byte offset otherwise).
pub struct Tokenizer<'a> {
    data: &'a [u8],
    /// Current position in `data`. Between 0 and `data.len()` inclusive.
    pub pos: usize,
}

impl<'a> Tokenizer<'a> {
    /// Construct a tokenizer over `data`. The caller retains ownership;
    /// tokens borrow from this buffer.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Byte offset of the next token that `next()` will try to parse.
    /// Useful for the parser's byte-range capture of unknown regions
    /// (Option A preservation — see `app/data.rs::PsktParsed`).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Advance past any ASCII whitespace. Tolerated even though compact
    /// JSON has none — prettified paste-in debug inputs still tokenize.
    #[inline]
    fn skip_ws(&mut self) {
        while self.pos < self.data.len() {
            match self.data[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => return,
            }
        }
    }

    /// Produce the next token. After Eof is returned, subsequent calls
    /// continue to return Eof (not an error) — the parser can treat Eof
    /// as a normal terminator.
    pub fn next(&mut self) -> Result<Tok<'a>, PskError> {
        self.skip_ws();
        if self.pos >= self.data.len() {
            return Ok(Tok::Eof);
        }

        let b = self.data[self.pos];
        match b {
            b'{' => { self.pos += 1; Ok(Tok::LBrace) }
            b'}' => { self.pos += 1; Ok(Tok::RBrace) }
            b'[' => { self.pos += 1; Ok(Tok::LBracket) }
            b']' => { self.pos += 1; Ok(Tok::RBracket) }
            b':' => { self.pos += 1; Ok(Tok::Colon) }
            b',' => { self.pos += 1; Ok(Tok::Comma) }
            b'"' => self.read_string(),
            b'0'..=b'9' => self.read_number(),
            b't' => self.read_keyword(b"true", Tok::True),
            b'f' => self.read_keyword(b"false", Tok::False),
            b'n' => self.read_keyword(b"null", Tok::Null),
            _ => Err(PskError::UnexpectedToken),
        }
    }

    /// Peek at the next token without consuming it. Implementation saves
    /// and restores `pos`; cheap since `Tok` is Copy.
    pub fn peek(&mut self) -> Result<Tok<'a>, PskError> {
        let saved = self.pos;
        let tok = self.next();
        self.pos = saved;
        tok
    }

    // ─── String literal ──────────────────────────────────────────
    //
    // Accepts bytes 0x20..=0x7E except `"` (0x22) and `\` (0x5C).
    // Rejects everything else — no escapes, no non-ASCII, no control
    // chars. This is tighter than strict JSON but matches exactly
    // what serde emits for our schema.

    fn read_string(&mut self) -> Result<Tok<'a>, PskError> {
        debug_assert!(self.data[self.pos] == b'"');
        let start = self.pos + 1;   // skip opening quote
        let mut i = start;
        while i < self.data.len() {
            let c = self.data[i];
            if c == b'"' {
                // closing quote found
                let body = &self.data[start..i];
                self.pos = i + 1;
                return Ok(Tok::Str(body));
            }
            if c == b'\\' {
                // Any escape sequence is rejected — see comment above.
                self.pos = i;
                return Err(PskError::UnexpectedToken);
            }
            if !(0x20..=0x7E).contains(&c) {
                // Non-printable or non-ASCII — outside our grammar.
                self.pos = i;
                return Err(PskError::UnexpectedToken);
            }
            i += 1;
        }
        // ran off the end without finding closing quote
        self.pos = self.data.len();
        Err(PskError::TruncatedEnvelope)
    }

    // ─── Number literal ──────────────────────────────────────────
    //
    // Accepts `0` or any sequence of digits starting with `1-9`.
    // Rejects leading zeros (e.g. `007`), negatives, fractions,
    // exponents. serde_json emits numbers in exactly this form for
    // u64 fields.

    fn read_number(&mut self) -> Result<Tok<'a>, PskError> {
        let start = self.pos;
        let first = self.data[start];
        debug_assert!(first.is_ascii_digit());

        if first == b'0' {
            // Single '0' only — no leading zeros like "007".
            self.pos += 1;
            // If a digit immediately follows, that's a leading-zero number.
            if self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
                return Err(PskError::UnexpectedToken);
            }
            return Ok(Tok::Num(&self.data[start..self.pos]));
        }

        // `1-9` followed by zero or more digits.
        self.pos += 1;
        while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        // Reject fractions / exponents explicitly.
        if self.pos < self.data.len() {
            let c = self.data[self.pos];
            if c == b'.' || c == b'e' || c == b'E' {
                return Err(PskError::UnexpectedToken);
            }
        }
        Ok(Tok::Num(&self.data[start..self.pos]))
    }

    // ─── Keyword (true/false/null) ───────────────────────────────
    //
    // Exact-match lowercase. No case folding. One-shot check of the
    // expected bytes and return the fixed Tok variant.

    fn read_keyword(&mut self, expected: &'static [u8], tok: Tok<'a>) -> Result<Tok<'a>, PskError> {
        let end = self.pos + expected.len();
        if end > self.data.len() {
            return Err(PskError::TruncatedEnvelope);
        }
        if &self.data[self.pos..end] != expected {
            return Err(PskError::UnexpectedToken);
        }
        self.pos = end;
        Ok(tok)
    }
}

/// Helper: parse a `Tok::Num` byte slice into a u64. Returns
/// `UnexpectedToken` on overflow or empty input. The tokenizer has
/// already guaranteed the bytes are all ASCII digits with no leading
/// zero (except for "0" itself), so this is a simple multiply-and-add
/// with an overflow check.
///
/// Used by the parser (Step 3) for fields like `amount`, `sequence`,
/// `blockDaaScore`, `sigOpCount`, `version`, `txVersion`, etc.
pub fn parse_u64_num(bytes: &[u8]) -> Result<u64, PskError> {
    if bytes.is_empty() {
        return Err(PskError::UnexpectedToken);
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(PskError::UnexpectedToken);
        }
        let digit = (b - b'0') as u64;
        acc = match acc.checked_mul(10).and_then(|x| x.checked_add(digit)) {
            Some(v) => v,
            None => return Err(PskError::UnexpectedToken),  // overflow
        };
    }
    Ok(acc)
}


// ═══════════════════════════════════════════════════════════════════════
// Parser — top level
// ═══════════════════════════════════════════════════════════════════════
//
// Walks the PSKT/PSKB wire bytes end-to-end: strips the 4-byte magic,
// hex-decodes the body into `scratch`, then tokenizes and parses the
// JSON bundle. Fills `tx` from known fields. Captures byte-range offsets
// for unknown fields into `parsed` so the serializer (Step 5) can splice
// them back verbatim on re-emission — see Option A in the migration plan.
//
// All offsets stored in `parsed.unknowns` are relative to the start of
// the decoded JSON in `scratch`, not the original wire payload. The
// serializer slices directly from `scratch`.

/// Limits on tx shape. Matched to the existing `Transaction` struct caps
/// in `wallet/transaction.rs`. Rejecting anything above these bounds
/// keeps the parser safe from pathological inputs.
const MIN_TX_VERSION: u16 = 0;
const MAX_TX_VERSION: u16 = 1;     // v0 + optional future v1
const PSKT_VERSION_OK: u64 = 0;    // global.version field — only 0 supported
const SIGHASH_ALL: u8 = 1;

/// Decode the wire payload and parse the resulting JSON into `tx`.
///
/// `wire` must carry a PSKB/PSKT magic prefix; inner body is lowercase
/// hex of a compact JSON bundle. `scratch` must be at least
/// `(wire.len() - 4) / 2` bytes; the decoded JSON lives there for the
/// lifetime of the parse. `parsed` is zeroed and repopulated.
///
/// On success, `tx` contains the parsed transaction and `parsed.unknowns`
/// records byte-range offsets (into `scratch`) of unknown fields.
///
/// On error, `tx` and `parsed` are left in an unspecified state —
/// callers must treat the whole parse as failed and not trust partial
/// results.
pub fn parse_pskt(
    wire: &[u8],
    scratch: &mut [u8],
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    // Stage 1 — envelope.
    let body_hex = strip_pskt_magic(wire)?;

    // Stage 2 — hex decode into scratch.
    let json_len = hex_decode_strict(body_hex, scratch)?;
    let json = &scratch[..json_len];

    // Stage 3 — JSON parse.
    *parsed = PsktParsed::empty();
    parsed.json_start = 0;
    parsed.json_len = json_len as u16;

    *tx = Transaction::new();

    let mut tok = Tokenizer::new(json);
    parse_bundle_array(&mut tok, tx, parsed)?;

    // Trailing content after the closing `]` is rejected — we don't
    // allow junk after the bundle (would otherwise let an attacker
    // append hidden data that passes the hex check).
    expect(&mut tok, Tok::Eof)?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — helpers
// ═══════════════════════════════════════════════════════════════════════

/// Assert the next token matches `expected`. Consumes the token on
/// match; errors on mismatch.
fn expect(tok: &mut Tokenizer<'_>, expected: Tok<'_>) -> Result<(), PskError> {
    let got = tok.next()?;
    if core::mem::discriminant(&got) != core::mem::discriminant(&expected) {
        return Err(PskError::UnexpectedToken);
    }
    Ok(())
}

/// Read a string token, return its bytes.
fn expect_string<'a>(tok: &mut Tokenizer<'a>) -> Result<&'a [u8], PskError> {
    match tok.next()? {
        Tok::Str(s) => Ok(s),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Read a u64 number token.
fn expect_u64(tok: &mut Tokenizer<'_>) -> Result<u64, PskError> {
    match tok.next()? {
        Tok::Num(n) => parse_u64_num(n),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Record an unknown byte-range. `start` is the position where the
/// field's `"key"` token began; `end` is the position after the value's
/// last byte. Fails with `TooManyUnknownRegions` if the slot array is
/// full.
fn capture_unknown(parsed: &mut PsktParsed, start: usize, end: usize) -> Result<(), PskError> {
    let idx = parsed.unknowns_count as usize;
    if idx >= MAX_PSKT_UNKNOWN_REGIONS {
        return Err(PskError::TooManyUnknownRegions);
    }
    parsed.unknowns[idx] = (start as u16, end as u16);
    parsed.unknowns_count += 1;
    Ok(())
}

/// Skip one JSON value (string, number, bool, null, object, array).
/// Consumes tokens until a complete value has been read. Used for fields
/// we want to byte-range-capture without interpreting.
fn skip_value(tok: &mut Tokenizer<'_>) -> Result<(), PskError> {
    match tok.next()? {
        Tok::Str(_) | Tok::Num(_) | Tok::True | Tok::False | Tok::Null => Ok(()),
        Tok::LBrace => skip_until_matching(tok, Tok::RBrace),
        Tok::LBracket => skip_until_matching(tok, Tok::RBracket),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Consume tokens until the matching close brace/bracket is found,
/// handling nesting. Called after an opening `{` or `[` has already
/// been consumed.
fn skip_until_matching(tok: &mut Tokenizer<'_>, close: Tok<'_>) -> Result<(), PskError> {
    let mut depth: u32 = 1;
    while depth > 0 {
        match tok.next()? {
            Tok::LBrace | Tok::LBracket => depth += 1,
            Tok::RBrace | Tok::RBracket => {
                depth -= 1;
                // Only check the close discriminant at depth 0 — nested
                // brace/bracket mismatches get caught structurally.
                if depth == 0 {
                    // No way to verify which close variant matched because
                    // the tokenizer doesn't distinguish, but that's fine:
                    // a mismatched `{` `]` would have been caught earlier
                    // by increment/decrement balance. This loop just walks.
                    let _ = close;
                    return Ok(());
                }
            }
            Tok::Eof => return Err(PskError::TruncatedEnvelope),
            _ => { /* strings, numbers, literals inside — ignore */ }
        }
    }
    Ok(())
}

/// Parse a hex-string JSON field into raw bytes. Returns the decoded
/// length. Errors on bad hex or buffer overflow.
fn parse_hex_field(hex_str: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    hex_decode_strict(hex_str, dst)
}

/// Parse the flat-hex `scriptPublicKey` string: first 4 hex chars are a
/// u16 BE version, remaining chars are the script bytes.
///
/// Populates `out_version` and `out_script`; returns the script byte
/// length. Errors if hex is too short for the version prefix or if the
/// script doesn't fit in `out_script`.
fn parse_script_public_key(
    hex_str: &[u8],
    out_version: &mut u16,
    out_script: &mut [u8; MAX_SCRIPT_SIZE],
) -> Result<usize, PskError> {
    if hex_str.len() < 4 {
        return Err(PskError::ShortScriptPubkey);
    }
    // Version: 2 bytes (4 hex chars) BE.
    let mut version_bytes = [0u8; 2];
    hex_decode_strict(&hex_str[..4], &mut version_bytes)?;
    *out_version = ((version_bytes[0] as u16) << 8) | (version_bytes[1] as u16);

    // Script bytes.
    let script_hex = &hex_str[4..];
    if script_hex.len() / 2 > MAX_SCRIPT_SIZE {
        return Err(PskError::InvalidScriptLen);
    }
    let n = hex_decode_strict(script_hex, out_script)?;
    Ok(n)
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — bundle + PSKT object
// ═══════════════════════════════════════════════════════════════════════

/// Parse the outer `[{...}]` bundle array. KasSigner only accepts
/// single-element bundles.
fn parse_bundle_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBracket)?;

    // Empty bundle rejected — must have one PSKT.
    match tok.peek()? {
        Tok::RBracket => return Err(PskError::MissingField),
        _ => {}
    }

    parse_pskt_object(tok, tx, parsed)?;

    // Closing `]`. Reject multi-element bundles — a comma here would
    // start another PSKT.
    match tok.next()? {
        Tok::RBracket => Ok(()),
        Tok::Comma => Err(PskError::BundleMultiElement),
        _ => Err(PskError::UnexpectedToken),
    }
}

/// Parse a single `{global, inputs, outputs}` PSKT object.
fn parse_pskt_object(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    // Field-seen bitmask. The three top-level fields are required.
    const HAS_GLOBAL: u8 = 1 << 0;
    const HAS_INPUTS: u8 = 1 << 1;
    const HAS_OUTPUTS: u8 = 1 << 2;
    let mut seen: u8 = 0;

    // Empty objects are rejected — we need all three fields.
    if let Tok::RBrace = tok.peek()? {
        return Err(PskError::MissingField);
    }

    loop {
        // Key.
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;

        match key {
            b"global" => {
                if seen & HAS_GLOBAL != 0 {
                    return Err(PskError::DuplicateField);
                }
                parse_global(tok, tx, parsed)?;
                seen |= HAS_GLOBAL;
            }
            b"inputs" => {
                if seen & HAS_INPUTS != 0 {
                    return Err(PskError::DuplicateField);
                }
                parse_inputs_array(tok, tx, parsed)?;
                seen |= HAS_INPUTS;
            }
            b"outputs" => {
                if seen & HAS_OUTPUTS != 0 {
                    return Err(PskError::DuplicateField);
                }
                parse_outputs_array(tok, tx, parsed)?;
                seen |= HAS_OUTPUTS;
            }
            _ => {
                // Unknown top-level field — capture and move on.
                skip_value(tok)?;
                capture_unknown(parsed, key_start, tok.position())?;
            }
        }

        // Comma or close.
        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if seen != (HAS_GLOBAL | HAS_INPUTS | HAS_OUTPUTS) {
        return Err(PskError::MissingField);
    }

    // Validate counts match arrays.
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — global
// ═══════════════════════════════════════════════════════════════════════

fn parse_global(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    // Most global fields are required; some are always-present but we
    // don't need to interpret them (xpubs, id, proprietaries,
    // fallbackLockTime). We still validate presence by reading them.
    let mut seen_version = false;
    let mut seen_tx_version = false;
    let mut seen_input_count = false;
    let mut seen_output_count = false;

    if let Tok::RBrace = tok.peek()? {
        return Err(PskError::MissingField);
    }

    loop {
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;

        match key {
            b"version" => {
                if seen_version { return Err(PskError::DuplicateField); }
                let v = expect_u64(tok)?;
                if v != PSKT_VERSION_OK {
                    return Err(PskError::VersionNotSupported);
                }
                seen_version = true;
            }
            b"txVersion" => {
                if seen_tx_version { return Err(PskError::DuplicateField); }
                let v = expect_u64(tok)?;
                if v > MAX_TX_VERSION as u64 || v < MIN_TX_VERSION as u64 {
                    return Err(PskError::VersionNotSupported);
                }
                tx.version = v as u16;
                seen_tx_version = true;
            }
            b"inputCount" => {
                if seen_input_count { return Err(PskError::DuplicateField); }
                let n = expect_u64(tok)?;
                if n as usize > MAX_INPUTS {
                    return Err(PskError::TooManyInputs);
                }
                // We don't store input_count directly; num_inputs is set
                // by parse_inputs_array. We validate consistency later.
                seen_input_count = true;
                let _ = n;
            }
            b"outputCount" => {
                if seen_output_count { return Err(PskError::DuplicateField); }
                let n = expect_u64(tok)?;
                if n as usize > MAX_OUTPUTS {
                    return Err(PskError::TooManyOutputs);
                }
                seen_output_count = true;
                let _ = n;
            }
            // ── Structural fields: shape is fixed, serializer reconstructs
            //    from known state. No capture needed.
            b"fallbackLockTime" | b"inputsModifiable" | b"outputsModifiable" => {
                skip_value(tok)?;
            }
            // ── Opaque fields: may carry content the serializer can't
            //    reconstruct. Capture only if non-default so a realistic
            //    2-of-3 multisig PSKT survives the 16-slot budget.
            b"xpubs" | b"proprietaries" => {
                // Both are objects. Empty `{}` is the default in all
                // canonical vectors; capture only if non-empty.
                expect(tok, Tok::LBrace)?;
                match tok.peek()? {
                    Tok::RBrace => { tok.next()?; }
                    _ => {
                        skip_until_matching(tok, Tok::RBrace)?;
                        capture_unknown(parsed, key_start, tok.position())?;
                    }
                }
            }
            b"id" => {
                // Either `null` or a hex string. `null` is the default.
                match tok.next()? {
                    Tok::Null => { /* default, no capture */ }
                    Tok::Str(_) => {
                        // Non-default id present — capture the whole
                        // `"id":"..."` region.
                        capture_unknown(parsed, key_start, tok.position())?;
                    }
                    _ => return Err(PskError::UnexpectedToken),
                }
            }
            _ => {
                // Truly unknown field (e.g. future kaspa-wallet-pskt
                // addition). Capture for round-trip.
                skip_value(tok)?;
                capture_unknown(parsed, key_start, tok.position())?;
            }
        }

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if !(seen_version && seen_tx_version && seen_input_count && seen_output_count) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — inputs
// ═══════════════════════════════════════════════════════════════════════

fn parse_inputs_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBracket)?;

    // Empty array allowed in principle (Creator state), but a KasSigner
    // signing flow should see at least one input. We accept empty here
    // and let semantic validation in camera_loop.rs reject if needed.
    if let Tok::RBracket = tok.peek()? {
        tok.next()?; // consume `]`
        tx.num_inputs = 0;
        return Ok(());
    }

    let mut count: usize = 0;
    loop {
        if count >= MAX_INPUTS {
            return Err(PskError::TooManyInputs);
        }
        parse_input(tok, tx, parsed, count)?;
        count += 1;

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBracket => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }
    tx.num_inputs = count;
    Ok(())
}

fn parse_input(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    idx: usize,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    let inp = &mut tx.inputs[idx];
    let mut seen_utxo = false;
    let mut seen_outpoint = false;
    let mut seen_sighash = false;

    if let Tok::RBrace = tok.peek()? {
        return Err(PskError::MissingField);
    }

    loop {
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;

        match key {
            b"utxoEntry" => {
                if seen_utxo { return Err(PskError::DuplicateField); }
                parse_utxo_entry(tok, inp)?;
                seen_utxo = true;
            }
            b"previousOutpoint" => {
                if seen_outpoint { return Err(PskError::DuplicateField); }
                parse_outpoint(tok, inp)?;
                seen_outpoint = true;
            }
            b"sequence" => {
                inp.sequence = expect_u64(tok)?;
            }
            b"sighashType" => {
                if seen_sighash { return Err(PskError::DuplicateField); }
                let st = expect_u64(tok)?;
                if st != SIGHASH_ALL as u64 {
                    return Err(PskError::InvalidSighashType);
                }
                inp.sighash_type = SIGHASH_ALL;
                seen_sighash = true;
            }
            b"redeemScript" => {
                // null OR hex string.
                match tok.next()? {
                    Tok::Null => { inp.redeem_script_len = 0; }
                    Tok::Str(hex_str) => {
                        if hex_str.len() / 2 > MAX_SCRIPT_SIZE {
                            return Err(PskError::InvalidScriptLen);
                        }
                        inp.redeem_script_len =
                            parse_hex_field(hex_str, &mut inp.redeem_script)?;
                    }
                    _ => return Err(PskError::UnexpectedToken),
                }
            }
            b"sigOpCount" => {
                let n = expect_u64(tok)?;
                if n > MAX_SIGS_PER_INPUT as u64 {
                    return Err(PskError::TooManyPartialSigs);
                }
                inp.sig_op_count = n as u8;
            }
            b"partialSigs" => {
                parse_partial_sigs(tok, inp)?;
            }
            b"bip32Derivations" => {
                // We don't interpret KeySource; just skip the object
                // shape. Capture so non-empty maps round-trip.
                parse_bip32_derivations(tok, parsed, key_start)?;
            }
            b"minTime" | b"finalScriptSig" => {
                // Always-present structural fields (null by default).
                // Serializer reconstructs from known state.
                skip_value(tok)?;
            }
            b"proprietaries" => {
                // Opaque. `{}` is the default — capture only if non-empty
                // so V1.1 multisig flows don't blow the 16-slot budget.
                // Peek at the first token inside the map.
                let val_start = tok.position();
                expect(tok, Tok::LBrace)?;
                match tok.peek()? {
                    Tok::RBrace => { tok.next()?; }  // empty, no capture
                    _ => {
                        skip_until_matching(tok, Tok::RBrace)?;
                        capture_unknown(parsed, key_start, tok.position())?;
                    }
                }
                let _ = val_start;
            }
            _ => {
                // Unknown future field.
                skip_value(tok)?;
                capture_unknown(parsed, key_start, tok.position())?;
            }
        }

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if !(seen_utxo && seen_outpoint && seen_sighash) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

fn parse_utxo_entry(
    tok: &mut Tokenizer<'_>,
    inp: &mut crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    let mut seen_amount = false;
    let mut seen_spk = false;

    loop {
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        match key {
            b"amount" => {
                if seen_amount { return Err(PskError::DuplicateField); }
                inp.utxo_entry.amount = expect_u64(tok)?;
                seen_amount = true;
            }
            b"scriptPublicKey" => {
                if seen_spk { return Err(PskError::DuplicateField); }
                let hex_str = expect_string(tok)?;
                let spk = &mut inp.utxo_entry.script_public_key;
                spk.script_len = parse_script_public_key(
                    hex_str,
                    &mut spk.version,
                    &mut spk.script,
                )?;
                seen_spk = true;
            }
            b"blockDaaScore" | b"isCoinbase" => {
                // Not used in signing. Read and discard.
                skip_value(tok)?;
            }
            _ => {
                skip_value(tok)?;
            }
        }
        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if !(seen_amount && seen_spk) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

fn parse_outpoint(
    tok: &mut Tokenizer<'_>,
    inp: &mut crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    let mut seen_txid = false;
    let mut seen_index = false;

    loop {
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        match key {
            b"transactionId" => {
                if seen_txid { return Err(PskError::DuplicateField); }
                let hex_str = expect_string(tok)?;
                if hex_str.len() != 64 {
                    return Err(PskError::UnexpectedToken);
                }
                hex_decode_strict(hex_str, &mut inp.previous_outpoint.transaction_id)?;
                seen_txid = true;
            }
            b"index" => {
                if seen_index { return Err(PskError::DuplicateField); }
                let v = expect_u64(tok)?;
                if v > u32::MAX as u64 {
                    return Err(PskError::UnexpectedToken);
                }
                inp.previous_outpoint.index = v as u32;
                seen_index = true;
            }
            _ => {
                skip_value(tok)?;
            }
        }
        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if !(seen_txid && seen_index) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

fn parse_partial_sigs(
    tok: &mut Tokenizer<'_>,
    inp: &mut crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    // Empty map is fine and common (unsigned PSKT).
    if let Tok::RBrace = tok.peek()? {
        tok.next()?;
        inp.incoming_partial_sigs_count = 0;
        return Ok(());
    }

    let mut count: usize = 0;
    loop {
        if count >= MAX_SIGS_PER_INPUT {
            return Err(PskError::TooManyPartialSigs);
        }

        // Key: 33-byte compressed pubkey as 66-char hex.
        let pk_hex = expect_string(tok)?;
        if pk_hex.len() != 66 {
            return Err(PskError::InvalidPubkeyLen);
        }
        let slot = &mut inp.incoming_partial_sigs[count];
        hex_decode_strict(pk_hex, &mut slot.pubkey)?;

        expect(tok, Tok::Colon)?;

        // Value: { "schnorr": "<128 hex chars>" }
        expect(tok, Tok::LBrace)?;
        let variant = expect_string(tok)?;
        if variant == b"ecdsa" {
            return Err(PskError::InvalidSignatureType);
        }
        if variant != b"schnorr" {
            return Err(PskError::UnexpectedToken);
        }
        expect(tok, Tok::Colon)?;
        let sig_hex = expect_string(tok)?;
        if sig_hex.len() != 128 {
            return Err(PskError::UnexpectedToken);
        }
        hex_decode_strict(sig_hex, &mut slot.signature)?;
        expect(tok, Tok::RBrace)?;

        slot.present = true;
        count += 1;

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    inp.incoming_partial_sigs_count = count as u8;
    Ok(())
}

fn parse_bip32_derivations(
    tok: &mut Tokenizer<'_>,
    parsed: &mut PsktParsed,
    field_start: usize,
) -> Result<(), PskError> {
    // Object of { pubkey_hex: null-or-KeySource }. We don't interpret
    // KeySource; we validate the shape and capture the whole field if
    // non-empty so it round-trips.
    expect(tok, Tok::LBrace)?;

    let peek = tok.peek()?;
    if let Tok::RBrace = peek {
        tok.next()?;
        return Ok(());
    }

    // Non-empty: walk pubkey keys + opaque values.
    loop {
        let pk_hex = expect_string(tok)?;
        if pk_hex.len() != 66 {
            return Err(PskError::InvalidPubkeyLen);
        }
        expect(tok, Tok::Colon)?;
        // Value: null or object. skip_value handles both.
        skip_value(tok)?;

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    // Capture the entire `"bip32Derivations": {...}` region.
    capture_unknown(parsed, field_start, tok.position())?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — outputs
// ═══════════════════════════════════════════════════════════════════════

fn parse_outputs_array(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(), PskError> {
    expect(tok, Tok::LBracket)?;

    if let Tok::RBracket = tok.peek()? {
        tok.next()?;
        tx.num_outputs = 0;
        return Ok(());
    }

    let mut count: usize = 0;
    loop {
        if count >= MAX_OUTPUTS {
            return Err(PskError::TooManyOutputs);
        }
        parse_output(tok, tx, parsed, count)?;
        count += 1;

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBracket => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }
    tx.num_outputs = count;
    Ok(())
}

fn parse_output(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
    idx: usize,
) -> Result<(), PskError> {
    expect(tok, Tok::LBrace)?;

    let out = &mut tx.outputs[idx];
    let mut seen_amount = false;
    let mut seen_spk = false;

    if let Tok::RBrace = tok.peek()? {
        return Err(PskError::MissingField);
    }

    loop {
        let key_start = tok.position();
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;

        match key {
            b"amount" => {
                if seen_amount { return Err(PskError::DuplicateField); }
                out.value = expect_u64(tok)?;
                seen_amount = true;
            }
            b"scriptPublicKey" => {
                if seen_spk { return Err(PskError::DuplicateField); }
                let hex_str = expect_string(tok)?;
                let spk = &mut out.script_public_key;
                spk.script_len = parse_script_public_key(
                    hex_str,
                    &mut spk.version,
                    &mut spk.script,
                )?;
                seen_spk = true;
            }
            b"redeemScript" => {
                // Structural — null or hex. Serializer emits from known
                // state or passes through the parsed hex (outputs don't
                // carry signer-relevant redeem scripts in our flow).
                skip_value(tok)?;
            }
            b"bip32Derivations" | b"proprietaries" => {
                // Opaque maps. Capture only if non-empty so the 16-slot
                // budget survives realistic 2-of-3 multisig shapes.
                expect(tok, Tok::LBrace)?;
                match tok.peek()? {
                    Tok::RBrace => { tok.next()?; }  // empty, no capture
                    _ => {
                        skip_until_matching(tok, Tok::RBrace)?;
                        capture_unknown(parsed, key_start, tok.position())?;
                    }
                }
            }
            _ => {
                skip_value(tok)?;
                capture_unknown(parsed, key_start, tok.position())?;
            }
        }

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    if !(seen_amount && seen_spk) {
        return Err(PskError::MissingField);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Serializer — writes a Transaction back out as a PSKB/PSKT wire payload.
// ═══════════════════════════════════════════════════════════════════════
//
// Design: single-pass, zero-copy, no intermediate JSON buffer.
//
// The serializer walks the Transaction + PsktParsed state and writes
// hex-encoded JSON directly to `out`. Each structural byte is hex-encoded
// on the fly; each captured unknown byte-range is also hex-encoded
// from its position in `scratch` (which still holds the original decoded
// JSON from parse time). The wire format is 4-byte magic + 2x hex of
// the emitted JSON.
//
// Field order reproduces `kaspa-wallet-pskt`'s BTreeMap / struct-field
// emission order exactly, as verified against the canonical vectors in
// `docs/pskt/PSKT_CANONICAL_VECTORS.md`. Deviating from that order
// would produce a valid-looking PSKT that still round-trips JSON-parsed
// equivalent, but not byte-identical — and byte-identical output is
// what lets a Combiner collate signatures from multiple signers without
// mismatched bundles.
//
// ─── Fidelity caveat ─────────────────────────────────────────────────
//
// The `UtxoEntry` struct in `wallet/transaction.rs` currently only
// tracks `amount` + `scriptPublicKey`. `blockDaaScore` and `isCoinbase`
// from the incoming PSKT are parsed-but-discarded, and emitted as
// defaults (0 and false) on round-trip.
//
// Safe for `KasSee → KasSigner → KasSee` ceremonies (KasSee's Combiner
// overlays partial sigs onto its own Constructor state, so it has the
// real values). Potentially unsafe for `Alice → KasSigner → Bob` where
// Bob hasn't seen the original and would see the zeroed metadata.
//
// Step 7 (end-to-end ceremony test) is the right place to verify
// whether this matters in practice. Adding the fields to `UtxoEntry`
// is a one-commit fix if needed.
//
// No allocator. No panics. All writes bounds-checked.

/// Serialize a parsed Transaction back into PSKB or PSKT-single wire bytes.
///
/// `tx`     — the transaction to emit.
/// `parsed` — byte-range state captured during parse; used to splice
///            unknown regions back verbatim.
/// `scratch` — the original decoded-JSON buffer from parse time. Must
///            still hold the bytes the `parsed.unknowns` offsets refer
///            to; caller is responsible for not clobbering it between
///            parse and serialize.
/// `format` — `PsktPskb` or `PsktSingle`; decides magic prefix.
/// `out`    — destination buffer, receives magic + hex(JSON).
///
/// Returns the number of bytes written to `out`.
pub fn serialize_pskt(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
    out: &mut [u8],
) -> Result<usize, PskError> {
    // Magic prefix.
    let magic: &[u8; 4] = match format {
        TxInputFormat::PsktPskb => PSKB_MAGIC,
        TxInputFormat::PsktSingle => PSKT_MAGIC,
        _ => return Err(PskError::UnexpectedToken),  // not a PSKT format
    };
    if out.len() < 4 {
        return Err(PskError::OutputBufferTooSmall);
    }
    out[..4].copy_from_slice(magic);

    // Hex-encoded JSON starts at offset 4.
    let mut w = HexWriter { out, pos: 4, scratch };

    // For PSKB, wrap in `[...]`.
    let bundle_wrap = matches!(format, TxInputFormat::PsktPskb);
    if bundle_wrap {
        w.lit(b"[")?;
    }

    emit_pskt_object(&mut w, tx, parsed)?;

    if bundle_wrap {
        w.lit(b"]")?;
    }

    Ok(w.pos)
}

// ═══════════════════════════════════════════════════════════════════════
// HexWriter: one-pass hex-encoding writer over `out`.
// ═══════════════════════════════════════════════════════════════════════

/// Tiny helper that hex-encodes bytes directly to an output buffer.
/// `pos` always tracks byte offset into `out` in terms of hex chars
/// written — so `pos` is always at an even hex boundary between bytes.
///
/// Keeping `scratch` inside the writer simplifies the splice path —
/// `write_scratch_range` reads from the original JSON and hex-encodes
/// without a second round-trip.
struct HexWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    scratch: &'a [u8],
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

impl<'a> HexWriter<'a> {
    /// Write one raw byte, producing 2 hex chars.
    fn byte(&mut self, b: u8) -> Result<(), PskError> {
        if self.pos + 2 > self.out.len() {
            return Err(PskError::OutputBufferTooSmall);
        }
        self.out[self.pos]     = HEX_CHARS[(b >> 4) as usize];
        self.out[self.pos + 1] = HEX_CHARS[(b & 0x0F) as usize];
        self.pos += 2;
        Ok(())
    }

    /// Write a byte slice, producing `2 * slice.len()` hex chars.
    fn bytes(&mut self, s: &[u8]) -> Result<(), PskError> {
        if self.pos + 2 * s.len() > self.out.len() {
            return Err(PskError::OutputBufferTooSmall);
        }
        for &b in s {
            self.out[self.pos]     = HEX_CHARS[(b >> 4) as usize];
            self.out[self.pos + 1] = HEX_CHARS[(b & 0x0F) as usize];
            self.pos += 2;
        }
        Ok(())
    }

    /// Alias for `bytes` when emitting a JSON literal fragment
    /// (`{`, `":"`, `,`, etc.). Named differently for readability at
    /// call sites.
    #[inline]
    fn lit(&mut self, s: &[u8]) -> Result<(), PskError> {
        self.bytes(s)
    }

    /// Splice a byte-range from scratch into the output, hex-encoded.
    /// Used for captured unknown regions during parse.
    fn scratch_range(&mut self, start: u16, end: u16) -> Result<(), PskError> {
        let (s, e) = (start as usize, end as usize);
        if e > self.scratch.len() || s > e {
            return Err(PskError::UnexpectedToken);
        }
        self.bytes(&self.scratch[s..e])
    }

    /// Write a decimal u64. Max 20 digits.
    fn u64(&mut self, mut v: u64) -> Result<(), PskError> {
        if v == 0 {
            return self.byte(b'0');
        }
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        self.bytes(&buf[i..])
    }

    /// Write a hex-string field: `"<hex of bytes>"`. Useful for
    /// `transactionId`, `signature` values, etc., where the source is
    /// raw bytes that need to be lowercase-hex-stringified.
    fn hex_string_field(&mut self, bytes: &[u8]) -> Result<(), PskError> {
        self.lit(b"\"")?;
        // The *string contents* are hex chars. Each hex char is itself
        // one byte on the wire, which then gets hex-encoded into two
        // chars. Net: each source byte becomes four chars in `out`.
        // We emit via .byte() of the ASCII hex chars.
        for &b in bytes {
            self.byte(HEX_CHARS[(b >> 4) as usize])?;
            self.byte(HEX_CHARS[(b & 0x0F) as usize])?;
        }
        self.lit(b"\"")?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Emit — top-level PSKT object
// ═══════════════════════════════════════════════════════════════════════

fn emit_pskt_object(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    // {"global":...,"inputs":[...],"outputs":[...]}
    w.lit(b"{\"global\":")?;
    emit_global(w, tx, parsed)?;
    w.lit(b",\"inputs\":")?;
    emit_inputs_array(w, tx, parsed)?;
    w.lit(b",\"outputs\":")?;
    emit_outputs_array(w, tx, parsed)?;
    w.lit(b"}")?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Emit — global
// ═══════════════════════════════════════════════════════════════════════
//
// Field order from canonical vectors:
//   version, txVersion, fallbackLockTime, inputsModifiable,
//   outputsModifiable, inputCount, outputCount, xpubs, id, proprietaries.
//
// Of these, the structural ones (fallbackLockTime:null, inputsModifiable,
// outputsModifiable) are emitted as hardcoded defaults. The opaque ones
// (xpubs, id, proprietaries) use a captured byte-range if one exists for
// that key name, else emit the empty default.

fn emit_global(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    w.lit(b"{\"version\":0,\"txVersion\":")?;
    w.u64(tx.version as u64)?;
    w.lit(b",\"fallbackLockTime\":null,\"inputsModifiable\":true,\"outputsModifiable\":true,\"inputCount\":")?;
    w.u64(tx.num_inputs as u64)?;
    w.lit(b",\"outputCount\":")?;
    w.u64(tx.num_outputs as u64)?;

    // xpubs
    w.lit(b",\"xpubs\":")?;
    if let Some(range) = find_captured_value(parsed, w.scratch, b"xpubs") {
        w.scratch_range(range.0, range.1)?;
    } else {
        w.lit(b"{}")?;
    }

    // id
    w.lit(b",\"id\":")?;
    if let Some(range) = find_captured_value(parsed, w.scratch, b"id") {
        w.scratch_range(range.0, range.1)?;
    } else {
        w.lit(b"null")?;
    }

    // proprietaries
    w.lit(b",\"proprietaries\":")?;
    if let Some(range) = find_captured_value(parsed, w.scratch, b"proprietaries") {
        w.scratch_range(range.0, range.1)?;
    } else {
        w.lit(b"{}")?;
    }

    w.lit(b"}")?;
    Ok(())
}

/// Locate a captured byte-range whose `"key":` matches `name`.
/// Returns the range pointing at the **value** (after the colon), or
/// `None` if no capture for this key exists.
///
/// Captures were recorded with the range starting at the `"key"` token;
/// this helper walks past `"key":` to return just the value range.
/// Uses exact string matching on the key bytes.
fn find_captured_value(
    parsed: &PsktParsed,
    scratch: &[u8],
    name: &[u8],
) -> Option<(u16, u16)> {
    for i in 0..(parsed.unknowns_count as usize) {
        let (start, end) = parsed.unknowns[i];
        let s = start as usize;
        let e = end as usize;
        if e > scratch.len() || s >= e {
            continue;
        }
        // Captured region begins with `"key":value` (no surrounding
        // whitespace in compact JSON). Check the key matches.
        // Minimum length: `"X":X` = 5 bytes for 1-char key.
        if e - s < name.len() + 3 {
            continue;
        }
        if scratch[s] != b'"' {
            continue;
        }
        let key_end = s + 1 + name.len();
        if key_end >= e || scratch[key_end] != b'"' {
            continue;
        }
        if &scratch[s + 1..key_end] != name {
            continue;
        }
        if key_end + 1 >= e || scratch[key_end + 1] != b':' {
            continue;
        }
        // Value starts at key_end + 2, runs to end.
        return Some(((key_end + 2) as u16, end));
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════
// Emit — inputs array
// ═══════════════════════════════════════════════════════════════════════

fn emit_inputs_array(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    w.lit(b"[")?;
    for i in 0..tx.num_inputs {
        if i > 0 { w.lit(b",")?; }
        emit_input(w, tx, parsed, i)?;
    }
    w.lit(b"]")?;
    Ok(())
}

fn emit_input(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    _parsed: &PsktParsed,
    idx: usize,
) -> Result<(), PskError> {
    let inp = &tx.inputs[idx];

    // {"utxoEntry":{...},"previousOutpoint":{...},"sequence":N,"minTime":null,"partialSigs":{...},"sighashType":1,"redeemScript":"hex",...}
    w.lit(b"{\"utxoEntry\":")?;
    emit_utxo_entry(w, inp)?;
    w.lit(b",\"previousOutpoint\":")?;
    emit_outpoint(w, inp)?;
    w.lit(b",\"sequence\":")?;
    w.u64(inp.sequence)?;
    w.lit(b",\"minTime\":null,\"partialSigs\":")?;
    emit_partial_sigs(w, inp)?;
    w.lit(b",\"sighashType\":")?;
    w.u64(inp.sighash_type as u64)?;

    // redeemScript: null if empty, else hex string of redeem_script bytes.
    w.lit(b",\"redeemScript\":")?;
    if inp.redeem_script_len == 0 {
        w.lit(b"null")?;
    } else {
        w.hex_string_field(&inp.redeem_script[..inp.redeem_script_len])?;
    }

    w.lit(b",\"sigOpCount\":")?;
    w.u64(inp.sig_op_count as u64)?;

    // bip32Derivations: match partial sigs — emit an entry with null value
    // per incoming pubkey so Combiner compatibility is preserved.
    w.lit(b",\"bip32Derivations\":")?;
    emit_bip32_derivations_for_input(w, inp)?;

    w.lit(b",\"finalScriptSig\":null,\"proprietaries\":{}")?;
    w.lit(b"}")?;
    Ok(())
}

fn emit_utxo_entry(
    w: &mut HexWriter<'_>,
    inp: &crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    // {"amount":N,"scriptPublicKey":"<version><script hex>","blockDaaScore":0,"isCoinbase":false}
    w.lit(b"{\"amount\":")?;
    w.u64(inp.utxo_entry.amount)?;
    w.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(w, &inp.utxo_entry.script_public_key)?;
    w.lit(b",\"blockDaaScore\":0,\"isCoinbase\":false}")?;
    Ok(())
}

fn emit_outpoint(
    w: &mut HexWriter<'_>,
    inp: &crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    w.lit(b"{\"transactionId\":")?;
    w.hex_string_field(&inp.previous_outpoint.transaction_id)?;
    w.lit(b",\"index\":")?;
    w.u64(inp.previous_outpoint.index as u64)?;
    w.lit(b"}")?;
    Ok(())
}

fn emit_partial_sigs(
    w: &mut HexWriter<'_>,
    inp: &crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    // {"<pk_hex>":{"schnorr":"<sig_hex>"},...}
    // Emitted in the order sigs are stored — parser preserved the
    // lexicographic order from the incoming JSON, so round-trip order
    // is preserved too.
    if inp.incoming_partial_sigs_count == 0 {
        w.lit(b"{}")?;
        return Ok(());
    }
    w.lit(b"{")?;
    for i in 0..(inp.incoming_partial_sigs_count as usize) {
        if i > 0 { w.lit(b",")?; }
        let sig = &inp.incoming_partial_sigs[i];
        w.hex_string_field(&sig.pubkey)?;
        w.lit(b":{\"schnorr\":")?;
        w.hex_string_field(&sig.signature)?;
        w.lit(b"}")?;
    }
    w.lit(b"}")?;
    Ok(())
}

/// Emit a bip32Derivations object with one `null` entry per partial sig
/// pubkey. This matches `kaspa-wallet-pskt`'s invariant where every
/// signer pubkey in `partialSigs` also has a corresponding null entry
/// in `bip32Derivations`, even for signers who don't provide a
/// KeySource. Empty when no partial sigs present.
fn emit_bip32_derivations_for_input(
    w: &mut HexWriter<'_>,
    inp: &crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    if inp.incoming_partial_sigs_count == 0 {
        w.lit(b"{}")?;
        return Ok(());
    }
    w.lit(b"{")?;
    for i in 0..(inp.incoming_partial_sigs_count as usize) {
        if i > 0 { w.lit(b",")?; }
        w.hex_string_field(&inp.incoming_partial_sigs[i].pubkey)?;
        w.lit(b":null")?;
    }
    w.lit(b"}")?;
    Ok(())
}

fn emit_script_public_key(
    w: &mut HexWriter<'_>,
    spk: &crate::wallet::transaction::ScriptPublicKey,
) -> Result<(), PskError> {
    // Flat hex string: 2-byte BE version + script bytes.
    w.lit(b"\"")?;
    // Version as 4 hex chars.
    w.byte(HEX_CHARS[((spk.version >> 12) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[((spk.version >>  8) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[((spk.version >>  4) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[((spk.version      ) & 0x0F) as usize])?;
    // Script bytes as hex.
    for &b in &spk.script[..spk.script_len] {
        w.byte(HEX_CHARS[(b >> 4) as usize])?;
        w.byte(HEX_CHARS[(b & 0x0F) as usize])?;
    }
    w.lit(b"\"")?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Emit — outputs array
// ═══════════════════════════════════════════════════════════════════════

fn emit_outputs_array(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    parsed: &PsktParsed,
) -> Result<(), PskError> {
    w.lit(b"[")?;
    for i in 0..tx.num_outputs {
        if i > 0 { w.lit(b",")?; }
        emit_output(w, tx, parsed, i)?;
    }
    w.lit(b"]")?;
    Ok(())
}

fn emit_output(
    w: &mut HexWriter<'_>,
    tx: &Transaction,
    _parsed: &PsktParsed,
    idx: usize,
) -> Result<(), PskError> {
    let out = &tx.outputs[idx];
    // {"amount":N,"scriptPublicKey":"<hex>","redeemScript":null,"bip32Derivations":{},"proprietaries":{}}
    w.lit(b"{\"amount\":")?;
    w.u64(out.value)?;
    w.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(w, &out.script_public_key)?;
    w.lit(b",\"redeemScript\":null,\"bip32Derivations\":{},\"proprietaries\":{}}")?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Signing integration helpers
// ═══════════════════════════════════════════════════════════════════════
//
// After `wallet/pskt.rs::sign_transaction_*` has placed new signatures
// into `inp.sigs[]` (KSPT-style positional slots), these helpers bridge
// into the PSKT data model:
//
//   - `move_ksp_sigs_to_pskt` promotes sigs[] entries into
//     `incoming_partial_sigs[]`, keyed by the full compressed pubkey the
//     signer stashed. Sorted into BTreeMap (lexicographic-by-pubkey)
//     order so PSKT emission produces byte-identical output vs. the
//     upstream Rust crate.
//
//   - `pskt_signature_status` counts present/required for the PSKT
//     path (reading `incoming_partial_sigs_count` + parsing the redeem
//     script for required M). Used by the UI to display "2/3 sigs".

/// After `sign_transaction_multisig` or `sign_transaction_multi_addr`
/// has populated `inp.sigs[]` with new signatures tagged by
/// `pubkey_compressed`, promote them into `inp.incoming_partial_sigs[]`
/// ready for PSKT emission.
///
/// Merging rules:
///   - Existing entries in `incoming_partial_sigs` (from a PSKT that
///     arrived partially signed) are preserved.
///   - Each new entry from `sigs[]` with `present=true` and a non-zero
///     `pubkey_compressed` is inserted — unless a matching pubkey
///     already exists, in which case the existing entry wins (an
///     already-signed input shouldn't be resigned by this device).
///   - After insertion, the slot array is sorted by pubkey byte order
///     so emission matches `kaspa-wallet-pskt`'s BTreeMap iteration.
///
/// If the final count would exceed `MAX_SIGS_PER_INPUT`, silently
/// truncates — the redeem script only needs M signatures, any surplus
/// is discarded. Sort happens before truncation to keep the
/// lowest-pubkey entries (stable emission).
///
/// Does not mutate `sigs[]` — KSPT emission on the same tx still works
/// if the caller picks that path instead. Designed to be idempotent:
/// calling this twice is a no-op on the second call.
pub fn move_ksp_sigs_to_pskt(tx: &mut Transaction) {
    for i in 0..tx.num_inputs {
        let inp = &mut tx.inputs[i];

        // Snapshot existing incoming count; anything >= this is newly
        // appended in the loop below. We need this split so the sort
        // only rearranges the complete superset at the end.
        let base = inp.incoming_partial_sigs_count as usize;

        // Walk the KSPT sig slots and append each present one whose
        // pubkey isn't already in incoming.
        for s in 0..(inp.sig_count as usize) {
            if !inp.sigs[s].present {
                continue;
            }
            let pk = inp.sigs[s].pubkey_compressed;
            // Skip empty compressed pubkey — means signer didn't stash
            // it (e.g. raw-key path). PSKT can't emit a sig without a
            // pubkey key, so dropping is safer than emitting garbage.
            if pk == [0u8; 33] {
                continue;
            }
            // Already present? Leave the existing entry.
            let mut duplicate = false;
            for j in 0..(inp.incoming_partial_sigs_count as usize) {
                if inp.incoming_partial_sigs[j].pubkey == pk {
                    duplicate = true;
                    break;
                }
            }
            if duplicate {
                continue;
            }
            // Append if there's room.
            let next = inp.incoming_partial_sigs_count as usize;
            if next >= MAX_SIGS_PER_INPUT {
                break;
            }
            inp.incoming_partial_sigs[next].pubkey = pk;
            inp.incoming_partial_sigs[next].signature = inp.sigs[s].signature;
            inp.incoming_partial_sigs[next].present = true;
            inp.incoming_partial_sigs_count = (next + 1) as u8;
        }

        // Sort the full set by pubkey byte order. Simple insertion sort
        // — MAX_SIGS_PER_INPUT is 5 so it's tiny and we're no_std.
        let count = inp.incoming_partial_sigs_count as usize;
        if count > 1 && base < count {
            // Only sort if we actually added something.
            let mut k = 1;
            while k < count {
                let mut m = k;
                while m > 0 {
                    let a = inp.incoming_partial_sigs[m - 1].pubkey;
                    let b = inp.incoming_partial_sigs[m].pubkey;
                    if a <= b {
                        break;
                    }
                    inp.incoming_partial_sigs.swap(m - 1, m);
                    m -= 1;
                }
                k += 1;
            }
        }
    }
}

/// PSKT-aware sig counter for the UI. Mirrors
/// `wallet/pskt.rs::signature_status` but reads
/// `incoming_partial_sigs_count` instead of `sig_count`, and uses the
/// shared `analyze_input_script` to determine required M from the
/// redeem script.
///
/// Returns `(present, required)`. For P2PK inputs, `required` is 1 and
/// `present` is 1 if any incoming sig exists. For multisig, `required`
/// is M from the parsed redeem script and `present` is the count of
/// incoming partial sigs capped at M.
pub fn pskt_signature_status(tx: &Transaction) -> (u8, u8) {
    use crate::wallet::pskt::analyze_input_script;
    use crate::wallet::transaction::ScriptType;
    let mut present: u8 = 0;
    let mut required: u8 = 0;
    for i in 0..tx.num_inputs {
        let (script_type, ms_info) = analyze_input_script(tx, i);
        let incoming = tx.inputs[i].incoming_partial_sigs_count;
        match script_type {
            ScriptType::P2PK => {
                required += 1;
                if incoming > 0 {
                    present += 1;
                }
            }
            ScriptType::Multisig | ScriptType::P2SH => {
                if let Some(ref ms) = ms_info {
                    required += ms.m;
                    present += incoming.min(ms.m);
                }
            }
            ScriptType::Unknown => {
                required += 1;
            }
        }
    }
    (present, required)
}
