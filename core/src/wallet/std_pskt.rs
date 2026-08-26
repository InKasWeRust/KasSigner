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

use crate::types::{TxInputFormat, PsktParsed, MAX_PSKT_UNKNOWN_REGIONS};
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
///     (populated in Step 2/3.)
///   - Semantic:       invalid sighash, invalid version, ECDSA rejected,
///     too many inputs/outputs/sigs, etc.
///     (populated in Step 3.)
///   - Output:         buffer too small, scratch too small.
///     (populated in Step 5.)
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
    /// An input amount or output value above `MAX_SOMPI`, or a total that is.
    ///
    /// Same consensus rule the KSPT parser applies (see
    /// `pskt::PsktError::ValueOutOfRange`): rusty-kaspa 2.0.1 refuses both a
    /// single value and a running total above 29e9 KAS in sompi. Checked here
    /// because the review screen sums these and the release profile traps on
    /// overflow, so an unbounded value is a panic waiting on a hostile
    /// payload.
    ValueOutOfRange,

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
    /// `covenantBinding` was present but malformed: wrong `covenantId`
    /// length or hex, `authorizingInput` out of range or naming an input
    /// that does not exist, a repeated or missing member, an unknown
    /// member, or a non-object value. Deliberately one variant for all of
    /// them: the screen is the only channel in a production build, and a
    /// user cannot act differently on the distinction.
    InvalidCovenantBinding,
    /// Bundle had more than one PSKT element (unsupported by KasSigner).
    BundleMultiElement,

    // ─── Output / Serialize (Step 5) ──────────────────────────────
    /// Output buffer too small for the serialized payload.
    OutputBufferTooSmall,
}

impl PskError {
    /// Two short lines for `draw_tx_error_screen`: what went wrong, and what
    /// the user can do about it.
    ///
    /// Every variant used to render as "Too many UTXOs" / "Consolidate
    /// first". The error was matched at the call site, logged, and thrown
    /// away. In a `production` build `log!` compiles out, so the screen is
    /// the only channel and it was saying something false: a bundle rejected
    /// for carrying an ECDSA signature advised consolidating UTXOs, with no
    /// way for the user to learn the real cause.
    ///
    /// Two lines of roughly 22 and 30 characters, which is what the screen
    /// renders without truncation at title and body sizes.
    pub fn screen_text(&self) -> (&'static str, &'static str) {
        match self {
            // ─── Envelope: not what it claims to be ───
            PskError::TooShort            => ("Bundle too short", "Truncated in transit"),
            PskError::BadMagic            => ("Not a PSKT bundle", "Wrong format scanned"),
            PskError::TruncatedEnvelope   => ("Bundle truncated", "Rescan all frames"),
            PskError::OddHexLength        => ("Malformed bundle", "Odd hex length"),
            PskError::BadHexChar          => ("Malformed bundle", "Bad hex character"),

            // ─── Capacity: real limits, and the user can act on them ───
            PskError::ScratchBufferTooSmall => ("Bundle too large", "Split the transaction"),
            PskError::OutputBufferTooSmall  => ("Result too large", "Split the transaction"),
            PskError::TooManyInputs       => ("Too many UTXOs", "Consolidate first"),
            PskError::TooManyOutputs      => ("Too many outputs", "Split the transaction"),
            PskError::TooManyPartialSigs  => ("Too many signatures", "Bundle already full"),
            PskError::TooManyUnknownRegions => ("Too many unknown fields", "Wallet not supported"),
            PskError::ValueOutOfRange     => ("Amount out of range", "Above the total supply"),

            // ─── Structure: the sender built it wrong ───
            PskError::UnexpectedToken     => ("Malformed bundle", "Unexpected JSON token"),
            PskError::MissingField        => ("Incomplete bundle", "A field is missing"),
            PskError::DuplicateField      => ("Malformed bundle", "Duplicate field"),
            PskError::CountMismatch       => ("Inconsistent bundle", "Declared count is wrong"),
            PskError::InvalidCovenantBinding => ("Bad covenant binding", "Malformed or incomplete"),
            PskError::BundleMultiElement  => ("Multi-bundle scanned", "Send one at a time"),
            PskError::VersionNotSupported => ("Unsupported version", "Update this firmware"),

            // ─── Field shape ───
            PskError::InvalidPubkeyLen    => ("Bad public key", "Wrong key length"),
            PskError::InvalidScriptLen    => ("Bad script length", "Script does not fit"),
            PskError::ShortScriptPubkey   => ("Bad output script", "Script too short"),

            // ─── Consensus-relevant. These two most needed saying. ───
            // A sighash type this firmware will not sign is PSBT's
            // best-documented vulnerability class, and Kaspa standard
            // addresses are Schnorr, so an ECDSA signature cannot be merged
            // into a script this device can finalise.
            PskError::InvalidSighashType   => ("Unsupported sighash", "This wallet signs ALL only"),
            PskError::InvalidSignatureType => ("ECDSA not supported", "Kaspa uses Schnorr here"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Envelope detection
// ═══════════════════════════════════════════════════════════════════════

/// Magic prefix for PSKB (bundle of PSKTs) wire payloads.
///
/// The only PSKT interchange envelope. rusty-kaspa's `wallet/pskt`
/// serializes a bundle as `"PSKB" + hex(json array)` and accepts nothing
/// else; a `PSKT`-prefixed single-object form once declared here had no
/// emitter anywhere and was rejected by `parse_pskt` (which always expects
/// the bundle array), so it was removed in 1.0.7.
pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";

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

    DetectedFormat::Unknown
}

/// Strip the 4-byte magic prefix from a PSKT-shaped payload and return
/// the inner hex bytes, or an error if the payload isn't PSKT or is
/// truncated.
///
/// Use when you've already committed to a PSKT branch (e.g. after
/// `detect_tx_format` returned `PsktPskb`) and want the remaining hex
/// body to feed into `hex_decode_strict`.
///
/// An empty body is rejected — a zero-length hex payload can't encode
/// a valid JSON bundle.
pub fn strip_pskt_magic(data: &[u8]) -> Result<&[u8], PskError> {
    if data.len() < 4 {
        return Err(PskError::TooShort);
    }
    let magic = &data[..4];
    if magic != PSKB_MAGIC {
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

/// Mark a known field as seen. Returns `false` if it was already set, i.e.
/// the bundle repeats a key.
///
/// A `u16` bitmask rather than one `bool` per key: `parse_input` alone
/// carries eleven known fields, and the flags are only ever set and tested.
#[inline]
fn mark(bits: &mut u16, flag: u16) -> bool {
    if *bits & flag != 0 {
        return false;
    }
    *bits |= flag;
    true
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

    /// The bytes being tokenized. Needed to re-read a value region the
    /// tokenizer has already walked past, which is how the 45' derivation hint
    /// is lifted out of a KeySource without a second parser for it.
    pub fn source(&self) -> &'a [u8] {
        self.data
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

    tx.clear();

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
/// been consumed, with `close` naming the delimiter that opener expects.
///
/// Tracks the expected closer at every level rather than counting depth.
/// A single counter treats `}` and `]` as interchangeable, so `{"a":[1}]`
/// balances to zero and is accepted, which is not valid JSON. These are
/// regions the parser does not interpret, but it re-emits their bytes
/// verbatim, so accepting one means signing a bundle the next wallet in
/// the chain will reject.
fn skip_until_matching(tok: &mut Tokenizer<'_>, close: Tok<'_>) -> Result<(), PskError> {
    /// Deepest nesting accepted inside a skipped region. Real PSKT
    /// nesting is five levels (bundle, element, inputs, input,
    /// utxoEntry), so this is a wide margin that still bounds the
    /// stack.
    const MAX_DEPTH: usize = 32;

    // One byte per open delimiter: `false` expects `}`, `true` expects `]`.
    let mut expect_bracket = [false; MAX_DEPTH];
    expect_bracket[0] = match close {
        Tok::RBrace => false,
        Tok::RBracket => true,
        // Only the two callers above construct this, and both pass a
        // closing delimiter. Anything else is a programming error.
        _ => return Err(PskError::UnexpectedToken),
    };
    let mut depth: usize = 1;

    loop {
        match tok.next()? {
            Tok::LBrace => {
                if depth >= MAX_DEPTH {
                    return Err(PskError::UnexpectedToken);
                }
                expect_bracket[depth] = false;
                depth += 1;
            }
            Tok::LBracket => {
                if depth >= MAX_DEPTH {
                    return Err(PskError::UnexpectedToken);
                }
                expect_bracket[depth] = true;
                depth += 1;
            }
            Tok::RBrace => {
                depth -= 1;
                if expect_bracket[depth] {
                    // Opened with `[`, closed with `}`.
                    return Err(PskError::UnexpectedToken);
                }
                if depth == 0 {
                    return Ok(());
                }
            }
            Tok::RBracket => {
                depth -= 1;
                if !expect_bracket[depth] {
                    // Opened with `{`, closed with `]`.
                    return Err(PskError::UnexpectedToken);
                }
                if depth == 0 {
                    return Ok(());
                }
            }
            Tok::Eof => return Err(PskError::TruncatedEnvelope),
            _ => { /* strings, numbers, literals inside — ignore */ }
        }
    }
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

    // Declared counts from `global`. Checked against the parsed array
    // lengths after the loop, because JSON member order is not fixed:
    // `global` may legally appear after `inputs` and `outputs`.
    let mut declared_input_count: usize = 0;
    let mut declared_output_count: usize = 0;

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
                let (n_in, n_out) = parse_global(tok, tx, parsed)?;
                declared_input_count = n_in;
                declared_output_count = n_out;
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
    //
    // Deferred to here rather than checked inside `parse_global`: JSON
    // member order is not fixed, so `global` may legally precede or follow
    // the arrays, and `tx.num_inputs` is only reliable once all three
    // top-level fields have been seen.
    // A zero count is "unset", not a claim of emptiness. `inputCount` and
    // `outputCount` are Creator-role bookkeeping upstream and the
    // Constructor does not maintain them as inputs are added, so a bundle
    // straight from the reference library carries 0 alongside populated
    // arrays (their own committed fixture,
    // `wallet/pskt/src/wasm/bundle.rs:229`, does exactly that). The
    // signature covers neither field. Rejecting on them refused normal
    // reference output until 1.0.7; the check still holds whenever a
    // non-zero count is stated.
    if (declared_input_count != 0 && declared_input_count != tx.num_inputs)
        || (declared_output_count != 0 && declared_output_count != tx.num_outputs)
    {
        return Err(PskError::CountMismatch);
    }

    // A covenant binding names the input that authorises it. Upstream
    // rejects an index with no matching input
    // (`crypto/txscript/src/covenants.rs`, `AuthInputOutOfBounds`), so the
    // device must not sign one. Deferred here for the same reason as the
    // counts: an output may be parsed before `inputs` has been seen.
    for i in 0..tx.num_outputs {
        let o = &tx.outputs[i];
        if o.has_covenant && (o.covenant_auth_input as usize) >= tx.num_inputs {
            return Err(PskError::InvalidCovenantBinding);
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Parser — global
// ═══════════════════════════════════════════════════════════════════════

/// Returns the declared `(inputCount, outputCount)` so the caller can check
/// them against the parsed array lengths once all three top-level fields have
/// been seen. Both are bounded by MAX_INPUTS / MAX_OUTPUTS here.
fn parse_global(
    tok: &mut Tokenizer<'_>,
    tx: &mut Transaction,
    parsed: &mut PsktParsed,
) -> Result<(usize, usize), PskError> {
    expect(tok, Tok::LBrace)?;

    // Most global fields are required; some are always-present but we
    // don't need to interpret them (xpubs, id, proprietaries,
    // fallbackLockTime). We still validate presence by reading them.
    let mut seen_version = false;
    let mut seen_tx_version = false;
    let mut seen_input_count = false;
    let mut seen_output_count = false;
    let mut declared_input_count: usize = 0;
    let mut declared_output_count: usize = 0;

    const S_FALLBACK: u16 = 1 << 0;
    const S_INMOD: u16 = 1 << 1;
    const S_OUTMOD: u16 = 1 << 2;
    const S_XPUBS: u16 = 1 << 3;
    const S_PROPRIETARIES: u16 = 1 << 4;
    const S_ID: u16 = 1 << 5;
    let mut seen_opt: u16 = 0;

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
                // Compare in u64. `n as usize` would narrow on a 32-bit
                // target and let a value above u32::MAX past the bound.
                if n > MAX_INPUTS as u64 {
                    return Err(PskError::TooManyInputs);
                }
                // Bounded by MAX_INPUTS (32) above, so the cast is exact.
                declared_input_count = n as usize;
                seen_input_count = true;
            }
            b"outputCount" => {
                if seen_output_count { return Err(PskError::DuplicateField); }
                let n = expect_u64(tok)?;
                if n > MAX_OUTPUTS as u64 {
                    return Err(PskError::TooManyOutputs);
                }
                // Bounded by MAX_OUTPUTS (8) above, so the cast is exact.
                declared_output_count = n as usize;
                seen_output_count = true;
            }
            // ── Structural fields: shape is fixed, serializer reconstructs
            //    from known state. No capture needed.
            b"fallbackLockTime" | b"inputsModifiable" | b"outputsModifiable" => {
                let flag = match key {
                    b"fallbackLockTime" => S_FALLBACK,
                    b"inputsModifiable" => S_INMOD,
                    _ => S_OUTMOD,
                };
                if !mark(&mut seen_opt, flag) {
                    return Err(PskError::DuplicateField);
                }
                skip_value(tok)?;
            }
            // ── Opaque fields: may carry content the serializer can't
            //    reconstruct. Capture only if non-default so a realistic
            //    2-of-3 multisig PSKT survives the 16-slot budget.
            b"xpubs" | b"proprietaries" => {
                let flag = if key == b"xpubs" { S_XPUBS } else { S_PROPRIETARIES };
                if !mark(&mut seen_opt, flag) {
                    return Err(PskError::DuplicateField);
                }
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
                if !mark(&mut seen_opt, S_ID) {
                    return Err(PskError::DuplicateField);
                }
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
    Ok((declared_input_count, declared_output_count))
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

    // Optional fields. Required ones keep their own bools above; these are
    // the eight that previously took the last occurrence silently.
    const S_SEQUENCE: u16 = 1 << 0;
    const S_REDEEM: u16 = 1 << 1;
    const S_SIGOP: u16 = 1 << 2;
    const S_PARTIALSIGS: u16 = 1 << 3;
    const S_BIP32: u16 = 1 << 4;
    const S_MINTIME: u16 = 1 << 5;
    const S_FINALSIG: u16 = 1 << 6;
    const S_PROPRIETARIES: u16 = 1 << 7;
    let mut seen_opt: u16 = 0;

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
                if !mark(&mut seen_opt, S_SEQUENCE) {
                    return Err(PskError::DuplicateField);
                }
                // `Option<u64>` upstream: `null` and an omitted field both
                // mean unset, and unset is the final sequence number
                // (`wallet/pskt/src/input.rs:25`). Their signer hashes
                // `sequence.unwrap_or(u64::MAX)` (`pskt.rs:146`), so MAX is
                // the value the counterparty signed against; filling 0 here,
                // which is what an omitted field silently did until 1.0.7,
                // produced a signature their broadcaster rejects. An
                // explicit value is signed exactly as given, whatever it is.
                match tok.peek()? {
                    Tok::Null => { tok.next()?; inp.sequence = u64::MAX; }
                    _ => inp.sequence = expect_u64(tok)?,
                }
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
                if !mark(&mut seen_opt, S_REDEEM) {
                    return Err(PskError::DuplicateField);
                }
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
                if !mark(&mut seen_opt, S_SIGOP) {
                    return Err(PskError::DuplicateField);
                }
                let n = expect_u64(tok)?;
                if n > MAX_SIGS_PER_INPUT as u64 {
                    return Err(PskError::TooManyPartialSigs);
                }
                inp.sig_op_count = n as u8;
            }
            b"partialSigs" => {
                // Guarded for a second reason: `parse_partial_sigs` writes
                // from slot 0 and resets the count, so a repeat silently
                // discards the first set.
                if !mark(&mut seen_opt, S_PARTIALSIGS) {
                    return Err(PskError::DuplicateField);
                }
                parse_partial_sigs(tok, inp)?;
            }
            b"bip32Derivations" => {
                // Guarded for a second reason: a repeat burns another
                // `capture_unknown` slot from the 16-slot budget, and
                // `find_captured_value` returns the first match, so the
                // second capture is stored and never emitted.
                if !mark(&mut seen_opt, S_BIP32) {
                    return Err(PskError::DuplicateField);
                }
                // Capture so non-empty maps round-trip, AND pull the 45'
                // derivation path out of the first KeySource that has one.
                parse_bip32_derivations(tok, parsed, key_start, inp)?;
            }
            // Always-present structural fields (null by default). The
            // serializer reconstructs them from known state.
            //
            // One arm per key rather than the shared arm they used to have:
            // `{"minTime":null,"finalScriptSig":null}` is the normal shape,
            // and a single flag covering both would reject it.
            b"minTime" => {
                if !mark(&mut seen_opt, S_MINTIME) {
                    return Err(PskError::DuplicateField);
                }
                // The transaction's lock time is the largest `minTime` over
                // the inputs, 0 when none states one
                // (`wallet/pskt/src/pskt.rs:172`, `determine_lock_time`).
                // `fallbackLockTime` is NOT consulted for a bundle that has
                // inputs: `.max()` over `Option<u64>` items yields
                // `Option<Option<u64>>` and the outer `unwrap_or` fires only
                // on an empty input list, so it is dead for anything
                // signable. Skipped entirely until 1.0.7, which made the
                // device sign locktime 0 while their extractor built the
                // requested value: a signature that could not broadcast, and
                // a lock time silently dropped from the review screen.
                match tok.peek()? {
                    Tok::Null => { tok.next()?; }
                    _ => {
                        let t = expect_u64(tok)?;
                        if t > tx.locktime { tx.locktime = t; }
                    }
                }
            }
            b"finalScriptSig" => {
                if !mark(&mut seen_opt, S_FINALSIG) {
                    return Err(PskError::DuplicateField);
                }
                skip_value(tok)?;
            }
            b"proprietaries" => {
                if !mark(&mut seen_opt, S_PROPRIETARIES) {
                    return Err(PskError::DuplicateField);
                }
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

    // An omitted `sequence` is the same "unset" as an explicit `null`, and
    // means the same thing: the final sequence number. Until 1.0.7 the
    // omitted spelling silently kept the zero-initialised 0 while the
    // `null` spelling was refused, so two spellings of one state had two
    // different outcomes and neither matched the reference.
    if seen_opt & S_SEQUENCE == 0 {
        tx.inputs[idx].sequence = u64::MAX;
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
    let mut seen_covenant = false;

    loop {
        let key = expect_string(tok)?;
        expect(tok, Tok::Colon)?;
        match key {
            b"amount" => {
                if seen_amount { return Err(PskError::DuplicateField); }
                let amount = expect_u64(tok)?;
                if amount > crate::wallet::pskt::MAX_SOMPI {
                    return Err(PskError::ValueOutOfRange);
                }
                inp.utxo_entry.amount = amount;
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
            b"covenantId" => {
                if seen_covenant { return Err(PskError::DuplicateField); }
                // `null` when the coin carries no covenant, a 64-character
                // lowercase hex string when it does. Validated as strictly as
                // the output binding: a value the device cannot decode is a
                // value it must not display.
                match tok.next()? {
                    Tok::Null => {
                        inp.utxo_entry.has_covenant = false;
                    }
                    Tok::Str(hex_str) => {
                        if hex_str.len() != 64 {
                            return Err(PskError::InvalidCovenantBinding);
                        }
                        hex_decode_strict(hex_str, &mut inp.utxo_entry.covenant_id)
                            .map_err(|_| PskError::InvalidCovenantBinding)?;
                        inp.utxo_entry.has_covenant = true;
                    }
                    _ => return Err(PskError::InvalidCovenantBinding),
                }
                seen_covenant = true;
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

/// Parse `bip32Derivations` and, as a side effect, extract the 45' hint.
///
/// The object is `{ pubkey_hex: null-or-KeySource }`. The shape is validated
/// and the whole field captured so it round-trips byte-for-byte, exactly as
/// before. What is new is that a `derivationPath` string is read out of the
/// first KeySource that carries one, into `inp.ms45_hint`.
///
/// **The FIRST is enough, and taking it is not a shortcut.** On a 45' multisig
/// input every cosigner derives at the same
/// `m/45'/111111'/account'/cosigner/chain/index`: the path belongs to the
/// address being spent, and the entries differ only by pubkey and fingerprint.
/// So any entry yields the same three trailing components.
///
/// Nothing here trusts the value. It is a search index; the signer must still
/// derive at that path and confirm the pubkey appears in the input's redeem
/// script before signing.
/// Pull `cosigner/chain/index` out of a KeySource's `derivationPath`.
///
/// Reads the region `[start, end)`, which `skip_value` has already validated as
/// well-formed JSON, looks for `"derivationPath"`, and takes the LAST THREE
/// slash-separated components of its value. A 45' path is
/// `m/45'/111111'/account'/cosigner/chain/index`, and only those three vary per
/// address; the account prefix is fixed by our own derivation.
///
/// Returns `None` for anything that is not a usable 45' path: a `null` value, a
/// missing field, a hardened final component (a `'` anywhere in the last three
/// means it is not an address path), fewer than six components, or a number
/// that does not fit `u32`.
///
/// Deliberately tolerant of formatting and deliberately unauthenticated. The
/// redeem-script check downstream is what decides whether the path was right.
fn extract_ms45_hint(
    src: &[u8],
    start: usize,
    end: usize,
) -> Option<crate::wallet::transaction::Ms45Hint> {
    if start >= end || end > src.len() {
        return None;
    }
    let region = &src[start..end];
    let needle = b"\"derivationPath\"";
    let mut i = 0usize;
    let at = loop {
        if i + needle.len() > region.len() {
            return None;
        }
        if &region[i..i + needle.len()] == needle {
            break i + needle.len();
        }
        i += 1;
    };

    // Skip to the opening quote of the value.
    let mut j = at;
    while j < region.len() && region[j] != b'"' {
        if region[j] == b',' || region[j] == b'}' {
            return None; // value was null or absent
        }
        j += 1;
    }
    if j >= region.len() {
        return None;
    }
    j += 1;
    let vstart = j;
    while j < region.len() && region[j] != b'"' {
        j += 1;
    }
    if j >= region.len() {
        return None;
    }
    let path = &region[vstart..j];

    // Split on '/', keep the last three components.
    let mut comps: [&[u8]; 8] = [&[]; 8];
    let mut n = 0usize;
    let mut seg_start = 0usize;
    for k in 0..=path.len() {
        if k == path.len() || path[k] == b'/' {
            if n < comps.len() {
                comps[n] = &path[seg_start..k];
                n += 1;
            } else {
                return None; // deeper than any path we emit
            }
            seg_start = k + 1;
        }
    }
    if n < 6 {
        return None;
    }

    let mut vals = [0u32; 3];
    for (slot, comp) in comps[n - 3..n].iter().enumerate() {
        if comp.is_empty() {
            return None;
        }
        let mut v: u32 = 0;
        for &c in comp.iter() {
            if !c.is_ascii_digit() {
                return None; // hardened marker or junk: not an address path
            }
            v = v.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        }
        vals[slot] = v;
    }

    Some(crate::wallet::transaction::Ms45Hint {
        present: true,
        cosigner: vals[0],
        chain: vals[1],
        index: vals[2],
    })
}

fn parse_bip32_derivations(
    tok: &mut Tokenizer<'_>,
    parsed: &mut PsktParsed,
    field_start: usize,
    inp: &mut crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
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
        // Value: null or object. Peek: only an object can carry a path, and
        // `skip_value` handles both forms once we are done looking.
        let val_start = tok.position();
        skip_value(tok)?;
        if !inp.ms45_hint.present {
            if let Some(h) = extract_ms45_hint(tok.source(), val_start, tok.position()) {
                inp.ms45_hint = h;
            }
        }

        match tok.next()? {
            Tok::Comma => continue,
            Tok::RBrace => break,
            _ => return Err(PskError::UnexpectedToken),
        }
    }

    // Capture the entire `"bip32Derivations": {...}` region, and remember WHICH
    // region it is so the serializer can re-emit exactly this input's map.
    // `unknowns_count` before the call is the index it will occupy; stored +1 so
    // that zero, the value a zeroed Transaction starts with, means "no map".
    let region_idx = parsed.unknowns_count;
    capture_unknown(parsed, field_start, tok.position())?;
    inp.bip32_region = region_idx.saturating_add(1);
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
    let mut seen_covenant = false;

    const S_REDEEM: u16 = 1 << 0;
    const S_BIP32: u16 = 1 << 1;
    const S_PROPRIETARIES: u16 = 1 << 2;
    let mut seen_opt: u16 = 0;

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
                let value = expect_u64(tok)?;
                if value > crate::wallet::pskt::MAX_SOMPI {
                    return Err(PskError::ValueOutOfRange);
                }
                out.value = value;
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
                if !mark(&mut seen_opt, S_REDEEM) {
                    return Err(PskError::DuplicateField);
                }
                // Structural — null or hex. Serializer emits from known
                // state or passes through the parsed hex (outputs don't
                // carry signer-relevant redeem scripts in our flow).
                skip_value(tok)?;
            }
            b"covenantBinding" => {
                // KIP-20 covenant binding: `null`, or an object carrying
                // exactly `authorizingInput` and `covenantId`, each once.
                //
                // Validated strictly because both values are consumed twice:
                // `sighash.rs` commits them for tx_version >= 1, and the
                // covenant confirm screen displays the id. A value accepted
                // here is both signed and shown.
                if seen_covenant {
                    return Err(PskError::DuplicateField);
                }
                seen_covenant = true;
                match tok.peek()? {
                    Tok::Null => {
                        tok.next()?;
                        out.has_covenant = false;
                    }
                    Tok::LBrace => {
                        tok.next()?;
                        // `{}` is a contradiction: a binding is present but
                        // carries nothing. `null` is how absence is spelled.
                        if let Tok::RBrace = tok.peek()? {
                            return Err(PskError::InvalidCovenantBinding);
                        }
                        let mut seen_auth = false;
                        let mut seen_id = false;
                        loop {
                            let cb_key = expect_string(tok)?;
                            expect(tok, Tok::Colon)?;
                            match cb_key {
                                b"authorizingInput" => {
                                    if seen_auth {
                                        return Err(PskError::InvalidCovenantBinding);
                                    }
                                    // Range-check before narrowing: `as u16`
                                    // on an unchecked value turns 65536 into
                                    // 0, which is then hashed and signed.
                                    let n = expect_u64(tok)?;
                                    if n > u16::MAX as u64 {
                                        return Err(PskError::InvalidCovenantBinding);
                                    }
                                    out.covenant_auth_input = n as u16;
                                    seen_auth = true;
                                }
                                b"covenantId" => {
                                    if seen_id {
                                        return Err(PskError::InvalidCovenantBinding);
                                    }
                                    let hex_str = expect_string(tok)?;
                                    if hex_str.len() != 64 {
                                        return Err(PskError::InvalidCovenantBinding);
                                    }
                                    // Propagate the decode error. Discarding
                                    // it left a partially written id (the
                                    // decoder writes byte by byte before
                                    // failing) on the screen and in the
                                    // sighash.
                                    hex_decode_strict(hex_str, &mut out.covenant_id)
                                        .map_err(|_| PskError::InvalidCovenantBinding)?;
                                    seen_id = true;
                                }
                                // Rejected rather than skipped: upstream
                                // defines exactly these two members, and a
                                // skipped member is also dropped from the
                                // round trip.
                                _ => return Err(PskError::InvalidCovenantBinding),
                            }
                            match tok.next()? {
                                Tok::Comma => continue,
                                Tok::RBrace => break,
                                _ => return Err(PskError::UnexpectedToken),
                            }
                        }
                        if !(seen_auth && seen_id) {
                            return Err(PskError::InvalidCovenantBinding);
                        }
                        // Set only once the object is known good, so a
                        // rejected binding cannot leave the flag raised.
                        out.has_covenant = true;
                    }
                    // Anything else (number, string, array, bool) is not a
                    // binding. Previously skipped silently.
                    _ => return Err(PskError::InvalidCovenantBinding),
                }
            }
            // Shared arm, per-key flag: both are present in every canonical
            // output, so one flag covering both would reject the normal case.
            b"bip32Derivations" | b"proprietaries" => {
                let flag = if key == b"bip32Derivations" { S_BIP32 } else { S_PROPRIETARIES };
                if !mark(&mut seen_opt, flag) {
                    return Err(PskError::DuplicateField);
                }
                // Opaque maps. Capture only if non-empty so the 16-slot
                // budget survives realistic 2-of-3 multisig shapes.
                expect(tok, Tok::LBrace)?;
                let val_start = tok.position();
                match tok.peek()? {
                    Tok::RBrace => { tok.next()?; }  // empty, no capture
                    _ => {
                        skip_until_matching(tok, Tok::RBrace)?;
                        // Pull the derivation path out NOW, as the input side
                        // does. An output claiming to be change can only be
                        // checked against the FULL cosigner set, and this path
                        // says where to rebuild it. Extracted at parse time so
                        // the review screen never depends on the scratch buffer
                        // still holding this region.
                        if key == b"bip32Derivations" && !out.ms45_hint.present {
                            if let Some(h) =
                                extract_ms45_hint(tok.source(), val_start, tok.position())
                            {
                                out.ms45_hint = h;
                            }
                        }
                        let region_idx = parsed.unknowns_count;
                        capture_unknown(parsed, key_start, tok.position())?;
                        if key == b"bip32Derivations" {
                            out.bip32_region = region_idx.saturating_add(1);
                        }
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
/// `format` — must be `PsktPskb`; any other format is an error.
/// `out`    — destination buffer, receives magic + hex(JSON).
///
/// Returns the number of bytes written to `out`.
/// Wire bytes the emitted bundle grows by for each input this device
/// signs.
///
/// Signing fills two fields that were empty on the way in. Measured from a
/// real emission rather than derived: `partialSigs` goes from `{}` to 213
/// JSON characters (a 66-char pubkey, a 130-char signature and the
/// punctuation), and `bip32Derivations` from `{}` to 75. That is 284 JSON
/// characters, and the bundle is hex-encoded onto the wire, so 568 bytes.
pub const EMIT_GROWTH_PER_SIGNED_INPUT: usize = 568;

/// Predict the emitted size before signing anything.
///
/// The size check inside `HexWriter` is exact but runs at the end, so a
/// bundle too large to emit was parsed, signed and only then refused: an
/// 11-input PSKB spent about two seconds on eleven key operations and
/// eleven verifications before `OutputBufferTooSmall`. The work was
/// discarded and the user was told "Result too large", which suggests
/// splitting the transaction when the real remedy is the compact format.
///
/// This serialises the unsigned bundle, which is pure JSON writing with no
/// crypto, and adds the known per-signature growth. Exact rather than
/// estimated, so it holds for any shape: covenant outputs, preserved
/// unknown regions, whatever the scratch carries.
///
/// `n_to_sign` is how many inputs this device will actually sign, which on
/// a cosigning pass is fewer than `tx.num_inputs`.
pub fn predict_emitted_size(
    tx: &Transaction,
    parsed: &PsktParsed,
    scratch: &[u8],
    format: TxInputFormat,
    n_to_sign: usize,
    dry_run_buf: &mut [u8],
) -> Result<usize, PskError> {
    let unsigned = serialize_pskt(tx, parsed, scratch, format, dry_run_buf)?;
    Ok(unsigned + n_to_sign * EMIT_GROWTH_PER_SIGNED_INPUT)
}

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
    parsed: &PsktParsed,
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
        w.hex_string_field(tx.redeem_bytes(idx))?;
    }

    w.lit(b",\"sigOpCount\":")?;
    w.u64(inp.sig_op_count as u64)?;

    // bip32Derivations.
    //
    // Re-emit the INCOMING map verbatim when there was one. It is how the NEXT
    // cosigner finds their key: one KeySource per cosigner, including those who
    // have not signed yet. Regenerating it from `partialSigs` keeps only
    // signers and nulls their KeySource, so a 45' bundle survived exactly one
    // hop and the second signer refused on a payload this device had gutted.
    // Observed with vector M5: two entries in, one entry out with a null value.
    //
    // Falls back to the regenerated null-map when no region was captured, which
    // is the pre-existing behaviour for payloads that arrive without a map and
    // preserves the kaspa-wallet-pskt invariant that every `partialSigs` pubkey
    // also appears here.
    //
    // The region is recorded per input, not looked up by field name: a
    // multi-input transaction has one such region per input and a name search
    // would return the first one every time.
    w.lit(b",\"bip32Derivations\":")?;
    let mut emitted = false;
    if inp.bip32_region > 0 {
        let idx = (inp.bip32_region - 1) as usize;
        if idx < parsed.unknowns_count as usize {
            let (start, end): (u16, u16) = parsed.unknowns[idx];
            // The captured region is `"bip32Derivations":{...}`; skip the key
            // and colon so only the value is spliced.
            let skip: u16 = b"\"bip32Derivations\":".len() as u16;
            if start.saturating_add(skip) < end {
                w.scratch_range(start + skip, end)?;
                emitted = true;
            }
        }
    }
    if !emitted {
        emit_bip32_derivations_for_input(w, inp)?;
    }

    w.lit(b",\"finalScriptSig\":null,\"proprietaries\":{}")?;
    w.lit(b"}")?;
    Ok(())
}

fn emit_utxo_entry(
    w: &mut HexWriter<'_>,
    inp: &crate::wallet::transaction::TransactionInput,
) -> Result<(), PskError> {
    // {"amount":N,"scriptPublicKey":"<version><script hex>","blockDaaScore":0,
    //  "isCoinbase":false[,"covenantId":"<hex>"]}
    w.lit(b"{\"amount\":")?;
    w.u64(inp.utxo_entry.amount)?;
    w.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(w, &inp.utxo_entry.script_public_key)?;
    // `blockDaaScore` and `isCoinbase` are written as constants because the
    // device does not carry them: neither reaches the sighash, and neither has
    // a field on `UtxoEntry`. Deliberate, not an oversight.
    w.lit(b",\"blockDaaScore\":0,\"isCoinbase\":false")?;
    // The covenant id is carried, so a bundle that round-trips through the
    // device still tells the next signer which covenant each coin belongs to.
    // Omitted rather than written as `null` when absent, matching the output
    // binding and costing nothing on ordinary inputs.
    if inp.utxo_entry.has_covenant {
        w.lit(b",\"covenantId\":")?;
        w.hex_string_field(&inp.utxo_entry.covenant_id)?;
    }
    w.lit(b"}")?;
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
    parsed: &PsktParsed,
    idx: usize,
) -> Result<(), PskError> {
    let out = &tx.outputs[idx];
    // {"amount":N,"scriptPublicKey":"<hex>"[,"covenantBinding":{...}],
    //  "redeemScript":null,"bip32Derivations":{},"proprietaries":{}}
    w.lit(b"{\"amount\":")?;
    w.u64(out.value)?;
    w.lit(b",\"scriptPublicKey\":")?;
    emit_script_public_key(w, &out.script_public_key)?;

    // `covenantBinding` used to be omitted entirely, so a covenant bundle
    // that round-tripped through the device came back without it. The
    // sighash commits the binding for tx_version >= 1 (`sighash.rs:428`),
    // so the device signed over a value the emitted bundle no longer
    // declared, and whoever finalised computed a different sighash. The
    // second cosigner of a multisig covenant is where that bites: it parses
    // a stripped bundle and signs a different message.
    //
    // Emitted whatever the transaction version. The binding is data the
    // bundle arrived with, not something this device may drop because the
    // version it happens to carry does not commit it.
    //
    // Written only when set, in KasSee's field order (`kspt.rs:1393`).
    // KasSee also writes an explicit `null` on outputs without one; the
    // parser treats the field as optional, so omitting it is equivalent and
    // saves 46 wire bytes per plain output, on an emit path that is already
    // the narrower half of the device (16,384 in, 8,192 out).
    if out.has_covenant {
        w.lit(b",\"covenantBinding\":{\"authorizingInput\":")?;
        w.u64(out.covenant_auth_input as u64)?;
        w.lit(b",\"covenantId\":")?;
        w.hex_string_field(&out.covenant_id)?;
        w.lit(b"}")?;
    }

    // Re-emit the output's map VERBATIM when there was one.
    //
    // This was a hardcoded empty object, so the first signer stripped every
    // output's derivation claim and the next signer had nothing to verify. Same
    // defect as N-20 on the input side, and the same fix: the parser already
    // captured the region, nothing consumed it.
    w.lit(b",\"redeemScript\":null,\"bip32Derivations\":")?;
    let mut emitted = false;
    if out.bip32_region > 0 {
        let idx = (out.bip32_region - 1) as usize;
        if idx < parsed.unknowns_count as usize {
            let (start, end) = parsed.unknowns[idx];
            let skip: u16 = b"\"bip32Derivations\":".len() as u16;
            if start.saturating_add(skip) < end {
                w.scratch_range(start + skip, end)?;
                emitted = true;
            }
        }
    }
    if !emitted {
        w.lit(b"{}")?;
    }
    w.lit(b",\"proprietaries\":{}}")?;
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
