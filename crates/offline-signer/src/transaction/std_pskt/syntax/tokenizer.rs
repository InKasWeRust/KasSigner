//! Allocation-free tokenizer for the restricted PSKT JSON grammar.

use super::super::PskError;

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
    /// `next_token()` calls keep returning `Eof`.
    Eof,
}

/// Flat one-pass tokenizer over a byte slice.
///
/// Does not carry interior `Result` state — every `next_token()` call returns
/// a fresh `Result<Tok, PskError>`. Errors leave the `pos` cursor
/// pointing at the offending byte so callers can build useful diagnostics
/// (line/column if they want, byte offset otherwise).
pub struct Tokenizer<'a> {
    data: &'a [u8],
    /// Current position in `data`. Between 0 and `data.len()` inclusive.
    pub pos: usize,
}

fn punctuation(byte: u8) -> Option<Tok<'static>> {
    match byte {
        b'{' => Some(Tok::LBrace),
        b'}' => Some(Tok::RBrace),
        b'[' => Some(Tok::LBracket),
        b']' => Some(Tok::RBracket),
        b':' => Some(Tok::Colon),
        b',' => Some(Tok::Comma),
        _ => None,
    }
}

impl<'a> Tokenizer<'a> {
    /// Construct a tokenizer over `data`. The caller retains ownership;
    /// tokens borrow from this buffer.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Byte offset of the next token that `next_token()` will try to parse.
    /// Useful for the parser's byte-range capture of unknown regions
    /// (see the scoped ranges in `shared_signer::PsktParsed`).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Original token source for validated byte-range inspection.
    pub fn source(&self) -> &'a [u8] {
        self.data
    }

    /// Advance past any ASCII whitespace. Tolerated even though compact
    /// JSON has none — prettified paste-in debug inputs still tokenize.
    #[inline]
    fn skip_ws(&mut self) {
        let remaining = self.data.get(self.pos..).unwrap_or_default();
        let consumed = remaining
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .unwrap_or(remaining.len());
        self.pos = self.pos.saturating_add(consumed);
    }

    /// Produce the next token. After Eof is returned, subsequent calls
    /// continue to return Eof (not an error) — the parser can treat Eof
    /// as a normal terminator.
    pub fn next_token(&mut self) -> Result<Tok<'a>, PskError> {
        self.skip_ws();
        if self.pos >= self.data.len() {
            return Ok(Tok::Eof);
        }

        let byte = self.data[self.pos];
        if let Some(token) = punctuation(byte) {
            self.pos += 1;
            return Ok(token);
        }
        match byte {
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
        let tok = self.next_token();
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
        let start = self.pos.checked_add(1).ok_or(PskError::UnexpectedToken)?;
        for (relative, c) in self
            .data
            .get(start..)
            .unwrap_or_default()
            .iter()
            .copied()
            .enumerate()
        {
            let i = start
                .checked_add(relative)
                .ok_or(PskError::UnexpectedToken)?;
            if c == b'"' {
                let body = &self.data[start..i];
                self.pos = i.checked_add(1).ok_or(PskError::UnexpectedToken)?;
                return Ok(Tok::Str(body));
            }
            if c == b'\\' || !(0x20..=0x7E).contains(&c) {
                self.pos = i;
                return Err(PskError::UnexpectedToken);
            }
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
        let digits_start = self.pos.checked_add(1).ok_or(PskError::UnexpectedToken)?;
        let digit_count = self
            .data
            .get(digits_start..)
            .unwrap_or_default()
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        self.pos = digits_start
            .checked_add(digit_count)
            .ok_or(PskError::UnexpectedToken)?;
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
/// Used by the parser for fields like `amount`, `sequence`,
/// `blockDaaScore`, `sigOpCount`, `version`, `txVersion`, etc.
pub fn parse_u64_num(bytes: &[u8]) -> Result<u64, PskError> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
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
            None => return Err(PskError::UnexpectedToken), // overflow
        };
    }
    Ok(acc)
}
