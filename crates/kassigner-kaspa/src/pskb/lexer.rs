// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A strict JSON tokenizer over borrowed bytes, enough to read a PSKB
//! document. It allocates and copies nothing: every token carries offsets
//! into the document, so a region can be kept exactly as it arrived.
//!
//! A string token is the span between its quotes, escapes checked but not
//! decoded. Keys are decoded on request ([`decode_key`]) as serde_json does
//! before upstream matches field names: `"seq\u0075ence"` is `sequence`.
//! What serde_json refuses is refused here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token<'a> {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    Colon,
    Comma,
    /// The bytes between the quotes, undecoded.
    String {
        raw: &'a [u8],
        start: usize,
        end: usize,
    },
    /// A JSON number, as it appeared.
    Number {
        raw: &'a [u8],
    },
    True,
    False,
    Null,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LexError {
    /// A byte that cannot begin any token.
    Unexpected { offset: usize },
    /// A string or literal ran off the end of the document.
    Truncated { offset: usize },
    /// A control character inside a string, which JSON forbids unescaped.
    ControlInString { offset: usize },
    /// A value nested deeper than [`MAX_DEPTH`].
    TooDeep { offset: usize },
    /// A backslash not followed by a JSON escape, or `\u` not by four hex
    /// digits, which serde_json refuses in any string; in a key, also a
    /// surrogate without its pair.
    BadEscape { offset: usize },
    /// A key that is not UTF-8; serde_json reads every key as text.
    NotUtf8 { offset: usize },
    /// A number not in JSON's grammar (`01`, `1.`, `-.5`, `1e`, `1.2.3`),
    /// which serde_json refuses kept or skipped.
    BadNumber { offset: usize },
}

/// The deepest nesting [`Lexer::skip_value`] follows: far above a bundle's
/// own four levels, and the width of a skip's one piece of state, a bit per
/// open level for its kind of bracket.
pub const MAX_DEPTH: usize = 64;

/// Tokenizer over a JSON document.
pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Self {
        Self { src, pos: 0 }
    }

    /// Current byte offset.
    pub fn offset(&self) -> usize {
        self.pos
    }

    /// Move to a recorded offset, at most the end.
    pub fn seek(&mut self, offset: usize) {
        self.pos = offset.min(self.src.len());
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.src.len() {
            match self.src[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn literal(&mut self, word: &[u8], tok: Token<'a>) -> Result<Token<'a>, LexError> {
        let start = self.pos;
        if self.src.len() - start < word.len() {
            return Err(LexError::Truncated { offset: start });
        }
        if &self.src[start..start + word.len()] != word {
            return Err(LexError::Unexpected { offset: start });
        }
        self.pos += word.len();
        Ok(tok)
    }

    /// The next token, or `None` at the end of the document.
    pub fn next_token(&mut self) -> Option<Result<Token<'a>, LexError>> {
        self.skip_whitespace();
        if self.pos >= self.src.len() {
            return None;
        }
        let start = self.pos;
        let c = self.src[start];
        let r = match c {
            b'{' => {
                self.pos += 1;
                Ok(Token::ObjectStart)
            }
            b'}' => {
                self.pos += 1;
                Ok(Token::ObjectEnd)
            }
            b'[' => {
                self.pos += 1;
                Ok(Token::ArrayStart)
            }
            b']' => {
                self.pos += 1;
                Ok(Token::ArrayEnd)
            }
            b':' => {
                self.pos += 1;
                Ok(Token::Colon)
            }
            b',' => {
                self.pos += 1;
                Ok(Token::Comma)
            }
            b't' => self.literal(b"true", Token::True),
            b'f' => self.literal(b"false", Token::False),
            b'n' => self.literal(b"null", Token::Null),
            b'"' => self.lex_string(start),
            b'-' | b'0'..=b'9' => self.lex_number(start),
            _ => Err(LexError::Unexpected { offset: start }),
        };
        Some(r)
    }

    fn lex_string(&mut self, start: usize) -> Result<Token<'a>, LexError> {
        let mut i = start + 1;
        while i < self.src.len() {
            match self.src[i] {
                b'"' => {
                    self.pos = i + 1;
                    return Ok(Token::String {
                        raw: &self.src[start + 1..i],
                        start: start + 1,
                        end: i,
                    });
                }
                // An escape, held to the forms serde_json's skip accepts
                // (`ignore_escape`) and stepped over, not decoded.
                b'\\' => match self.src.get(i + 1) {
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                    Some(b'u') => {
                        let Some(digits) = self.src.get(i + 2..i + 6) else {
                            return Err(LexError::Truncated { offset: start });
                        };
                        if !digits.iter().all(u8::is_ascii_hexdigit) {
                            return Err(LexError::BadEscape { offset: i });
                        }
                        i += 6;
                    }
                    Some(_) => return Err(LexError::BadEscape { offset: i }),
                    None => return Err(LexError::Truncated { offset: start }),
                },
                c if c < 0x20 => return Err(LexError::ControlInString { offset: i }),
                _ => i += 1,
            }
        }
        Err(LexError::Truncated { offset: start })
    }

    fn lex_number(&mut self, start: usize) -> Result<Token<'a>, LexError> {
        let mut i = start;
        if self.src[i] == b'-' {
            i += 1;
        }
        let digits_start = i;
        while i < self.src.len()
            && matches!(self.src[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
        {
            i += 1;
        }
        if i == digits_start {
            return Err(LexError::Unexpected { offset: start });
        }
        // Measured by the characters a number can hold, then held to JSON's
        // grammar, as serde_json holds every number, kept or skipped.
        if !json_number(&self.src[start..i]) {
            return Err(LexError::BadNumber { offset: start });
        }
        self.pos = i;
        Ok(Token::Number {
            raw: &self.src[start..i],
        })
    }

    /// Skip one complete value at the current position: its span. Not
    /// interpreted, but held to JSON as upstream reads it.
    ///
    /// # Errors
    ///
    /// `Unexpected` at the first token out of place, `Truncated` for a value
    /// the document ends inside, `TooDeep` past [`MAX_DEPTH`], and the
    /// tokenizer's own errors.
    pub fn skip_value(&mut self) -> Result<(usize, usize), LexError> {
        /// What the next token has to be.
        #[derive(Clone, Copy)]
        enum Want {
            /// A value: after a colon, or a comma inside an array.
            Value,
            /// A value or `]`: straight after `[`.
            ValueOrEnd,
            /// A key or `}`: straight after `{`.
            KeyOrEnd,
            /// A key: after a comma inside an object.
            Key,
            /// The colon after a key.
            Colon,
            /// A comma or the close of the innermost container.
            CommaOrEnd,
        }

        self.skip_whitespace();
        let start = self.pos;
        // Bit `i` set: the container open at depth `i + 1` is an object.
        let mut objects: u64 = 0;
        let mut depth: usize = 0;
        let mut want = Want::Value;
        loop {
            self.skip_whitespace();
            let at = self.pos;
            let Some(tok) = self.next_token() else {
                return Err(LexError::Truncated { offset: start });
            };
            let tok = tok?;
            let unexpected = LexError::Unexpected { offset: at };
            // A value, or a container, just finished.
            let mut complete = false;
            match want {
                Want::Value | Want::ValueOrEnd => match tok {
                    Token::ArrayEnd if matches!(want, Want::ValueOrEnd) => {
                        depth -= 1;
                        complete = true;
                    }
                    Token::String { .. }
                    | Token::Number { .. }
                    | Token::True
                    | Token::False
                    | Token::Null => complete = true,
                    Token::ObjectStart | Token::ArrayStart => {
                        if depth == MAX_DEPTH {
                            return Err(LexError::TooDeep { offset: at });
                        }
                        let object = matches!(tok, Token::ObjectStart);
                        objects = (objects & !(1 << depth)) | (u64::from(object) << depth);
                        depth += 1;
                        want = if object {
                            Want::KeyOrEnd
                        } else {
                            Want::ValueOrEnd
                        };
                    }
                    _ => return Err(unexpected),
                },
                Want::KeyOrEnd | Want::Key => match tok {
                    Token::ObjectEnd if matches!(want, Want::KeyOrEnd) => {
                        depth -= 1;
                        complete = true;
                    }
                    Token::String { .. } => want = Want::Colon,
                    _ => return Err(unexpected),
                },
                Want::Colon => match tok {
                    Token::Colon => want = Want::Value,
                    _ => return Err(unexpected),
                },
                Want::CommaOrEnd => {
                    let in_object = objects & (1 << (depth - 1)) != 0;
                    match tok {
                        Token::Comma => want = if in_object { Want::Key } else { Want::Value },
                        Token::ObjectEnd if in_object => {
                            depth -= 1;
                            complete = true;
                        }
                        Token::ArrayEnd if !in_object => {
                            depth -= 1;
                            complete = true;
                        }
                        _ => return Err(unexpected),
                    }
                }
            }
            if complete {
                if depth == 0 {
                    return Ok((start, self.pos));
                }
                want = Want::CommaOrEnd;
            }
        }
    }
}

/// Whether `s` is a JSON number: `-`, then `0` or a digit run not starting
/// with `0`, then an optional `.` and digits, then an optional `e` or `E`, a
/// sign and digits.
fn json_number(s: &[u8]) -> bool {
    let digits = |from: usize| s[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let mut i = usize::from(s.first() == Some(&b'-'));
    match s.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i += digits(i),
        _ => return false,
    }
    if s.get(i) == Some(&b'.') {
        let n = digits(i + 1);
        if n == 0 {
            return false;
        }
        i += 1 + n;
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(s.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let n = digits(i);
        if n == 0 {
            return false;
        }
        i += n;
    }
    i == s.len()
}

/// Room a caller gives [`decode_key`] for a key it matches by name: the
/// longest name read here, `outputsModifiable`, is 17 bytes.
pub const KEY_ROOM: usize = 24;

/// A string token's bytes `raw`, at offset `at`, decoded into `out` as
/// serde_json decodes a key: a `\u` surrogate must have its pair, and the
/// bytes between escapes must be UTF-8.
///
/// `Ok(None)` when too long for `out`; still checked whole, as serde_json
/// refuses a bad key of any length.
///
/// # Errors
///
/// `BadEscape` for an escape serde_json refuses in a key, `NotUtf8` for bytes
/// that are not text.
pub fn decode_key<'o>(
    raw: &[u8],
    at: usize,
    out: &'o mut [u8],
) -> Result<Option<&'o [u8]>, LexError> {
    let mut len = 0usize;
    let mut fits = true;
    // Start of the run of bytes since the last escape.
    let mut run = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] != b'\\' {
            i += 1;
            continue;
        }
        text(&raw[run..i], at)?;
        fits = fits && put(out, &mut len, &raw[run..i]);
        let (c, next) = escape(raw, i).ok_or(LexError::BadEscape { offset: at + i })?;
        let mut utf8 = [0u8; 4];
        fits = fits && put(out, &mut len, c.encode_utf8(&mut utf8).as_bytes());
        i = next;
        run = i;
    }
    text(&raw[run..], at)?;
    fits = fits && put(out, &mut len, &raw[run..]);
    Ok(if fits { Some(&out[..len]) } else { None })
}

/// A run between escapes must be UTF-8 on its own: an escape is a whole
/// character and a backslash ASCII, so the key is text when every run is.
fn text(run: &[u8], at: usize) -> Result<(), LexError> {
    core::str::from_utf8(run)
        .map(|_| ())
        .map_err(|_| LexError::NotUtf8 { offset: at })
}

/// Append `bytes` after the `len` bytes of `out` written; false, writing
/// nothing, when they do not fit.
fn put(out: &mut [u8], len: &mut usize, bytes: &[u8]) -> bool {
    match out.get_mut(*len..*len + bytes.len()) {
        Some(dst) => {
            dst.copy_from_slice(bytes);
            *len += bytes.len();
            true
        }
        None => false,
    }
}

/// A string token's text as serde_json decodes it (`"\u0030"` is `"0"`),
/// for text read only as ASCII: hex, a derivation path. A character past
/// ASCII, written or escaped, or a bad escape gives `0xFF`, which nothing
/// read this way takes.
pub fn ascii(raw: &[u8]) -> impl Iterator<Item = u8> + Clone + '_ {
    let mut i = 0usize;
    core::iter::from_fn(move || {
        let c = *raw.get(i)?;
        if c != b'\\' {
            i += 1;
            return Some(if c.is_ascii() { c } else { 0xFF });
        }
        match escape(raw, i) {
            Some((ch, next)) => {
                i = next;
                Some(u8::try_from(ch).ok().filter(u8::is_ascii).unwrap_or(0xFF))
            }
            None => {
                i = raw.len();
                Some(0xFF)
            }
        }
    })
}

/// The escape whose backslash is at `raw[i]`: its character and where the
/// next byte is. `None` where serde_json's `parse_escape` refuses, with
/// `validate` set as for text.
fn escape(raw: &[u8], i: usize) -> Option<(char, usize)> {
    let one = |c: u8| Some((char::from(c), i + 2));
    match *raw.get(i + 1)? {
        b'"' => one(b'"'),
        b'\\' => one(b'\\'),
        b'/' => one(b'/'),
        b'b' => one(0x08),
        b'f' => one(0x0c),
        b'n' => one(b'\n'),
        b'r' => one(b'\r'),
        b't' => one(b'\t'),
        b'u' => {
            let n = crate::hex::hex4(raw.get(i + 2..i + 6)?)?;
            match n {
                // A leading surrogate: its trailing one has to follow at once.
                0xD800..=0xDBFF => {
                    if raw.get(i + 6..i + 8)? != b"\\u" {
                        return None;
                    }
                    let m = crate::hex::hex4(raw.get(i + 8..i + 12)?)?;
                    if !(0xDC00..=0xDFFF).contains(&m) {
                        return None;
                    }
                    let c = 0x1_0000 + ((u32::from(n) - 0xD800) << 10) + (u32::from(m) - 0xDC00);
                    Some((char::from_u32(c)?, i + 12))
                }
                // A trailing surrogate with nothing before it.
                0xDC00..=0xDFFF => None,
                _ => Some((char::from_u32(u32::from(n))?, i + 6)),
            }
        }
        _ => None,
    }
}
