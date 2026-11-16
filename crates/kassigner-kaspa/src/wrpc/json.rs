// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! JSON as a node writes it, read in place: a node's wRPC messages here,
//! the WASM SDK's transactions in [`crate::safe_json`].
//!
//! [`document`] checks RFC 8259's grammar over the whole message; values are
//! then read in place by span, strings unescaped only when read as text
//! ([`Unescaped`]). Nesting is bounded at 64; a node's deepest reply has
//! five levels.
//!
//! As serde: a key is compared unescaped, a key twice in an object is
//! refused, an unknown key is passed over, a `u64` is digits alone and
//! fits, a float is any finite number. Every function takes spans in a
//! message [`document`] accepted.

/// A value's bytes in the message: `start..end`.
pub(crate) type Span = (usize, usize);

/// The offset in the message where it stops being what was expected.
pub(crate) type At = usize;

/// The deepest nesting accepted.
const DEPTH: u32 = 64;

/// Past any whitespace at `i`.
pub(crate) fn ws(s: &[u8], mut i: usize) -> usize {
    while let Some(b' ' | b'\t' | b'\n' | b'\r') = s.get(i) {
        i += 1;
    }
    i
}

/// The span of the one JSON value `s` holds, whitespace around it allowed;
/// `s` must be UTF-8.
pub(crate) fn document(s: &[u8]) -> Result<Span, At> {
    core::str::from_utf8(s).map_err(|e| e.valid_up_to())?;
    let start = ws(s, 0);
    let end = value_end(s, start)?;
    let after = ws(s, end);
    if after != s.len() {
        return Err(after);
    }
    Ok((start, end))
}

/// Where the value at `i` ends, every byte checked. No recursion: one bit
/// per open container, 1 for an object.
pub(crate) fn value_end(s: &[u8], mut i: usize) -> Result<usize, At> {
    let mut stack: u64 = 0;
    let mut depth = 0u32;
    loop {
        // A value at `i`.
        match s.get(i) {
            Some(b'{') => {
                i = ws(s, i + 1);
                if s.get(i) == Some(&b'}') {
                    i += 1;
                } else {
                    if depth == DEPTH {
                        return Err(i);
                    }
                    stack = (stack << 1) | 1;
                    depth += 1;
                    i = member_value(s, i)?;
                    continue;
                }
            }
            Some(b'[') => {
                i = ws(s, i + 1);
                if s.get(i) == Some(&b']') {
                    i += 1;
                } else {
                    if depth == DEPTH {
                        return Err(i);
                    }
                    stack <<= 1;
                    depth += 1;
                    continue;
                }
            }
            Some(b'"') => i = string_end(s, i)?,
            Some(b't') => i = literal(s, i, b"true")?,
            Some(b'f') => i = literal(s, i, b"false")?,
            Some(b'n') => i = literal(s, i, b"null")?,
            Some(b'-' | b'0'..=b'9') => i = number_end(s, i)?,
            _ => return Err(i),
        }
        // After a value: close what it closes, then on to the next one.
        loop {
            if depth == 0 {
                return Ok(i);
            }
            i = ws(s, i);
            let object = stack & 1 == 1;
            match s.get(i) {
                Some(b',') => {
                    i = ws(s, i + 1);
                    if object {
                        i = member_value(s, i)?;
                    }
                    break;
                }
                Some(b'}') if object => {}
                Some(b']') if !object => {}
                _ => return Err(i),
            }
            stack >>= 1;
            depth -= 1;
            i += 1;
        }
    }
}

/// From a member's key at `i` to its value.
fn member_value(s: &[u8], i: usize) -> Result<usize, At> {
    if s.get(i) != Some(&b'"') {
        return Err(i);
    }
    let i = ws(s, string_end(s, i)?);
    if s.get(i) != Some(&b':') {
        return Err(i);
    }
    Ok(ws(s, i + 1))
}

/// Where the string opening at `i` ends: only JSON's escapes, no control
/// character, a surrogate only in a pair.
pub(crate) fn string_end(s: &[u8], i: usize) -> Result<usize, At> {
    let mut i = i + 1;
    loop {
        match s.get(i) {
            None => return Err(i),
            Some(b'"') => return Ok(i + 1),
            Some(b'\\') => match s.get(i + 1) {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                Some(b'u') => {
                    let unit = hex4(s, i + 2).ok_or(i)?;
                    if (0xDC00..0xE000).contains(&unit) {
                        return Err(i);
                    }
                    i += 6;
                    if (0xD800..0xDC00).contains(&unit) {
                        if s.get(i..i + 2) != Some(b"\\u") {
                            return Err(i);
                        }
                        let low = hex4(s, i + 2).ok_or(i)?;
                        if !(0xDC00..0xE000).contains(&low) {
                            return Err(i);
                        }
                        i += 6;
                    }
                }
                _ => return Err(i),
            },
            Some(&c) if c < 0x20 => return Err(i),
            Some(_) => i += 1,
        }
    }
}

/// Four hex digits at `i`, as a number.
fn hex4(s: &[u8], i: usize) -> Option<u32> {
    s.get(i..i + 4).and_then(crate::hex::hex4).map(u32::from)
}

fn literal(s: &[u8], i: usize, word: &[u8]) -> Result<usize, At> {
    if s.get(i..i + word.len()) == Some(word) {
        Ok(i + word.len())
    } else {
        Err(i)
    }
}

/// Past one or more digits at `i`.
fn digits(s: &[u8], mut i: usize) -> Result<usize, At> {
    if !matches!(s.get(i), Some(b'0'..=b'9')) {
        return Err(i);
    }
    while let Some(b'0'..=b'9') = s.get(i) {
        i += 1;
    }
    Ok(i)
}

/// Where the number at `i` ends: optional minus, an integer with no
/// leading zero, optional fraction and exponent.
fn number_end(s: &[u8], mut i: usize) -> Result<usize, At> {
    if s.get(i) == Some(&b'-') {
        i += 1;
    }
    i = match s.get(i) {
        Some(b'0') => i + 1,
        _ => digits(s, i)?,
    };
    if s.get(i) == Some(&b'.') {
        i = digits(s, i + 1)?;
    }
    if let Some(b'e' | b'E') = s.get(i) {
        i += 1;
        if let Some(b'+' | b'-') = s.get(i) {
            i += 1;
        }
        i = digits(s, i)?;
    }
    Ok(i)
}

/// A string's characters with its escapes undone, for a string
/// [`string_end`] accepted. Never fails on another: a bad `\u` escape, a
/// lone surrogate or a final backslash reads as U+FFFD, any other escape as
/// its character.
#[derive(Clone, Debug)]
pub(crate) struct Unescaped<'a> {
    chars: core::str::Chars<'a>,
}

impl<'a> Unescaped<'a> {
    /// Over a string's body, the bytes between its quotes.
    pub(crate) fn new(body: &'a str) -> Self {
        Unescaped {
            chars: body.chars(),
        }
    }

    fn unit(&mut self) -> Option<u32> {
        let mut v = 0;
        for _ in 0..4 {
            let c = u8::try_from(self.chars.next()?).ok()?;
            v = v * 16 + u32::from(crate::hex::nibble(c)?);
        }
        Some(v)
    }
}

impl Iterator for Unescaped<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        let c = self.chars.next()?;
        if c != '\\' {
            return Some(c);
        }
        Some(match self.chars.next() {
            Some('b') => '\u{8}',
            Some('f') => '\u{c}',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('t') => '\t',
            Some('u') => {
                let high = self.unit().unwrap_or(0xFFFD);
                if (0xD800..0xDC00).contains(&high) {
                    // `\uD83D\uDE00`: the second escape is the low half. A
                    // high half without one is U+FFFD, and what follows
                    // reads as itself.
                    let mut ahead = self.clone();
                    if let (Some('\\'), Some('u')) = (ahead.chars.next(), ahead.chars.next()) {
                        if let Some(low @ 0xDC00..=0xDFFF) = ahead.unit() {
                            *self = ahead;
                            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                            return Some(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                    }
                    '\u{FFFD}'
                } else {
                    // A low half alone is no character either.
                    char::from_u32(high).unwrap_or('\u{FFFD}')
                }
            }
            Some(other) => other,
            None => '\u{FFFD}',
        })
    }
}

/// The body of the string at `span`, between its quotes, as written.
pub(crate) fn string_body(s: &[u8], span: Span) -> Result<&str, At> {
    if s.get(span.0) != Some(&b'"') || span.1 < span.0 + 2 {
        return Err(span.0);
    }
    let body = s.get(span.0 + 1..span.1 - 1).ok_or(span.0)?;
    core::str::from_utf8(body).map_err(|_| span.0)
}

/// The string at `span`, with no escape: hex, an address, a name, which
/// serde writes plain.
pub(crate) fn plain(s: &[u8], span: Span) -> Result<&[u8], At> {
    let body = string_body(s, span)?;
    match body.bytes().position(|b| b == b'\\') {
        Some(k) => Err(span.0 + 1 + k),
        None => Ok(body.as_bytes()),
    }
}

/// The members of the object at `span`, in order: each key's span inside
/// its quotes, and its value's.
#[derive(Clone, Debug)]
pub(crate) struct Members<'a> {
    s: &'a [u8],
    i: usize,
}

pub(crate) fn members(s: &[u8], span: Span) -> Result<Members<'_>, At> {
    if s.get(span.0) != Some(&b'{') {
        return Err(span.0);
    }
    Ok(Members {
        s,
        i: ws(s, span.0 + 1),
    })
}

impl Iterator for Members<'_> {
    type Item = (Span, Span);

    fn next(&mut self) -> Option<(Span, Span)> {
        let s = self.s;
        if s.get(self.i) != Some(&b'"') {
            return None;
        }
        let key_end = string_end(s, self.i).ok()?;
        let key = (self.i + 1, key_end - 1);
        let value = member_value(s, self.i).ok()?;
        let value_end = value_end(s, value).ok()?;
        let after = ws(s, value_end);
        self.i = if s.get(after) == Some(&b',') {
            ws(s, after + 1)
        } else {
            after
        };
        Some((key, (value, value_end)))
    }
}

/// The value of `key` in the object at `span`, if there. A key twice is
/// refused, as serde refuses a field twice.
pub(crate) fn member(s: &[u8], span: Span, key: &str) -> Result<Option<Span>, At> {
    let mut found = None;
    for (k, v) in members(s, span)? {
        let name = core::str::from_utf8(s.get(k.0..k.1).ok_or(k.0)?).map_err(|_| k.0)?;
        if Unescaped::new(name).eq(key.chars()) {
            if found.is_some() {
                return Err(k.0);
            }
            found = Some(v);
        }
    }
    Ok(found)
}

/// The value of `key` in the object at `span`, which must be there.
pub(crate) fn required(s: &[u8], span: Span, key: &str) -> Result<Span, At> {
    member(s, span, key)?.ok_or(span.0)
}

/// The value of `key`, absent or `null` read as none: serde's `Option`.
pub(crate) fn optional(s: &[u8], span: Span, key: &str) -> Result<Option<Span>, At> {
    Ok(member(s, span, key)?.filter(|&v| !is_null(s, v)))
}

/// The elements of the array at `span`, in order.
#[derive(Clone, Debug)]
pub(crate) struct Elements<'a> {
    s: &'a [u8],
    i: usize,
}

pub(crate) fn elements(s: &[u8], span: Span) -> Result<Elements<'_>, At> {
    if s.get(span.0) != Some(&b'[') {
        return Err(span.0);
    }
    Ok(Elements {
        s,
        i: ws(s, span.0 + 1),
    })
}

impl Iterator for Elements<'_> {
    type Item = Span;

    fn next(&mut self) -> Option<Span> {
        let s = self.s;
        if s.get(self.i) == Some(&b']') {
            return None;
        }
        let start = self.i;
        let end = value_end(s, start).ok()?;
        let after = ws(s, end);
        self.i = if s.get(after) == Some(&b',') {
            ws(s, after + 1)
        } else {
            after
        };
        Some((start, end))
    }
}

pub(crate) fn is_null(s: &[u8], span: Span) -> bool {
    s.get(span.0..span.1) == Some(b"null")
}

/// The number at `span` as a `u64`: digits alone, no larger than a `u64`.
pub(crate) fn u64_at(s: &[u8], span: Span) -> Result<u64, At> {
    let text = s.get(span.0..span.1).ok_or(span.0)?;
    if text.is_empty() {
        return Err(span.0);
    }
    let mut v: u64 = 0;
    for (k, &c) in text.iter().enumerate() {
        if !c.is_ascii_digit() {
            return Err(span.0 + k);
        }
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(span.0)?;
    }
    Ok(v)
}

/// The string at `span` as `u64::from_str` reads it, as upstream reads the
/// WASM SDK's decimal strings (`consensus/client/src/serializable/string.rs`):
/// an optional `+`, then digits that fit. Escapes are refused; every writer
/// writes these plain.
pub(crate) fn decimal_text_at(s: &[u8], span: Span) -> Result<u64, At> {
    let body = plain(s, span)?;
    let digits = body.strip_prefix(b"+").unwrap_or(body);
    if digits.is_empty() {
        return Err(span.0);
    }
    let mut v: u64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return Err(span.0);
        }
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(span.0)?;
    }
    Ok(v)
}

/// The number at `span` as a `u32`.
pub(crate) fn u32_at(s: &[u8], span: Span) -> Result<u32, At> {
    u32::try_from(u64_at(s, span)?).map_err(|_| span.0)
}

/// The number at `span` as a `u16`.
pub(crate) fn u16_at(s: &[u8], span: Span) -> Result<u16, At> {
    u16::try_from(u64_at(s, span)?).map_err(|_| span.0)
}

/// The number at `span` as an `f64`, finite.
pub(crate) fn f64_at(s: &[u8], span: Span) -> Result<f64, At> {
    let text = s.get(span.0..span.1).ok_or(span.0)?;
    if number_end(s, span.0) != Ok(span.1) {
        return Err(span.0);
    }
    let text = core::str::from_utf8(text).map_err(|_| span.0)?;
    let v: f64 = text.parse().map_err(|_| span.0)?;
    if v.is_finite() {
        Ok(v)
    } else {
        Err(span.0)
    }
}

pub(crate) fn bool_at(s: &[u8], span: Span) -> Result<bool, At> {
    match s.get(span.0..span.1) {
        Some(b"true") => Ok(true),
        Some(b"false") => Ok(false),
        _ => Err(span.0),
    }
}

/// Hex digits, either case as serde reads them, as bytes into `out`.
pub(crate) fn unhex(text: &[u8], at: usize, out: &mut [u8]) -> Result<(), At> {
    if text.len() != 2 * out.len() {
        return Err(at);
    }
    for (k, b) in out.iter_mut().enumerate() {
        let hi = crate::hex::nibble(text[2 * k]).ok_or(at + 2 * k)?;
        let lo = crate::hex::nibble(text[2 * k + 1]).ok_or(at + 2 * k + 1)?;
        *b = hi << 4 | lo;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(s: &str) -> Result<Span, At> {
        document(s.as_bytes())
    }

    /// The grammar is RFC 8259's: what it forbids is refused at the byte
    /// where it goes wrong.
    #[test]
    fn the_grammar_is_rfc_8259s() {
        for good in [
            "{}",
            "[]",
            " {\"a\" : [1, -0, 0.5, 1e9, 1E-9, 2.5e+3, true, false, null, \"\"]} ",
            "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\"",
            "[[[[[[[[]]]]]]]]",
            "{\"\u{e9}\":\"\u{1F600}\"}",
        ] {
            assert!(whole(good).is_ok(), "{good}");
        }
        for (bad, at) in [
            ("", 0),
            ("{", 1),
            ("{\"a\"}", 4),
            ("{\"a\":1,}", 7),
            ("[1,]", 3),
            ("[1 2]", 3),
            ("01", 1),
            ("1.", 2),
            ("-", 1),
            ("+1", 0),
            ("1e", 2),
            ("tru", 0),
            ("\"\\x\"", 1),
            ("\"\\ud83d\"", 7),
            ("\"\\ude00\"", 1),
            ("\"a\nb\"", 2),
            ("{} {}", 3),
            ("[}", 1),
            ("{]", 1),
        ] {
            assert_eq!(whole(bad), Err(at), "{bad:?}");
        }
        // Sixty-four nonempty containers, then an empty one.
        let deep = "[".repeat(65) + &"]".repeat(65);
        assert!(whole(&deep).is_ok());
        let deeper = "[".repeat(66) + &"]".repeat(66);
        assert_eq!(whole(&deeper), Err(65));
        assert_eq!(document(b"\"\xff\""), Err(1));
    }

    /// A key is matched as serde matches it: unescaped, once.
    #[test]
    fn a_key_is_matched_as_serde_matches_it() {
        let s = b"{\"i\\u0064\":7,\"other\":[1,{\"id\":2}],\"n\":null}";
        let doc = document(s).unwrap();
        let id = member(s, doc, "id").unwrap().unwrap();
        assert_eq!(u64_at(s, id), Ok(7));
        assert_eq!(optional(s, doc, "n"), Ok(None));
        assert_eq!(optional(s, doc, "absent"), Ok(None));
        assert!(required(s, doc, "absent").is_err());
        let twice = b"{\"id\":1,\"id\":2}";
        assert_eq!(member(twice, document(twice).unwrap(), "id"), Err(9));
    }

    /// Numbers are read as serde reads them: a `u64` is digits that fit, a
    /// float any finite number.
    #[test]
    fn numbers_are_read_as_serde_reads_them() {
        let s = b"[18446744073709551615,18446744073709551616,1.0,-1,1e3,0.25,1e400]";
        let doc = document(s).unwrap();
        let v: [Span; 7] = core::array::from_fn({
            let mut e = elements(s, doc).unwrap();
            move |_| e.next().unwrap()
        });
        assert_eq!(u64_at(s, v[0]), Ok(u64::MAX));
        assert!(u64_at(s, v[1]).is_err());
        assert!(u64_at(s, v[2]).is_err());
        assert!(u64_at(s, v[3]).is_err());
        assert!(u64_at(s, v[4]).is_err());
        assert_eq!(f64_at(s, v[2]), Ok(1.0));
        assert_eq!(f64_at(s, v[4]), Ok(1000.0));
        assert_eq!(f64_at(s, v[5]), Ok(0.25));
        assert!(f64_at(s, v[6]).is_err());
    }

    /// Escapes are undone when a string is read as text, a surrogate pair
    /// as one character.
    #[test]
    fn escapes_are_undone_when_read_as_text() {
        let s = b"\"a\\\"b\\\\c\\/d\\n\\u00e9\\ud83d\\ude00\"";
        let body = string_body(s, document(s).unwrap()).unwrap();
        let mut out = [0u8; 32];
        let mut n = 0;
        for c in Unescaped::new(body) {
            n += c.encode_utf8(&mut out[n..]).len();
        }
        assert_eq!(&out[..n], "a\"b\\c/d\n\u{e9}\u{1F600}".as_bytes());
        assert!(plain(s, document(s).unwrap()).is_err());
    }

    /// Half a surrogate pair alone reads as U+FFFD, and what follows as
    /// itself. [`string_end`] refuses these first; the reader still never
    /// panics on one or drops what follows.
    #[test]
    fn a_lone_surrogate_reads_as_the_replacement_character() {
        for (body, want) in [
            ("\\ud83d", "\u{FFFD}"),
            ("\\ud83dx", "\u{FFFD}x"),
            ("\\ud83d\\u0041", "\u{FFFD}A"),
            ("\\ud83d\\ud83d\\ude00", "\u{FFFD}\u{1F600}"),
            ("\\ude00y", "\u{FFFD}y"),
            ("\\udbff\\udfff", "\u{10FFFF}"),
            ("\\ud83d\\u00", "\u{FFFD}\u{FFFD}"),
        ] {
            let mut out = [0u8; 32];
            let mut n = 0;
            for c in Unescaped::new(body) {
                n += c.encode_utf8(&mut out[n..]).len();
            }
            assert_eq!(&out[..n], want.as_bytes(), "{body:?}");
        }
    }
}
