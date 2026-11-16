// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A kpub as it travels, and a cosigner's file.
//!
//! A kpub travels as base58 text, `kpub...`, or raw: the marker byte `0x01`
//! and the 78-byte body, as v1.0.7 sent it and v1.1.0's
//! [`Format::Kpub`](crate::frame::Format::Kpub) frames carry it.
//!
//! A cosigner's kpub on the card carries its origin in the key-origin form
//! of wallet descriptors, `[73c5da0a/45'/111111'/0']kpub...`. A watch-only
//! `44'` kpub has the same depth and child, so only the file says which,
//! and a group takes no file that does not. Both layouts are ours and hold
//! no secret, so they live here, where an integrator can reach them.

use kassigner_kaspa::bip32_public::{
    ChildNumber, ExtendedPublicKey, Prefix, EXTENDED_KEY_SIZE, HARDENED_OFFSET, TEXT_MAX,
};

/// v1.0.7's marker for a kpub's raw form.
pub const RAW_MARK: u8 = 0x01;

/// A kpub's raw form: the marker and the body.
pub const RAW_LEN: usize = 1 + EXTENDED_KEY_SIZE;

/// Whether `bytes` begin as a kpub's raw form: the marker and a mainnet
/// kpub's version, five fixed bytes that tell a scanner v1.0.7's frame zero
/// is a kpub.
pub fn starts_raw(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[0] == RAW_MARK && bytes[1..5] == Prefix::Kpub.version().to_be_bytes()
}

/// `key`'s raw form into `out`: [`RAW_LEN`] bytes, or `None` if `out` is
/// too short.
pub fn write_raw(key: &ExtendedPublicKey, out: &mut [u8]) -> Option<usize> {
    let out = out.get_mut(..RAW_LEN)?;
    out[0] = RAW_MARK;
    key.serialize(Prefix::Kpub, &mut out[1..]).ok()?;
    Some(RAW_LEN)
}

/// The kpub in `bytes`, as text or raw form: a mainnet kpub's version and a
/// key a child derives from, so a code that only looks like one is refused.
pub fn read(bytes: &[u8]) -> Option<ExtendedPublicKey> {
    let key = if bytes.len() == RAW_LEN && starts_raw(bytes) {
        ExtendedPublicKey::deserialize(&bytes[1..]).ok()?
    } else if bytes.starts_with(b"kpub") {
        ExtendedPublicKey::from_text(bytes).ok()?
    } else {
        return None;
    };
    match key {
        (Prefix::Kpub, key) if key.derive_child(ChildNumber(0)).is_ok() => Some(key),
        _ => None,
    }
}

/// A cosigner's path, `m/45'/111111'/0'`, as its file writes it.
pub const COSIGNER_PATH: &[u8] = b"/45'/111111'/0'";

/// The longest cosigner file: `[`, fingerprint, path, `]`, kpub text.
pub const COSIGNER_MAX: usize = 1 + 8 + COSIGNER_PATH.len() + 1 + TEXT_MAX;

/// The cosigner file of `fingerprint` and the text `kpub` into `out`: its
/// length, or `None` if `out` is too short.
pub fn write_cosigner(fingerprint: [u8; 4], kpub: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = 1 + 8 + COSIGNER_PATH.len() + 1 + kpub.len();
    let out = out.get_mut(..n)?;
    out[0] = b'[';
    write_hex(&fingerprint, &mut out[1..9]);
    let path = 9 + COSIGNER_PATH.len();
    out[9..path].copy_from_slice(COSIGNER_PATH);
    out[path] = b']';
    out[path + 1..].copy_from_slice(kpub);
    Some(n)
}

/// The key in a cosigner file: eight hex digits and the cosigner path in
/// brackets, then a kpub [`read`] takes, at the path's depth 3 and child
/// `0'`. A bare kpub is not one.
pub fn read_cosigner(bytes: &[u8]) -> Option<ExtendedPublicKey> {
    let rest = bytes.strip_prefix(b"[")?;
    let (fingerprint, rest) = rest.split_at_checked(8)?;
    if !fingerprint.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let text = rest.strip_prefix(COSIGNER_PATH)?.strip_prefix(b"]")?;
    if !text.starts_with(b"kpub") {
        return None;
    }
    let key = read(text)?;
    (key.depth == 3 && key.child_number == ChildNumber(HARDENED_OFFSET)).then_some(key)
}

/// `bytes` as lowercase hex, into `out`, which holds twice their length.
fn write_hex(bytes: &[u8], out: &mut [u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = DIGITS[usize::from(b >> 4)];
        out[i * 2 + 1] = DIGITS[usize::from(b & 0x0F)];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 12-word abandon seed's `m/44'/111111'/0'` account
    /// (`kassigner-crypto/tests/v107.rs`).
    const ABANDON_44: &[u8] = b"kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";

    /// Text and raw form read as one key; a raw form a byte short or with
    /// another marker, and text of another prefix, are not kpubs.
    #[test]
    fn text_and_raw_form_read_as_one_key() {
        let key = read(ABANDON_44).expect("text");
        let mut raw = [0u8; RAW_LEN];
        assert_eq!(write_raw(&key, &mut raw), Some(RAW_LEN));
        assert!(starts_raw(&raw));
        assert_eq!(read(&raw), Some(key));
        assert!(read(&raw[..RAW_LEN - 1]).is_none());
        let mut other = raw;
        other[0] = 0x02;
        assert!(!starts_raw(&other));
        assert!(read(&other).is_none());
        assert!(read(b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8").is_none());
        assert!(write_raw(&key, &mut [0u8; RAW_LEN - 1]).is_none());
    }

    /// A cosigner's file reads back as written; a bare kpub, a fingerprint
    /// that is not hex, another path, and a key at another depth are refused.
    #[test]
    fn a_cosigner_file_reads_back_as_written() {
        let key = read(ABANDON_44).expect("text");
        let mut file = [0u8; COSIGNER_MAX];
        let n = write_cosigner([0x73, 0xc5, 0xda, 0x0a], ABANDON_44, &mut file).unwrap();
        assert!(file[..n].starts_with(b"[73c5da0a/45'/111111'/0']kpub"));
        // A 44' account has a 45' one's depth and child: only the file says
        // which.
        assert_eq!(read_cosigner(&file[..n]), Some(key));
        assert!(read_cosigner(ABANDON_44).is_none(), "a bare kpub");
        let mut bad = file;
        bad[1] = b'g';
        assert!(read_cosigner(&bad[..n]).is_none(), "not hex");
        let mut path = [0u8; COSIGNER_MAX];
        let m = write_cosigner([0; 4], ABANDON_44, &mut path).unwrap();
        path[10..12].copy_from_slice(b"44");
        assert!(read_cosigner(&path[..m]).is_none(), "another path");
        assert!(write_cosigner([0; 4], ABANDON_44, &mut [0u8; 8]).is_none());
        let child = key.derive_child(ChildNumber(0)).unwrap();
        let mut text = [0u8; TEXT_MAX];
        let t = child.to_text(Prefix::Kpub, &mut text).unwrap();
        let mut deep = [0u8; COSIGNER_MAX];
        let d = write_cosigner([0; 4], &text[..t], &mut deep).unwrap();
        assert!(read_cosigner(&deep[..d]).is_none(), "depth 4");
    }
}
