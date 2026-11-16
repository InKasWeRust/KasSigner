// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Base58Check, as extended keys are written: Bitcoin's alphabet and a
//! checksum of the first four bytes of SHA-256 over SHA-256. Upstream's
//! `bs58` check mode (`wallet/bip32/src/xkey.rs`) with no allocator: every
//! buffer is the caller's.
//!
//! An extended key is 78 bytes, 82 with its checksum, 111 characters as a
//! kpub; [`encoded_max`] and [`decoded_max`] bound any length.

use sha2::{Digest, Sha256};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const CHECK: usize = 4;

/// Why a decode was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base58Error {
    /// A character outside the alphabet.
    BadCharacter { at: usize },
    /// The checksum does not hold.
    BadChecksum,
    /// Shorter than a checksum.
    TooShort,
    /// The caller's buffer cannot hold the result.
    BufferTooSmall,
}

/// Characters the encoding of `n` payload bytes can take.
pub const fn encoded_max(n: usize) -> usize {
    // log(256)/log(58) is 1.3657...; 138/100 is above it.
    (n + CHECK) * 138 / 100 + 1
}

/// Bytes a decode of `n` characters can produce, checksum included.
pub const fn decoded_max(n: usize) -> usize {
    // log(58)/log(256) is 0.7322...; 733/1000 is above it.
    n * 733 / 1000 + 1
}

fn checksum(payload: &[u8]) -> [u8; CHECK] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut c = [0u8; CHECK];
    c.copy_from_slice(&second[..CHECK]);
    c
}

/// Encode `payload` with its checksum into `out`; the characters written.
/// `scratch`, at least `payload.len() + 4`, is left holding the payload and
/// checksum, for the caller to wipe if secret.
///
/// # Errors
///
/// `BufferTooSmall` for either buffer.
pub fn encode_check(
    payload: &[u8],
    scratch: &mut [u8],
    out: &mut [u8],
) -> Result<usize, Base58Error> {
    let n = payload.len() + CHECK;
    let bytes = scratch.get_mut(..n).ok_or(Base58Error::BufferTooSmall)?;
    bytes[..payload.len()].copy_from_slice(payload);
    bytes[payload.len()..].copy_from_slice(&checksum(payload));
    encode(bytes, out)
}

/// Decode `text`, verify its checksum, and write the payload into `out`;
/// the bytes written.
///
/// # Errors
///
/// `BadCharacter`, `TooShort`, `BadChecksum`, `BufferTooSmall`. On
/// `BadChecksum` the payload was written and the caller wipes it.
pub fn decode_check(text: &[u8], out: &mut [u8]) -> Result<usize, Base58Error> {
    let n = decode(text, out)?;
    if n < CHECK {
        return Err(Base58Error::TooShort);
    }
    let (payload, check) = out[..n].split_at(n - CHECK);
    if checksum(payload) != check {
        return Err(Base58Error::BadChecksum);
    }
    Ok(n - CHECK)
}

fn encode(bytes: &[u8], out: &mut [u8]) -> Result<usize, Base58Error> {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // Base 256 to base 58, least significant digit first, at the front of
    // `out`.
    let mut len = 0usize;
    for &b in &bytes[zeros..] {
        let mut carry = u32::from(b);
        for digit in out[..len].iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            if len >= out.len() {
                return Err(Base58Error::BufferTooSmall);
            }
            out[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }
    if zeros + len > out.len() {
        return Err(Base58Error::BufferTooSmall);
    }
    // Leading zero bytes are leading '1's; then the digits reversed.
    out.copy_within(..len, zeros);
    for c in &mut out[..zeros] {
        *c = ALPHABET[0];
    }
    for c in &mut out[zeros..zeros + len] {
        *c = ALPHABET[usize::from(*c)];
    }
    out[zeros..zeros + len].reverse();
    Ok(zeros + len)
}

fn value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

fn decode(text: &[u8], out: &mut [u8]) -> Result<usize, Base58Error> {
    let ones = text.iter().take_while(|&&c| c == ALPHABET[0]).count();
    let mut len = 0usize;
    for (at, &c) in text.iter().enumerate().skip(ones) {
        let mut carry = u32::from(value(c).ok_or(Base58Error::BadCharacter { at })?);
        for byte in out[..len].iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if len >= out.len() {
                return Err(Base58Error::BufferTooSmall);
            }
            out[len] = (carry & 0xff) as u8;
            len += 1;
            carry >>= 8;
        }
    }
    if ones + len > out.len() {
        return Err(Base58Error::BufferTooSmall);
    }
    out.copy_within(..len, ones);
    for b in &mut out[..ones] {
        *b = 0;
    }
    out[ones..ones + len].reverse();
    Ok(ones + len)
}
