// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa address encoding (upstream: `crypto/addresses/src/lib.rs`,
//! `bech32.rs`).
//!
//! Bech32 with Kaspa's own checksum generator, a version byte before the
//! payload, and the network prefix in the checksum: a mainnet address cannot
//! be read as a testnet one.
//!
//! The prefix is a parameter, and nothing is allocated: output goes to the
//! caller's buffer, and the arrays below are sized by the format (a payload
//! is at most 33 bytes, a compressed key).

/// Network prefix: in the checksum, so part of the address, not a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    Mainnet,
    Testnet,
    Simnet,
    Devnet,
}

impl Prefix {
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Prefix::Mainnet => b"kaspa",
            Prefix::Testnet => b"kaspatest",
            Prefix::Simnet => b"kaspasim",
            Prefix::Devnet => b"kaspadev",
        }
    }

    pub fn from_bytes(s: &[u8]) -> Option<Self> {
        match s {
            b"kaspa" => Some(Prefix::Mainnet),
            b"kaspatest" => Some(Prefix::Testnet),
            b"kaspasim" => Some(Prefix::Simnet),
            b"kaspadev" => Some(Prefix::Devnet),
            _ => None,
        }
    }
}

/// Address version. The discriminants are the byte written on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Version {
    /// Schnorr public key, 32 bytes.
    PubKey = 0,
    /// ECDSA public key, 33 bytes.
    PubKeyEcdsa = 1,
    /// Script hash, 32 bytes. Eight, not two, as upstream.
    ScriptHash = 8,
}

impl Version {
    /// Payload length this version requires; a mismatch is refused.
    pub const fn payload_len(self) -> usize {
        match self {
            Version::PubKey => 32,
            Version::PubKeyEcdsa => 33,
            Version::ScriptHash => 32,
        }
    }

    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Version::PubKey),
            1 => Some(Version::PubKeyEcdsa),
            8 => Some(Version::ScriptHash),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Payload length does not match the version.
    BadPayloadLength,
    /// Caller's buffer is too small. `MAX_ADDRESS_LEN` is always enough.
    BufferTooSmall,
    /// No prefix separator, or a prefix that is not a Kaspa network.
    BadPrefix,
    /// A character outside the bech32 alphabet.
    BadCharacter,
    /// Checksum did not verify. Also what a wrong-network address produces.
    BadChecksum,
    /// Too short to contain a version byte and a checksum.
    TooShort,
    /// Version byte is not one Kaspa defines.
    BadVersion,
}

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Longest address any version and prefix can produce: `kaspatest:` (10),
/// 34 bytes of version and payload as 55 five-bit groups, 8 of checksum.
pub const MAX_ADDRESS_LEN: usize = 10 + 55 + 8;

/// Largest version byte plus payload, in bytes.
const MAX_RAW: usize = 1 + 33;
/// The same, expanded to five-bit groups with right padding.
const MAX_FIVEBIT: usize = MAX_RAW * 8 / 5 + 1;

/// Kaspa's bech32 checksum generator (upstream: `polymod`), whose five
/// constants are not Bitcoin's. Upstream groups them as `0x98f2_bc8e_61`;
/// here with a leading `00`, in fours, same values.
fn polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &d in values {
        let c0 = c >> 35;
        c = ((c & 0x0007_ffff_ffff) << 5) ^ (d as u64);
        if c0 & 0x01 != 0 {
            c ^= 0x0098_f2bc_8e61;
        }
        if c0 & 0x02 != 0 {
            c ^= 0x0079_b76d_99e2;
        }
        if c0 & 0x04 != 0 {
            c ^= 0x00f3_3e5f_b3c4;
        }
        if c0 & 0x08 != 0 {
            c ^= 0x00ae_2eab_e2a8;
        }
        if c0 & 0x10 != 0 {
            c ^= 0x001e_4f43_e470;
        }
    }
    c ^ 1
}

/// Expand bytes into five-bit groups, right-padded; the groups written.
fn conv8to5(input: &[u8], out: &mut [u8]) -> usize {
    let padding = usize::from(!input.len().is_multiple_of(5));
    let n = input.len() * 8 / 5 + padding;
    let mut buff: u16 = 0;
    let mut bits: u8 = 0;
    let mut idx = 0;
    for &b in input {
        buff = (buff << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[idx] = ((buff >> bits) & 0x1f) as u8;
            idx += 1;
        }
    }
    if bits > 0 {
        out[idx] = ((buff << (5 - bits)) & 0x1f) as u8;
        idx += 1;
    }
    debug_assert_eq!(idx, n);
    n
}

/// Collapse five-bit groups into bytes, dropping the padding; the bytes
/// written.
fn conv5to8(input: &[u8], out: &mut [u8]) -> usize {
    let mut buff: u16 = 0;
    let mut bits: u8 = 0;
    let mut idx = 0;
    for &g in input {
        buff = (buff << 5) | g as u16;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if idx >= out.len() {
                return idx;
            }
            out[idx] = (buff >> bits) as u8;
            idx += 1;
        }
    }
    idx
}

/// Checksum over the prefix, a separator zero, the payload, and eight zeros.
fn checksum(prefix: Prefix, fivebit_payload: &[u8]) -> u64 {
    let mut buf = [0u8; 9 + 1 + MAX_FIVEBIT + 8];
    let p = prefix.as_bytes();
    let mut n = 0;
    for &c in p {
        buf[n] = c & 0x1f;
        n += 1;
    }
    buf[n] = 0;
    n += 1;
    buf[n..n + fivebit_payload.len()].copy_from_slice(fivebit_payload);
    n += fivebit_payload.len();
    n += 8; // eight trailing zeros, already zeroed
    polymod(&buf[..n])
}

/// Encode an address into `out`, [`MAX_ADDRESS_LEN`] always enough; the
/// bytes written.
pub fn encode(
    prefix: Prefix,
    version: Version,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, AddressError> {
    if payload.len() != version.payload_len() {
        return Err(AddressError::BadPayloadLength);
    }

    let mut raw = [0u8; MAX_RAW];
    raw[0] = version as u8;
    raw[1..1 + payload.len()].copy_from_slice(payload);

    let mut fivebit = [0u8; MAX_FIVEBIT];
    let n5 = conv8to5(&raw[..1 + payload.len()], &mut fivebit);

    let cs = checksum(prefix, &fivebit[..n5]);
    // The generator is 40 bits, so the checksum is the low five bytes.
    let mut cs5 = [0u8; 8];
    let n_cs = conv8to5(&cs.to_be_bytes()[3..], &mut cs5);

    let p = prefix.as_bytes();
    let total = p.len() + 1 + n5 + n_cs;
    if out.len() < total {
        return Err(AddressError::BufferTooSmall);
    }

    let mut i = 0;
    out[i..i + p.len()].copy_from_slice(p);
    i += p.len();
    out[i] = b':';
    i += 1;
    for &g in &fivebit[..n5] {
        out[i] = CHARSET[g as usize];
        i += 1;
    }
    for &g in &cs5[..n_cs] {
        out[i] = CHARSET[g as usize];
        i += 1;
    }
    Ok(i)
}

/// Decode and verify an address, its payload into `payload_out`. Returns its
/// prefix, version and payload length. Another network's address fails the
/// checksum.
pub fn decode(
    address: &[u8],
    payload_out: &mut [u8],
) -> Result<(Prefix, Version, usize), AddressError> {
    let sep = address
        .iter()
        .position(|&c| c == b':')
        .ok_or(AddressError::BadPrefix)?;
    let prefix = Prefix::from_bytes(&address[..sep]).ok_or(AddressError::BadPrefix)?;
    let body = &address[sep + 1..];
    if body.len() < 9 {
        return Err(AddressError::TooShort);
    }

    // Longer than any payload and checksum: a wrong payload length, as the
    // same check on the bytes below says.
    let mut fivebit = [0u8; MAX_FIVEBIT + 8];
    if body.len() > fivebit.len() {
        return Err(AddressError::BadPayloadLength);
    }
    for (i, &c) in body.iter().enumerate() {
        let v = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or(AddressError::BadCharacter)?;
        fivebit[i] = v as u8;
    }
    let n = body.len();

    // The last eight groups are the checksum: as upstream, five bytes read
    // as a big-endian u64 against the one recomputed.
    let (payload_u5, checksum_u5) = fivebit[..n].split_at(n - 8);
    let mut cs_bytes = [0u8; 8];
    let n_cs = conv5to8(checksum_u5, &mut cs_bytes[3..]);
    if n_cs != 5 {
        return Err(AddressError::BadChecksum);
    }
    if checksum(prefix, payload_u5) != u64::from_be_bytes(cs_bytes) {
        return Err(AddressError::BadChecksum);
    }

    // Back to bytes.
    let mut raw = [0u8; MAX_RAW];
    let mut buff: u16 = 0;
    let mut bits: u8 = 0;
    let mut idx = 0;
    for &g in payload_u5 {
        buff = (buff << 5) | g as u16;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if idx >= raw.len() {
                return Err(AddressError::BadPayloadLength);
            }
            raw[idx] = (buff >> bits) as u8;
            idx += 1;
        }
    }
    if idx == 0 {
        return Err(AddressError::TooShort);
    }

    let version = Version::from_u8(raw[0]).ok_or(AddressError::BadVersion)?;
    let plen = idx - 1;
    if plen != version.payload_len() {
        return Err(AddressError::BadPayloadLength);
    }
    if payload_out.len() < plen {
        return Err(AddressError::BufferTooSmall);
    }
    payload_out[..plen].copy_from_slice(&raw[1..1 + plen]);
    Ok((prefix, version, plen))
}

#[cfg(test)]
mod too_long {
    use super::{decode, AddressError, MAX_FIVEBIT};

    /// **An address longer than any payload is a wrong payload length**, not
    /// too short: one character past the longest body, then the longest,
    /// which the checksum refuses.
    #[test]
    fn is_a_wrong_payload_length() {
        const LONGEST: usize = MAX_FIVEBIT + 8;
        let mut address = [b'q'; 6 + LONGEST + 1];
        address[..6].copy_from_slice(b"kaspa:");
        let mut out = [0u8; 40];
        assert_eq!(
            decode(&address, &mut out),
            Err(AddressError::BadPayloadLength)
        );
        assert_eq!(
            decode(&address[..6 + LONGEST], &mut out),
            Err(AddressError::BadChecksum)
        );
    }
}
