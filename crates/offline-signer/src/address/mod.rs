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

// KasSigner — Kaspa Address Encoding
// 100% Rust, no-std, no-alloc
//
// Kaspa addresses use a custom Bech32 encoding with 40-bit (8-char) checksum.
// Verified against official rusty-kaspa test vectors.
//
// Address types (version bytes):
//   0x00 = P2PK (Pay to Public Key) — Schnorr, 32-byte x-only pubkey
//   0x01 = P2PK-ECDSA — 33-byte compressed pubkey
//   0x08 = P2SH (Pay to Script Hash) — 32-byte script hash

/// Bech32 character set
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Maximum address length buffer
pub const MAX_ADDR_LEN: usize = 80;

/// Kaspa address type
#[derive(Debug, Clone, Copy, PartialEq)]
/// Kaspa address type prefix (P2PK, P2SH, etc.).
pub enum AddressType {
    P2pk = 0x00,
    P2pkEcdsa = 0x01,
    P2sh = 0x08,
}

/// Network used to render a Kaspa address HRP. `Unknown` is reserved for
/// legacy transaction envelopes that did not bind network metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KaspaNetwork {
    Unknown = 0,
    Mainnet = 1,
    Testnet = 2,
    Devnet = 3,
    Simnet = 4,
}

const NETWORK_HRPS: [Option<&[u8]>; 5] = [
    None,
    Some(b"kaspa"),
    Some(b"kaspatest"),
    Some(b"kaspadev"),
    Some(b"kaspasim"),
];
const NETWORK_LABELS: [&str; 5] = ["NETWORK UNKNOWN", "MAINNET", "TESTNET", "DEVNET", "SIMNET"];
const NETWORK_BY_WIRE: [Option<KaspaNetwork>; 5] = [
    None,
    Some(KaspaNetwork::Mainnet),
    Some(KaspaNetwork::Testnet),
    Some(KaspaNetwork::Devnet),
    Some(KaspaNetwork::Simnet),
];

impl KaspaNetwork {
    pub const fn hrp(self) -> Option<&'static [u8]> {
        NETWORK_HRPS[self as usize]
    }

    pub const fn label(self) -> &'static str {
        NETWORK_LABELS[self as usize]
    }

    pub fn from_name(name: &str) -> Option<Self> {
        exact_network_name(name).or_else(|| name.starts_with("testnet").then_some(Self::Testnet))
    }

    pub const fn from_wire(value: u8) -> Option<Self> {
        if value > Self::Simnet as u8 {
            return None;
        }
        NETWORK_BY_WIRE[value as usize]
    }
}

fn exact_network_name(name: &str) -> Option<KaspaNetwork> {
    const NAMES: [(&str, KaspaNetwork); 7] = [
        ("mainnet", KaspaNetwork::Mainnet),
        ("kaspatest", KaspaNetwork::Testnet),
        ("devnet", KaspaNetwork::Devnet),
        ("kaspadev", KaspaNetwork::Devnet),
        ("simnet", KaspaNetwork::Simnet),
        ("kaspasim", KaspaNetwork::Simnet),
        ("testnet", KaspaNetwork::Testnet),
    ];
    NAMES
        .iter()
        .find_map(|(candidate, network)| (*candidate == name).then_some(*network))
}

/// Encode a Kaspa address for an explicit network. Returns bytes written to `out`.
pub fn encode_address_for_network(
    pubkey: &[u8],
    addr_type: AddressType,
    network: KaspaNetwork,
    out: &mut [u8; MAX_ADDR_LEN],
) -> usize {
    let Some(hrp) = network.hrp() else {
        return 0;
    };
    let pk_len = pubkey.len();
    let mut payload = [0u8; 34];
    payload[0] = addr_type as u8;
    payload[1..=pk_len].copy_from_slice(pubkey);
    let payload_len = 1 + pk_len;

    let mut data5 = [0u8; 56];
    let data5_len = convert_bits_8to5(&payload, payload_len, &mut data5);
    let checksum = create_checksum(hrp, &data5[..data5_len]);

    let needed = hrp.len() + 1 + data5_len + 8;
    if needed > out.len() {
        return 0;
    }
    let mut pos = 0;
    out[..hrp.len()].copy_from_slice(hrp);
    pos += hrp.len();
    out[pos] = b':';
    pos += 1;
    for i in 0..data5_len {
        out[pos] = CHARSET[data5[i] as usize];
        pos += 1;
    }
    for i in 0..8 {
        out[pos] = CHARSET[((checksum >> (5 * (7 - i))) & 0x1F) as usize];
        pos += 1;
    }
    pos
}

/// Mainnet compatibility helper for non-transaction wallet screens. Transaction
/// review code must use `encode_address_for_network` with bound network metadata.
pub fn encode_address(
    pubkey: &[u8],
    addr_type: AddressType,
    out: &mut [u8; MAX_ADDR_LEN],
) -> usize {
    encode_address_for_network(pubkey, addr_type, KaspaNetwork::Mainnet, out)
}

/// Encode P2PK address from 32-byte x-only pubkey
pub fn encode_p2pk(pubkey: &[u8; 32], out: &mut [u8; MAX_ADDR_LEN]) -> usize {
    encode_address(pubkey, AddressType::P2pk, out)
}

/// Encode address and return as str slice
pub fn encode_address_str_for_network<'a>(
    pubkey: &[u8; 32],
    addr_type: AddressType,
    network: KaspaNetwork,
    buf: &'a mut [u8; MAX_ADDR_LEN],
) -> &'a str {
    let len = encode_address_for_network(pubkey, addr_type, network, buf);
    core::str::from_utf8(&buf[..len]).unwrap_or("address:error")
}

pub fn encode_address_str<'a>(
    pubkey: &[u8; 32],
    addr_type: AddressType,
    buf: &'a mut [u8; MAX_ADDR_LEN],
) -> &'a str {
    encode_address_str_for_network(pubkey, addr_type, KaspaNetwork::Mainnet, buf)
}

/// Validate a Kaspa address string (known network HRP + checksum + format).
/// Accepts mainnet, testnet, devnet, and simnet addresses without rewriting
/// one network prefix into another.
pub fn validate_kaspa_address(addr: &[u8]) -> bool {
    let Some(colon) = addr.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let hrp = &addr[..colon];
    if !is_known_hrp(hrp) {
        return false;
    }
    let data_part = &addr[colon + 1..];
    if !(57..=69).contains(&data_part.len()) {
        return false;
    }

    let mut data5 = [0u8; 72];
    for (index, &ch) in data_part.iter().enumerate() {
        let value = bech32_char_to_val(ch);
        if value == 0xFF {
            return false;
        }
        data5[index] = value;
    }

    let mut values = [0u8; 128];
    let mut hrp_buf = [0u8; 16];
    let hrp_len = hrp_expand(hrp, &mut hrp_buf);
    values[..hrp_len].copy_from_slice(&hrp_buf[..hrp_len]);
    values[hrp_len..hrp_len + data_part.len()].copy_from_slice(&data5[..data_part.len()]);
    polymod(&values, hrp_len + data_part.len()) == 1
}

fn is_known_hrp(hrp: &[u8]) -> bool {
    matches!(hrp, b"kaspa" | b"kaspatest" | b"kaspadev" | b"kaspasim")
}

/// Decode a bech32 character to its 5-bit value. Returns 0xFF on invalid.
fn bech32_char_to_val(ch: u8) -> u8 {
    CHARSET
        .iter()
        .position(|&candidate| candidate == ch)
        .map_or(0xFF, |index| index as u8)
}

fn convert_bits_8to5(data: &[u8], len: usize, out: &mut [u8; 56]) -> usize {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut pos = 0;
    for &byte in data.iter().take(len) {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[pos] = ((acc >> bits) & 0x1F) as u8;
            pos += 1;
        }
    }
    if bits > 0 {
        out[pos] = ((acc << (5 - bits)) & 0x1F) as u8;
        pos += 1;
    }
    pos
}

fn polymod(values: &[u8], values_len: usize) -> u64 {
    const GEN: [u64; 5] = [
        0x98f2bc8e61,
        0x79b76d99e2,
        0xf33e5fb3c4,
        0xae2eabe2a8,
        0x1e4f43e470,
    ];
    let mut chk: u64 = 1;
    for &value in values.iter().take(values_len) {
        let top = chk >> 35;
        chk = ((chk & 0x07_FFFF_FFFF) << 5) ^ u64::from(value);
        for (bit, &generator) in GEN.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

/// Expand prefix for checksum calculation (CashAddr-style, NOT Bech32-style)
/// CashAddr: lower 5 bits of each character + trailing 0
/// Bech32:   high bits + 0 + low bits (NOT used by Kaspa)
fn hrp_expand(hrp: &[u8], out: &mut [u8; 16]) -> usize {
    let hrp_len = hrp.len();
    let mut pos = 0;
    for &byte in hrp.iter().take(hrp_len) {
        out[pos] = byte & 0x1F;
        pos += 1;
    }
    out[pos] = 0;
    pos += 1;
    pos
}

fn create_checksum(hrp: &[u8], data: &[u8]) -> u64 {
    let mut values = [0u8; 128];
    let mut pos = 0;
    let mut hrp_buf = [0u8; 16];
    let hrp_len = hrp_expand(hrp, &mut hrp_buf);
    values[pos..pos + hrp_len].copy_from_slice(&hrp_buf[..hrp_len]);
    pos += hrp_len;
    let data_len = data.len();
    values[pos..pos + data_len].copy_from_slice(data);
    pos += data_len;
    pos += 8; // 8 zeros for checksum
    let pm = polymod(&values, pos);
    pm ^ 1
}

// ═══════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "unit_tests/address_tests.rs"]
pub mod unit_tests;
