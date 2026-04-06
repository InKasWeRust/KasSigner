// KasSee Web — Kaspa address encoding
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// address.rs — Encode/decode Kaspa addresses.
// Format: "{prefix}:" + bech32-like encoding of [version_byte][payload]
// Checksum matches rusty-kaspa/crypto/addresses/src/bech32.rs exactly.
// Supports: kaspa (mainnet), kaspatest (testnet), kaspasim, kaspadev

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const REV_CHARSET: [u8; 123] = [
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
     15, 100,  10,  17,  21,  20,  26,  30,   7,   5, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100,  29, 100,  24,  13,  25,   9,   8,  23, 100,  18,  22,  31,  27,  19, 100,
      1,   0,   3,  16,  11,  28,  12,  14,   6,   4,   2,
];

/// Encode a 32-byte x-only public key as a Kaspa P2PK address with given prefix
pub fn encode_p2pk_address(pubkey: &[u8; 32], prefix: &str) -> String {
    encode_address(pubkey, 0x00, prefix)
}

/// Encode a 32-byte script hash as a Kaspa P2SH address with given prefix
pub fn encode_p2sh_address(script_hash: &[u8; 32], prefix: &str) -> String {
    encode_address(script_hash, 0x08, prefix)
}

/// Decode a Kaspa address → (version_byte, 32-byte payload)
pub fn decode_address(addr: &str) -> Result<(u8, [u8; 32]), String> {
    let prefix = if addr.starts_with("kaspa:") { "kaspa" }
        else if addr.starts_with("kaspatest:") { "kaspatest" }
        else if addr.starts_with("kaspasim:") { "kaspasim" }
        else if addr.starts_with("kaspadev:") { "kaspadev" }
        else { return Err("Unknown address prefix".into()); };

    let data_part = &addr[prefix.len() + 1..]; // skip "prefix:"
    if data_part.len() < 9 {
        return Err("Address too short".into());
    }

    // Decode bech32 characters → 5-bit values
    let mut values5 = Vec::with_capacity(data_part.len());
    for &b in data_part.as_bytes() {
        if (b as usize) >= REV_CHARSET.len() || REV_CHARSET[b as usize] == 100 {
            return Err(format!("Invalid character: '{}'", b as char));
        }
        values5.push(REV_CHARSET[b as usize]);
    }

    // Split payload and checksum (8 five-bit chars)
    let (payload5, checksum5) = values5.split_at(values5.len() - 8);

    // Verify checksum
    let fivebit_prefix = prefix.as_bytes().iter().map(|&c| c & 0x1f);
    let computed = checksum_value(payload5, fivebit_prefix);
    let expected = {
        let cs8 = conv5to8(checksum5);
        let mut buf = [0u8; 8];
        buf[3..3 + cs8.len().min(5)].copy_from_slice(&cs8[..cs8.len().min(5)]);
        u64::from_be_bytes(buf)
    };

    if computed != expected {
        return Err(format!("Checksum mismatch: computed {:#x}, expected {:#x}", computed, expected));
    }

    // Convert 5-bit → 8-bit
    let payload8 = conv5to8(payload5);
    if payload8.len() < 33 {
        return Err(format!("Payload too short: {} bytes", payload8.len()));
    }

    let version = payload8[0];
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload8[1..33]);

    Ok((version, hash))
}

/// Build script_public_key bytes from an address string
pub fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, String> {
    let (version, hash) = decode_address(addr)?;
    match version {
        0x00 => {
            // P2PK: OP_DATA_32 <pubkey> OP_CHECKSIG
            let mut script = Vec::with_capacity(34);
            script.push(0x20);
            script.extend_from_slice(&hash);
            script.push(0xAC);
            Ok(script)
        }
        0x08 => {
            // P2SH: OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL
            let mut script = Vec::with_capacity(35);
            script.push(0xAA);
            script.push(0x20);
            script.extend_from_slice(&hash);
            script.push(0x87);
            Ok(script)
        }
        _ => Err(format!("Unknown version: {:#x}", version)),
    }
}

// ─── Internal ───

fn encode_address(payload: &[u8; 32], version: u8, prefix: &str) -> String {
    let mut data8 = Vec::with_capacity(33);
    data8.push(version);
    data8.extend_from_slice(payload);

    let fivebit_payload = conv8to5(&data8);
    let fivebit_prefix = prefix.as_bytes().iter().map(|&c| c & 0x1f);

    let cs = checksum_value(&fivebit_payload, fivebit_prefix);

    // Encode checksum: take bytes 3..8 of big-endian u64, convert to 5-bit
    let cs_bytes = cs.to_be_bytes();
    let cs5 = conv8to5(&cs_bytes[3..]);

    let mut result = String::with_capacity(prefix.len() + 1 + fivebit_payload.len() + cs5.len());
    result.push_str(prefix);
    result.push(':');
    for &v in &fivebit_payload {
        result.push(CHARSET[v as usize] as char);
    }
    for &v in &cs5 {
        result.push(CHARSET[v as usize] as char);
    }

    result
}

// Polymod — matches rusty-kaspa exactly
fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    let mut c = 1u64;
    for d in values {
        let c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ (d as u64);
        if c0 & 0x01 != 0 { c ^= 0x98f2bc8e61; }
        if c0 & 0x02 != 0 { c ^= 0x79b76d99e2; }
        if c0 & 0x04 != 0 { c ^= 0xf33e5fb3c4; }
        if c0 & 0x08 != 0 { c ^= 0xae2eabe2a8; }
        if c0 & 0x10 != 0 { c ^= 0x1e4f43e470; }
    }
    c ^ 1
}

fn checksum_value(payload: &[u8], prefix: impl Iterator<Item = u8>) -> u64 {
    polymod(prefix.chain([0u8]).chain(payload.iter().copied()).chain([0u8; 8]))
}

// Convert 8-bit array to 5-bit array with right padding
fn conv8to5(payload: &[u8]) -> Vec<u8> {
    let padding = if payload.len() % 5 == 0 { 0 } else { 1 };
    let mut five_bit = vec![0u8; payload.len() * 8 / 5 + padding];
    let mut current_idx = 0;
    let mut buff = 0u16;
    let mut bits = 0u8;
    for &c in payload {
        buff = (buff << 8) | c as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five_bit[current_idx] = (buff >> bits) as u8;
            buff &= (1 << bits) - 1;
            current_idx += 1;
        }
    }
    if bits > 0 {
        five_bit[current_idx] = (buff << (5 - bits)) as u8;
    }
    five_bit
}

// Convert 5-bit array to 8-bit array, ignore right side padding
fn conv5to8(payload: &[u8]) -> Vec<u8> {
    let mut eight_bit = vec![0u8; payload.len() * 5 / 8];
    let mut current_idx = 0;
    let mut buff = 0u16;
    let mut bits = 0u8;
    for &c in payload {
        buff = (buff << 5) | c as u16;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            eight_bit[current_idx] = (buff >> bits) as u8;
            buff &= (1 << bits) - 1;
            current_idx += 1;
        }
    }
    eight_bit
}
