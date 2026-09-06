//! Small byte-oriented primitives shared by firmware, signing, and tooling.

/// Decode one ASCII hexadecimal digit.
///
/// Both uppercase and lowercase `A-F` are accepted. Invalid bytes return
/// `None`, allowing each protocol layer to map failure into its own error type.
#[inline]
pub const fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Decode one lowercase ASCII hexadecimal digit.
///
/// This is intentionally strict for canonical encodings that reject uppercase.
#[inline]
pub const fn decode_lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Return whether a bounds-checked reader consumed at least one byte.
///
/// Parser loops use this after a successful record dispatcher so a future
/// implementation (or fault) that returns `Ok(())` without advancing cannot
/// turn a malformed payload into an infinite loop.
#[inline]
pub const fn strict_forward_progress(before_remaining: usize, after_remaining: usize) -> bool {
    after_remaining < before_remaining
}

/// Encode bytes as canonical lowercase hexadecimal text.
#[inline]
pub fn encode_lower_hex(source: &[u8], destination: &mut [u8]) -> Option<usize> {
    let required = source.len().checked_mul(2)?;
    if destination.len() < required {
        return None;
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, value) in source.iter().copied().enumerate() {
        destination[index * 2] = DIGITS[(value >> 4) as usize];
        destination[index * 2 + 1] = DIGITS[(value & 0x0f) as usize];
    }
    Some(required)
}

/// Decode canonical lowercase hexadecimal text.
#[inline]
pub fn decode_lower_hex(source: &[u8], destination: &mut [u8]) -> Option<usize> {
    if source.len() & 1 != 0 {
        return None;
    }
    let required = source.len() / 2;
    if destination.len() < required {
        return None;
    }
    for index in 0..required {
        let high = decode_lower_hex_nibble(source[index * 2])?;
        let low = decode_lower_hex_nibble(source[index * 2 + 1])?;
        destination[index] = high.wrapping_shl(4).wrapping_add(low);
    }
    Some(required)
}

/// Constant-time equality for equal-length security values.
#[inline]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

/// Constant-time equality for fixed 32-byte security values.
#[inline]
pub fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    constant_time_eq(left, right)
}

/// Volatile-clear a slice with the supplied zero value.
///
/// The compiler fence prevents surrounding operations from being reordered
/// across the clearing pass. Callers use typed wrappers for bytes and mnemonic
/// indices rather than maintaining local volatile loops.
#[inline(never)]
pub fn volatile_clear<T: Copy>(values: &mut [T], zero: T) {
    for value in values {
        unsafe { core::ptr::write_volatile(value, zero) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Volatile-clear sensitive byte material.
#[inline]
pub fn zeroize_bytes(values: &mut [u8]) {
    volatile_clear(values, 0u8);
}

/// Volatile-clear mnemonic indices and other sensitive `u16` material.
#[inline]
pub fn zeroize_u16(values: &mut [u16]) {
    volatile_clear(values, 0u16);
}
