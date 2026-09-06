// Constant-time BIP32 scalar comparison and reduction.

use super::constants::SECP256K1_ORDER;

pub(super) fn is_zero(value: &[u8; 32]) -> bool {
    let mut accumulator = 0u8;
    for byte in value {
        accumulator |= *byte;
    }
    accumulator == 0
}

/// Return true when `value < secp256k1_order` without data-dependent exits.
pub(super) fn is_less_than_order(value: &[u8; 32]) -> bool {
    let (_, borrow) = subtract(value, &SECP256K1_ORDER);
    borrow == 1
}

/// A BIP32 secret scalar must be non-zero and strictly below the curve order.
/// Keeping both conditions in a directly testable primitive makes the master
/// key validation invariant explicit rather than duplicating boolean logic at
/// callers.
pub(super) fn is_valid_secret_scalar(value: &[u8; 32]) -> bool {
    !is_zero(value) && is_less_than_order(value)
}

/// Compute `(left + right) mod n` with fixed-iteration arithmetic and a
/// mask-based conditional reduction. No branch depends on secret scalar data.
pub(super) fn scalar_add_mod_n(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 32];
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let word = left[index] as u16 + right[index] as u16 + carry;
        sum[index] = word as u8;
        carry = word >> 8;
    }

    let (reduced, borrow) = subtract(&sum, &SECP256K1_ORDER);
    // Reduce if the addition overflowed 2^256 or if sum >= n.
    let should_reduce = carry != 0 || borrow == 0;
    let mask = 0u8.wrapping_sub(u8::from(should_reduce));
    for index in 0..32 {
        sum[index] = (reduced[index] & mask).wrapping_add(sum[index] & !mask);
    }
    sum
}

/// Fixed-width subtraction. Returns `(left - right mod 2^256, borrow)`.
fn subtract(left: &[u8; 32], right: &[u8; 32]) -> ([u8; 32], u16) {
    let mut output = [0u8; 32];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let minuend = left[index] as u16;
        let subtrahend = right[index] as u16 + borrow;
        let difference = minuend.wrapping_sub(subtrahend);
        output[index] = difference as u8;
        borrow = (difference >> 15) & 1;
    }
    (output, borrow)
}
