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

//! Curve helpers the key modules share: a value as a scalar, an x-only key
//! as its point.
//!
//! No parity helper: a caller negates a secret on the curve's own `Choice`,
//! in constant time, rather than branching on a `bool`.

use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, Scalar};

/// A 32-byte value as a curve scalar, or `None` if it is zero or past the
/// order: a private key, a tweak, a nonce.
pub(crate) fn scalar_of(bytes: &[u8; 32]) -> Option<Scalar> {
    let s: Option<Scalar> = Scalar::from_repr((*bytes).into()).into();
    s.filter(|v| !bool::from(v.is_zero()))
}

/// A 32-byte value as a curve scalar, zero included, or `None` past the
/// order: BIP32's `I_L`, where zero is valid and the child is its parent.
/// Zero is one `I_L` in 2^256, so only the test below reaches it.
pub(crate) fn tweak_of(bytes: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_repr((*bytes).into()).into()
}

/// The even-y point with this x coordinate, which is what an x-only key
/// names, if one exists.
pub(crate) fn lift_x(x: &[u8; 32]) -> Option<AffinePoint> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(x);
    Option::<AffinePoint>::from(AffinePoint::from_bytes(&sec1.into()))
}

#[cfg(test)]
mod tests {
    use super::{scalar_of, tweak_of};
    use k256::Scalar;

    /// A tweak may be zero and a key may not; neither may reach the order.
    #[test]
    fn a_tweak_may_be_zero_and_a_key_may_not() {
        assert_eq!(tweak_of(&[0u8; 32]), Some(Scalar::ZERO));
        assert_eq!(scalar_of(&[0u8; 32]), None);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(tweak_of(&one), Some(Scalar::ONE));
        assert_eq!(scalar_of(&one), Some(Scalar::ONE));
        assert_eq!(tweak_of(&[0xFF; 32]), None);
        assert_eq!(scalar_of(&[0xFF; 32]), None);
    }
}
