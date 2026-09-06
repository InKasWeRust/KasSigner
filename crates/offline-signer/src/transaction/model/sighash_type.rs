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

// ─── SigHash Types ────────────────────────────────────────────────────

/// Tipos de SigHash (Kaspa usa bitfield, diferente a Bitcoin)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
/// Kaspa sighash type — determines which parts of the transaction are signed.
pub enum SigHashType {
    All = 0b0000_0001,
    None = 0b0000_0010,
    Single = 0b0000_0100,
    AnyOneCanPay = 0b1000_0000,
    // Combinaciones
    AllAnyOneCanPay = 0b1000_0001,
    NoneAnyOneCanPay = 0b1000_0010,
    SingleAnyOneCanPay = 0b1000_0100,
}

impl SigHashType {
    /// Parse a sighash type from its byte representation.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0b0000_0001 => Some(Self::All),
            0b0000_0010 => Some(Self::None),
            0b0000_0100 => Some(Self::Single),
            0b1000_0001 => Some(Self::AllAnyOneCanPay),
            0b1000_0010 => Some(Self::NoneAnyOneCanPay),
            0b1000_0100 => Some(Self::SingleAnyOneCanPay),
            _ => Option::None,
        }
    }

    /// Convert to the wire byte representation.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns true if this is an ANYONE_CAN_PAY variant.
    pub fn is_anyone_can_pay(self) -> bool {
        (self.to_byte() & 0b1000_0000) != 0
    }

    /// Returns true if this is a SIGHASH_NONE variant.
    pub fn is_sighash_none(self) -> bool {
        (self.to_byte() & 0b0000_0010) != 0
    }

    /// Returns true if this is a SIGHASH_SINGLE variant.
    pub fn is_sighash_single(self) -> bool {
        (self.to_byte() & 0b0000_0100) != 0
    }
}
