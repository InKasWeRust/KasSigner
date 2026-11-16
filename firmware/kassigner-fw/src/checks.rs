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

//! Device checks over Kaspa data: rules this device applies on top of level
//! 0, which restates Kaspa and holds none of them.

use kassigner_kaspa::address::{decode, AddressError, Prefix, Version};

/// Why an address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressCheck {
    /// Not a valid address.
    Address(AddressError),
    /// A valid address for another network than the one expected.
    WrongNetwork,
}

/// Decode an address, and refuse anything not on `expected`.
///
/// `decode` accepts all four networks. Here an address on another network
/// fails, rather than decoding and leaving the caller to compare the prefix;
/// a refusal wipes the payload buffer, so a caller ignoring the error finds
/// nothing.
///
/// # Errors
///
/// `Address` for an invalid address, `WrongNetwork` for another network's.
pub fn decode_expecting(
    expected: Prefix,
    address: &[u8],
    payload_out: &mut [u8],
) -> Result<(Version, usize), AddressCheck> {
    let (found, version, len) = decode(address, payload_out).map_err(AddressCheck::Address)?;
    if found != expected {
        crate::wipe::wipe(&mut payload_out[..len]);
        return Err(AddressCheck::WrongNetwork);
    }
    Ok((version, len))
}
