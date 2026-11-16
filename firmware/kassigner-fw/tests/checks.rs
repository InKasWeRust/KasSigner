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

//! The device's checks over Kaspa data.

use kassigner_fw::checks::{decode_expecting, AddressCheck};
use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};

/// **Only the expected network decodes.** Twelve of the sixteen pairs fail,
/// and a refusal leaves nothing in the buffer.
#[test]
fn decode_expecting_refuses_other_networks() {
    let payload = [0x42u8; 32];
    let all = [
        Prefix::Mainnet,
        Prefix::Testnet,
        Prefix::Simnet,
        Prefix::Devnet,
    ];
    for actual in all {
        let mut buf = [0u8; MAX_ADDRESS_LEN];
        let n = encode(actual, Version::PubKey, &payload, &mut buf).unwrap();
        for expected in all {
            let mut out = [0u8; 33];
            let got = decode_expecting(expected, &buf[..n], &mut out);
            if expected == actual {
                let (v, len) = got.expect("same network must decode");
                assert_eq!(v, Version::PubKey);
                assert_eq!(&out[..len], &payload[..]);
            } else {
                assert_eq!(got, Err(AddressCheck::WrongNetwork));
                assert_eq!(out, [0u8; 33], "payload left behind after a refusal");
            }
        }
    }
    assert!(matches!(
        decode_expecting(Prefix::Mainnet, b"kaspa:nonsense", &mut [0u8; 33]),
        Err(AddressCheck::Address(_))
    ));
}
