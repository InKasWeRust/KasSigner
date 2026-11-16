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

//! A held group's keys kept at every branch and chain: the addresses made
//! from them, one step per key, are the group's own.

use kassigner_fw::branches::Branches;
use kassigner_fw::flow::HeldGroup;
use kassigner_fw::limits::MAX_MULTISIG_KEYS;
use kassigner_kaspa::address::Prefix;
use kassigner_kaspa::bip32_public::ExtendedPublicKey;
use kassigner_kaspa::kat::MULTISIG_45;

fn go_keys() -> Vec<ExtendedPublicKey> {
    MULTISIG_45
        .kpubs
        .iter()
        .map(|t| {
            ExtendedPublicKey::from_text(t.as_bytes())
                .expect("a kpub")
                .1
        })
        .collect()
}

/// The group's address the whole way down, three steps a key.
fn whole(g: &HeldGroup, cosigner: u32, chain: u32, index: u32) -> String {
    let mut out = [0u8; 128];
    let n = g
        .address(Prefix::Mainnet, cosigner, chain, index, &mut out)
        .expect("address");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// The same address from the kept keys, one step a key.
fn kept(b: &Branches, g: &HeldGroup, cosigner: usize, change: bool, index: u32) -> String {
    let mut keys = [[0u8; 32]; MAX_MULTISIG_KEYS];
    assert_eq!(
        b.keys_at(cosigner, change, index, &mut keys),
        Some(g.total())
    );
    let mut out = [0u8; 128];
    let n = g
        .address_of_keys(Prefix::Mainnet, &keys, &mut out)
        .expect("address");
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// **What is kept makes the group's addresses.** For the Go wallet's five
/// keys, and groups of three and one from them: one key at one branch per
/// step, the key count squared in all, nothing given before the last. Then
/// every cosigner, both chains, at indexes up to the keypad's last, gives
/// the address derived the whole way down, the Go wallet's own among them.
#[test]
fn the_kept_keys_make_the_groups_addresses() {
    let v = MULTISIG_45;
    for (required, total) in [(v.required, 5), (2, 3), (1, 1)] {
        let g = HeldGroup::new(required, &go_keys()[..total]).unwrap();
        let mut b = Branches::new();
        assert_eq!(b.progress(), (0, 0));
        b.start(total);
        assert_eq!(b.progress(), (0, total * total));
        let mut keys = [[0u8; 32]; MAX_MULTISIG_KEYS];
        for done in 1..=total * total {
            assert!(!b.ready());
            assert_eq!(b.keys_at(0, false, 0, &mut keys), None, "not before");
            b.step(&g).expect("a step");
            assert_eq!(b.progress(), (done, total * total));
        }
        assert!(b.ready());
        b.step(&g).expect("nothing left");
        assert_eq!(b.progress(), (total * total, total * total));

        for cosigner in 0..total {
            for change in [false, true] {
                for index in [0, 1, 7, 12, 99_999] {
                    assert_eq!(
                        kept(&b, &g, cosigner, change, index),
                        whole(&g, cosigner as u32, change.into(), index),
                        "{total} keys, {cosigner}/{}/{index}",
                        u8::from(change)
                    );
                }
            }
        }
        if total == 5 {
            assert_eq!(
                kept(&b, &g, v.cosigner as usize, v.chain == 1, v.index),
                v.address
            );
        }
        assert_eq!(
            b.keys_at(total, false, 0, &mut keys),
            None,
            "no such branch"
        );
        b.clear();
        assert!(!b.ready());
        assert_eq!(b.keys_at(0, false, 0, &mut keys), None, "cleared");
    }
}

/// **Started for another count, the first step starts over** for the group
/// it is given, rather than reading past its keys.
#[test]
fn a_step_takes_the_groups_count() {
    let g = HeldGroup::new(2, &go_keys()[..3]).unwrap();
    let mut b = Branches::new();
    b.start(5);
    b.step(&g).unwrap();
    assert_eq!(b.progress(), (1, 9));
    let mut b = Branches::new();
    b.step(&g).unwrap();
    assert_eq!(b.progress(), (1, 9));
}
