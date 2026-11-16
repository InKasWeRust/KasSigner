// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The keys behind the v1.0.7 corpus in `spec/vectors/v107/`, as
//! kassigner.org 1.0.7 derives them. Included by path, like `hex.rs`, as a
//! `pub mod`.

use kassigner_kaspa::bip32_public::{ChildNumber, ExtendedPublicKey};

/// A cosigner's key at the 2-of-3's receive address `index`, derived as
/// kassigner.org 1.0.7 derives a `multi_hd45` address's keys (cosigner,
/// chain, index); the requests spend cosigner 0's receive addresses.
pub fn cosigner_key(kpub: &str, index: u32) -> [u8; 33] {
    let (_, account) = ExtendedPublicKey::from_text(kpub.as_bytes()).expect("kpub");
    [0, 0, index]
        .into_iter()
        .try_fold(account, |k, i| k.derive_child(ChildNumber(i)))
        .expect("child")
        .public_key
}

/// The x-only keys a multisig redeem script names, in order.
pub fn redeem_keys(redeem: &[u8]) -> Vec<[u8; 32]> {
    kassigner_kaspa::script::recognize::parse_multisig(redeem)
        .expect("a multisig redeem script")
        .keys()
        .map(|k| k.try_into().expect("x-only"))
        .collect()
}
