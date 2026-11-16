// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The watch-only package, the crate built without `transactions`: what it
//! keeps still works, called as plain Rust on the host. `tests/glue.rs`
//! covers the full package; this file runs only where that one does not.
//!
//! ```sh
//! cargo test -p kassigner-sdk-wasm --no-default-features
//! ```

#![cfg(not(feature = "transactions"))]

use kassigner_sdk_wasm::card::Card;
use kassigner_sdk_wasm::coin::Coin;
use kassigner_sdk_wasm::transport::codes;
use kassigner_sdk_wasm::watch::{address_of_script, read_import};
use kassigner_sdk_wasm::Profile;

const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const KAS: u64 = 100_000_000;

/// **A wallet is still watched**: a kpub read, its addresses, and a mining
/// reward kept out until it has matured.
#[test]
fn a_wallet_is_watched_without_transactions() {
    let account = read_import(ABANDON12_KPUB44.as_bytes())
        .unwrap()
        .account()
        .expect("an account");
    let receive0 = account.address(0, 0).unwrap();
    assert!(receive0.starts_with("kaspa:q"), "{receive0}");
    assert_eq!(
        address_of_script(&account.script(0, 0).unwrap()).unwrap(),
        receive0
    );

    let mined = 90_000_000;
    let reward = Coin::with_entry(&"01".repeat(32), 1, 3 * KAS, mined, true).unwrap();
    assert_eq!(reward.spendable_at(mined + 999), Some(false));
    assert_eq!(reward.spendable_at(mined + 1_000), Some(true));
}

/// **A card is still made, backed up and read back**, its backup shown as
/// the codes a unit reads.
#[test]
fn a_card_is_made_and_read_back_without_transactions() {
    let account = read_import(ABANDON12_KPUB44.as_bytes())
        .unwrap()
        .account()
        .expect("an account");
    let owner = account.address(0, 0).unwrap();
    let card = Card::savings(&owner, None, 1, 1, 2030, 12, 30).unwrap();
    let line = card.backup().unwrap();
    assert!(line.starts_with("savings_v1("), "{line}");
    let again = Card::from_backup(&line).unwrap();
    assert_eq!(again.address().unwrap(), card.address().unwrap());
    assert_eq!(again.owner().unwrap(), owner);
    assert_eq!(
        card.signer(&account, 20).unwrap().map(|s| s.index()),
        Some(0)
    );

    let shown = codes(line.as_bytes(), "opaque", &Profile::esp32s3()).unwrap();
    assert!(shown.frames() >= 1);
}
