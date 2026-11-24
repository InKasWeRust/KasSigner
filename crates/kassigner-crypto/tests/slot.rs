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

//! Slots and the wallets opened from them.

use kaspa_bip32::{ChildNumber as UpChild, ExtendedPrivateKey as UpXPrv, SecretKey};
use kassigner_crypto::bip32::{compressed_public_key, ExtendedPrivateKey};
use kassigner_crypto::bip39::{self, scratch_for, Bip39Error, Mnemonic, ENTROPY_24};
use kassigner_crypto::slot::{
    fingerprint_of, from_compact_seedqr, from_seedqr, to_compact_seedqr, to_seedqr, Passphrase,
    RawKey, Slot, SlotError, Slots, PASSPHRASE_MAX, SEEDQR_MAX,
};
use kassigner_crypto::wallet::{Wallet, WalletError};
use kassigner_kaspa::derivation::{Path, MULTISIG_ACCOUNT, SINGLE_ACCOUNT};

/// Slots a test holds; the count is the caller's, and a unit's is in
/// `kassigner_fw::limits`.
const SLOTS: usize = 16;
use kassigner_kaspa::bip32_public::HARDENED_OFFSET;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::hex;

fn mnemonic(fill: u8) -> Mnemonic {
    bip39::from_entropy(&[fill; 16]).expect("entropy")
}

fn open(slot: &Slot) -> Wallet {
    let mut scratch = vec![0u8; scratch_for(PASSPHRASE_MAX)];
    Wallet::open(slot, &mut scratch).expect("open")
}

// ── Slots ───────────────────────────────────────────────────────────────────

/// A slot goes in, comes back out, and is the active one once activated.
#[test]
fn a_slot_is_stored_activated_and_read_back() {
    let mut slots: Slots<SLOTS> = Slots::new();
    assert_eq!(slots.count(), 0);
    assert!(slots.active().is_none());

    let i = slots
        .store(Slot::mnemonic(mnemonic(1), b"").unwrap())
        .expect("store");
    assert_eq!(slots.count(), 1);
    assert_eq!(slots.activate(i), Ok(()));
    let (a, s) = slots.active().expect("active");
    assert_eq!(a, i);
    assert_eq!(s.kind(), "mnemonic");
    assert_eq!(slots.fingerprint(i), None, "not derived yet");
}

/// The same secret stored twice lands once. A different passphrase, of any
/// length (compared whole, no early return on a length), or the same first
/// words in a longer mnemonic, is a different secret.
#[test]
fn the_same_secret_is_not_stored_twice() {
    let mut slots: Slots<SLOTS> = Slots::new();
    let a = slots
        .store(Slot::mnemonic(mnemonic(1), b"x").unwrap())
        .unwrap();
    let b = slots
        .store(Slot::mnemonic(mnemonic(1), b"x").unwrap())
        .unwrap();
    assert_eq!(a, b);
    let c = slots
        .store(Slot::mnemonic(mnemonic(1), b"y").unwrap())
        .unwrap();
    assert_ne!(a, c);
    let d = slots
        .store(Slot::RawKey(RawKey::new(&[7; 32]).unwrap()))
        .unwrap();
    let e = slots
        .store(Slot::RawKey(RawKey::new(&[7; 32]).unwrap()))
        .unwrap();
    assert_eq!(d, e);
    assert_eq!(slots.count(), 3);

    let mut slots: Slots<SLOTS> = Slots::new();
    let x = Slot::mnemonic(mnemonic(1), b"x").unwrap();
    let longer = Slot::mnemonic(mnemonic(1), b"xx").unwrap();
    let none = Slot::mnemonic(mnemonic(1), b"").unwrap();
    let twenty_four = Slot::mnemonic(bip39::from_entropy(&[1; 32]).unwrap(), b"x").unwrap();
    let at = [
        slots.store(x).unwrap(),
        slots.store(longer).unwrap(),
        slots.store(none).unwrap(),
        slots.store(twenty_four).unwrap(),
    ];
    assert_eq!(at, [0, 1, 2, 3], "four secrets");
}

/// A slot printed for debugging says nothing of its passphrase, not even
/// its length.
#[test]
fn a_slot_printed_says_nothing_of_its_passphrase() {
    let slot = Slot::mnemonic(mnemonic(1), b"nine char").unwrap();
    let printed = format!("{slot:?}");
    assert!(printed.contains("Passphrase(redacted)"), "{printed}");
    assert!(!printed.contains('9'), "{printed}");
}

/// Deleting frees the slot, drops the active mark, and clears the
/// fingerprint. A raw key's fingerprint is known at once.
#[test]
fn delete_frees_and_deactivates() {
    let mut slots: Slots<SLOTS> = Slots::new();
    let i = slots
        .store(Slot::RawKey(RawKey::new(&[7; 32]).unwrap()))
        .unwrap();
    let fp = RawKey::new(&[7; 32]).unwrap().fingerprint();
    assert_eq!(slots.fingerprint(i), Some(fp));
    assert_eq!(slots.find_by_fingerprint(&fp), Some(i));
    slots.activate(i).unwrap();
    slots.delete(i);
    assert!(slots.active().is_none());
    assert_eq!(slots.count(), 0);
    assert_eq!(slots.fingerprint(i), None);
    assert_eq!(slots.get(i).err(), Some(SlotError::Empty { index: i }));
    slots.delete(99); // nothing to do
}

/// What slots refuse.
#[test]
fn slots_refuse() {
    let mut slots: Slots<SLOTS> = Slots::new();
    assert_eq!(slots.store(Slot::Empty), Err(SlotError::InvalidKey));
    assert_eq!(slots.activate(3), Err(SlotError::Empty { index: 3 }));
    assert_eq!(
        slots.activate(SLOTS),
        Err(SlotError::NoSuchSlot { index: SLOTS })
    );
    assert_eq!(
        Passphrase::new(&[b'a'; PASSPHRASE_MAX + 1]).err(),
        Some(SlotError::PassphraseTooLong {
            len: PASSPHRASE_MAX + 1
        })
    );
    assert_eq!(RawKey::new(&[0; 32]).err(), Some(SlotError::InvalidKey));

    for k in 0..SLOTS {
        slots
            .store(Slot::RawKey(RawKey::new(&[k as u8 + 1; 32]).unwrap()))
            .unwrap();
    }
    assert_eq!(
        slots.store(Slot::RawKey(RawKey::new(&[99; 32]).unwrap())),
        Err(SlotError::Full)
    );
}

// ── SeedQR ──────────────────────────────────────────────────────────────────

/// Both SeedQR forms round-trip, for 12 and 24 words, and a known vector
/// reads as its words.
#[test]
fn seedqr_round_trips() {
    for m in [mnemonic(1), bip39::from_entropy(&[9; 32]).unwrap()] {
        let mut digits = [0u8; SEEDQR_MAX];
        let n = to_seedqr(&m, &mut digits);
        assert_eq!(n, m.len() * 4);
        let back = from_seedqr(&digits[..n]).expect("standard");
        assert!((0..m.len()).all(|i| back.index(i) == m.index(i)));

        let mut bytes = [0u8; ENTROPY_24];
        let n = to_compact_seedqr(&m, &mut bytes);
        assert_eq!(n, m.entropy_len());
        let back = from_compact_seedqr(&bytes[..n]).expect("compact");
        assert!((0..m.len()).all(|i| back.index(i) == m.index(i)));
    }

    // The all-zero entropy mnemonic: "abandon" x11 "about", indices 0 and 3.
    let m = from_seedqr(b"000000000000000000000000000000000000000000000003").unwrap();
    assert_eq!(m.word(11), Some("about"));
}

/// What SeedQR reading refuses.
#[test]
fn seedqr_refuses() {
    assert_eq!(from_seedqr(b"0000").err(), Some(SlotError::SeedQr));
    let mut bad = *b"000000000000000000000000000000000000000000000003";
    bad[0] = b'x';
    assert_eq!(from_seedqr(&bad).err(), Some(SlotError::SeedQr));
    let big = b"204800000000000000000000000000000000000000000003";
    assert_eq!(from_seedqr(big).err(), Some(SlotError::SeedQr));
    let wrong_checksum = b"000000000000000000000000000000000000000000000004";
    assert!(matches!(
        from_seedqr(wrong_checksum),
        Err(SlotError::Bip39(_))
    ));
    assert!(matches!(
        from_compact_seedqr(&[0; 20]),
        Err(SlotError::Bip39(_))
    ));
}

// ── Wallet ──────────────────────────────────────────────────────────────────

fn up_key(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let mut k = UpXPrv::<SecretKey>::new(seed).unwrap();
    for &c in path {
        k = k.derive_child(UpChild(c)).unwrap();
    }
    k.private_key().secret_bytes()
}

/// A mnemonic wallet's keys are upstream's keys at the documented paths,
/// with and without a passphrase.
#[test]
fn a_mnemonic_wallets_keys_are_upstreams() {
    for pass in [&b""[..], b"correct horse"] {
        let m = mnemonic(1);
        let mut scratch = vec![0u8; scratch_for(pass.len())];
        let seed = bip39::to_seed(&m, core::str::from_utf8(pass).unwrap(), &mut scratch).unwrap();
        let w = open(&Slot::mnemonic(m, pass).unwrap());
        assert!(w.has_multisig());

        let h = HARDENED_OFFSET;
        let single = w.signing_key(Path::change(7)).unwrap();
        assert_eq!(
            *single.private_key(),
            up_key(seed.as_bytes(), &[h + 44, h + 111_111, h, 1, 7])
        );
        let multi = w
            .signing_key(Path::Multisig {
                cosigner: 2,
                chain: 0,
                index: 5,
            })
            .unwrap();
        assert_eq!(
            *multi.private_key(),
            up_key(seed.as_bytes(), &[h + 45, h + 111_111, h, 2, 0, 5])
        );
        assert!(w.has_kcc3());
        let hidden = w.signing_key(Path::kcc3_receive(3)).unwrap();
        assert_eq!(
            *hidden.private_key(),
            up_key(seed.as_bytes(), &[h + 22, h + 111_111, h, 0, 3])
        );
        assert_eq!(single.x_only(), single.public_key()[1..]);

        // The fingerprint is the master key's, BIP32's rule.
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
        assert_eq!(w.fingerprint(), fingerprint_of(&master.public_key()));
        let _ = MULTISIG_ACCOUNT;
    }
}

/// An xprv slot is the 44' account node: it reaches the same single-signature
/// keys as the mnemonic it came from, and no multisig key.
#[test]
fn an_xprv_wallet_is_the_account_node() {
    let m = mnemonic(1);
    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = bip39::to_seed(&m, "", &mut scratch).unwrap();
    let account = ExtendedPrivateKey::from_seed(seed.as_bytes())
        .unwrap()
        .derive_path(&SINGLE_ACCOUNT)
        .unwrap();

    let account_fingerprint = account.fingerprint();
    let from_words = open(&Slot::mnemonic(m, b"").unwrap());
    let from_xprv = open(&Slot::Xprv(account));
    assert!(!from_xprv.has_multisig());
    assert!(!from_xprv.has_kcc3());
    assert!(from_xprv.kcc3_chain_public(0).unwrap().is_none());
    // No master key above it: its fingerprint is its own key's, as other
    // wallets show it, not the seed's.
    assert_eq!(from_xprv.fingerprint(), account_fingerprint);
    assert_ne!(from_xprv.fingerprint(), from_words.fingerprint());
    for p in [Path::receive(0), Path::receive(19), Path::change(4)] {
        assert_eq!(
            from_xprv.signing_key(p).unwrap().private_key(),
            from_words.signing_key(p).unwrap().private_key()
        );
    }
    assert_eq!(
        from_xprv
            .signing_key(Path::Multisig {
                cosigner: 0,
                chain: 0,
                index: 0
            })
            .err(),
        Some(WalletError::NoMultisigTree)
    );
    assert_eq!(
        from_xprv.signing_key(Path::kcc3_receive(0)).err(),
        Some(WalletError::NoKcc3Tree)
    );
}

/// A master xprv is a seed without the stretch: it reaches every key the
/// mnemonic reaches, multisig and KCC-3 included, and shows the same
/// fingerprint.
#[test]
fn a_master_xprv_wallet_is_a_seed_without_the_stretch() {
    let m = mnemonic(1);
    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = bip39::to_seed(&m, "", &mut scratch).unwrap();
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
    assert_eq!(master.depth(), 0);

    let from_words = open(&Slot::mnemonic(m, b"").unwrap());
    let from_master = open(&Slot::Xprv(master));
    assert!(from_master.has_multisig());
    assert!(from_master.has_kcc3());
    assert_eq!(from_master.fingerprint(), from_words.fingerprint());
    for p in [
        Path::receive(0),
        Path::change(4),
        Path::Multisig {
            cosigner: 2,
            chain: 1,
            index: 7,
        },
        Path::kcc3_change(2),
    ] {
        assert_eq!(
            from_master.signing_key(p).unwrap().private_key(),
            from_words.signing_key(p).unwrap().private_key(),
            "{p:?}"
        );
    }
}

/// An xprv at the account's depth must be account 0': another account's
/// keys show in no wallet of this seed, so it is refused at the wallet and
/// at the card, its number named. A chain must be 0 or 1.
#[test]
fn only_account_zero_and_its_two_chains_are_taken() {
    use kassigner_crypto::backup::FILE_MAX;
    use kassigner_kaspa::bip32_public::ChildNumber;

    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = bip39::to_seed(&mnemonic(1), "", &mut scratch).unwrap();
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
    let coin = master
        .derive_child(SINGLE_ACCOUNT[0])
        .unwrap()
        .derive_child(SINGLE_ACCOUNT[1])
        .unwrap();
    let other = coin.derive_child(ChildNumber(HARDENED_OFFSET + 1)).unwrap();
    assert_eq!(other.depth(), 3);
    let slot = Slot::Xprv(other);
    let mut scratch = vec![0u8; scratch_for(PASSPHRASE_MAX)];
    let child = HARDENED_OFFSET + 1;
    assert_eq!(
        Wallet::open(&slot, &mut scratch).err(),
        Some(WalletError::XprvAccount { child })
    );
    let mut file = [0u8; FILE_MAX];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .expect("sealing does not judge the key");
    assert_eq!(
        open_slot(&file[..n], CARD_PASSWORD, b"", None).err(),
        Some(BackupError::XprvAccount { child })
    );

    // Account 0' opens, and gives its two chains and nothing else.
    let account = Slot::Xprv(coin.derive_child(SINGLE_ACCOUNT[2]).unwrap());
    let wallet = Wallet::open(&account, &mut scratch).expect("account 0'");
    assert!(wallet.chain_public(0).unwrap().is_some());
    assert!(wallet.chain_public(1).unwrap().is_some());
    for chain in [2, 7, HARDENED_OFFSET] {
        assert_eq!(
            wallet.chain_public(chain).err(),
            Some(WalletError::Chain { chain })
        );
    }
}

/// An xprv from any other level (purpose, coin type, chain) is refused at
/// the wallet and at the card, `XprvDepth` naming the level: as the account
/// node it would sign under keys holding no funds.
#[test]
fn an_xprv_from_another_level_is_refused() {
    use kassigner_crypto::backup::FILE_MAX;
    use kassigner_kaspa::bip32_public::ChildNumber;

    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = bip39::to_seed(&mnemonic(1), "", &mut scratch).unwrap();
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap();
    let purpose = master.derive_child(SINGLE_ACCOUNT[0]).unwrap();
    let coin = purpose.derive_child(SINGLE_ACCOUNT[1]).unwrap();
    let account = coin.derive_child(SINGLE_ACCOUNT[2]).unwrap();
    let chain = account.derive_child(ChildNumber(0)).unwrap();
    assert_eq!(
        (
            purpose.depth(),
            coin.depth(),
            account.depth(),
            chain.depth()
        ),
        (1, 2, 3, 4)
    );

    for k in [purpose, coin, chain] {
        let depth = k.depth();
        let slot = Slot::Xprv(k);
        let mut scratch = vec![0u8; scratch_for(PASSPHRASE_MAX)];
        assert_eq!(
            Wallet::open(&slot, &mut scratch).err(),
            Some(WalletError::XprvDepth { depth })
        );
        // The card path refuses at import, before a slot exists.
        let mut file = [0u8; FILE_MAX];
        let n = seal_slot(
            &slot,
            CARD_PASSWORD,
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut file,
        )
        .expect("sealing does not judge the key");
        assert_eq!(
            open_slot(&file[..n], CARD_PASSWORD, b"", None).err(),
            Some(BackupError::XprvDepth { depth })
        );
    }
    // The account level still opens.
    let mut scratch = vec![0u8; scratch_for(PASSPHRASE_MAX)];
    assert!(Wallet::open(&Slot::Xprv(account), &mut scratch).is_ok());
}

/// A raw-key wallet yields its one key for every path, and its fingerprint
/// is over that key.
#[test]
fn a_raw_key_wallet_is_one_key() {
    let w = open(&Slot::RawKey(RawKey::new(&[7; 32]).unwrap()));
    for p in [
        Path::receive(0),
        Path::change(9),
        Path::Multisig {
            cosigner: 1,
            chain: 1,
            index: 1,
        },
        Path::kcc3_receive(0),
    ] {
        assert_eq!(*w.signing_key(p).unwrap().private_key(), [7; 32]);
    }
    assert_eq!(
        w.fingerprint(),
        fingerprint_of(&compressed_public_key(&[7; 32]).unwrap())
    );
    assert!(!w.has_multisig());
    // One key, no tree to hide KCC-3 keys in: a signer asks `has_kcc3`
    // before taking a script as one.
    assert!(!w.has_kcc3());
    assert!(w.kcc3_chain_public(0).unwrap().is_none());
}

/// A seed's KCC-3 keys are the convention's, at `m/22'/111111'/0'`: the
/// first receive and change keys of the "abandon ... about" seed, as
/// `kassigner-kaspa`'s KCC-3 tests hold them. The chains' public keys give
/// the same keys.
#[test]
fn a_seeds_kcc3_keys_are_the_conventions() {
    use kassigner_kaspa::bip32_public::ChildNumber;

    let w = open(&Slot::mnemonic(mnemonic(0), b"").unwrap());
    for (path, x) in [
        (
            Path::kcc3_receive(0),
            "fa507ef4400da1016770879248322820e16cdea980b83261b5bb5d384f2e2b45",
        ),
        (
            Path::kcc3_change(0),
            "a7521d727b42682622c3b507d7ec4342c108c7181b59601188645cba60fe2f6a",
        ),
    ] {
        let key = w.signing_key(path).unwrap().x_only();
        assert_eq!(hex(&key), x, "{path:?}");
        let Path::Kcc3 { chain, index } = path else {
            unreachable!()
        };
        let child = w
            .kcc3_chain_public(chain)
            .unwrap()
            .expect("a seed has the tree")
            .derive_child(ChildNumber(index))
            .unwrap();
        assert_eq!(child.public_key[1..], key);
    }
    assert_eq!(
        w.kcc3_chain_public(2).err(),
        Some(WalletError::Chain { chain: 2 })
    );
}

/// What a wallet refuses.
#[test]
fn wallets_refuse() {
    let mut scratch = vec![0u8; scratch_for(PASSPHRASE_MAX)];
    assert_eq!(
        Wallet::open(&Slot::Empty, &mut scratch).err(),
        Some(WalletError::EmptySlot)
    );
    let w = open(&Slot::mnemonic(mnemonic(1), b"").unwrap());
    assert!(
        matches!(
            w.signing_key(Path::receive(HARDENED_OFFSET)),
            Err(WalletError::Bip32(_))
        ),
        "nothing below an account in this scheme is hardened"
    );
    // Any chain but receive and change, on every account.
    for (path, chain) in [
        (Path::Single { chain: 2, index: 0 }, 2),
        (
            Path::Multisig {
                cosigner: 0,
                chain: 7,
                index: 0,
            },
            7,
        ),
        (
            Path::Kcc3 {
                chain: HARDENED_OFFSET,
                index: 0,
            },
            HARDENED_OFFSET,
        ),
    ] {
        assert_eq!(
            w.signing_key(path).err(),
            Some(WalletError::Chain { chain }),
            "{path:?}"
        );
    }
    for path in [Path::receive(0), Path::change(0), Path::kcc3_change(0)] {
        assert!(w.signing_key(path).is_ok(), "{path:?}");
    }
}

// ── Backup ──────────────────────────────────────────────────────────────────

use kassigner_crypto::backup::{
    mnemonic_from_plaintext, open_slot, seal_slot, seed_plaintext, BackupError, SEED_FILE_MAX,
    SEED_PLAINTEXT_MAX,
};
use kassigner_crypto::container::{Argon2Block, OpenError, SealKdf, ARGON2_BLOCKS};
use kassigner_crypto::password::Weakness;

/// A card password the policy accepts (`password.rs`).
const CARD_PASSWORD: &[u8] = b"Piggy-Bank-2026";

/// A mnemonic slot seals into a seed container and opens back to the same
/// words, with the passphrase supplied again rather than stored.
#[test]
fn a_backup_round_trips_without_the_passphrase() {
    for m in [mnemonic(1), bip39::from_entropy(&[9; 32]).unwrap()] {
        let words = m.len();
        let slot = Slot::mnemonic(m, b"secret").unwrap();
        let mut file = [0u8; SEED_FILE_MAX];
        let n = seal_slot(
            &slot,
            CARD_PASSWORD,
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut file,
        )
        .expect("seal");

        // The passphrase is not in the file: a plaintext of the words alone.
        let mut plain = [0u8; SEED_PLAINTEXT_MAX];
        if let Slot::Mnemonic { mnemonic, .. } = &slot {
            assert_eq!(seed_plaintext(mnemonic, &mut plain), words * 2);
        }

        let back = open_slot(&file[..n], CARD_PASSWORD, b"secret", None).expect("open");
        let mut slots: Slots<SLOTS> = Slots::new();
        let a = slots.store(slot).unwrap();
        let b = slots.store(back).unwrap();
        assert_eq!(a, b, "the same secret, once the passphrase is back");

        assert!(matches!(
            open_slot(&file[..n], b"wrong", b"", None),
            Err(BackupError::Container(_))
        ));
    }
}

/// What a backup refuses.
#[test]
fn backups_refuse() {
    let raw = Slot::RawKey(RawKey::new(&[7; 32]).unwrap());
    let mut file = [0u8; SEED_FILE_MAX];
    assert_eq!(
        seal_slot(
            &raw,
            CARD_PASSWORD,
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut file
        )
        .err(),
        Some(BackupError::NotBackedUp)
    );
    // A weak password is refused before the slot is looked at, even a raw
    // key's, which cannot be backed up at all.
    assert_eq!(
        seal_slot(
            &raw,
            b"pw",
            &[1; 16],
            &[2; 12],
            SealKdf::Pbkdf2Sha256,
            &mut file
        )
        .err(),
        Some(BackupError::WeakPassword(Weakness::TooShort {
            have: 2,
            min: kassigner_crypto::password::MIN_LEN
        }))
    );
    assert_eq!(
        mnemonic_from_plaintext(&[0; 23]).err(),
        Some(BackupError::Malformed)
    );
    assert_eq!(
        mnemonic_from_plaintext(&[0xff; 24]).err(),
        Some(BackupError::Malformed),
        "an index past the word list"
    );
    assert_eq!(
        mnemonic_from_plaintext(&[0; 24]).err(),
        Some(BackupError::Malformed),
        "a checksum that does not hold"
    );
}

/// An xprv slot seals into an xprv container and opens back to the same key.
#[test]
fn an_xprv_backup_round_trips() {
    use kassigner_crypto::backup::FILE_MAX;
    let k = ExtendedPrivateKey::from_seed(&[5; 32])
        .unwrap()
        .derive_path(&SINGLE_ACCOUNT)
        .unwrap();
    let slot = Slot::Xprv(k.clone());
    let mut file = [0u8; FILE_MAX];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .expect("seal");
    let back = open_slot(&file[..n], CARD_PASSWORD, b"ignored", None).expect("open");
    let Slot::Xprv(b) = back else {
        panic!("not an xprv slot");
    };
    assert_eq!(b.private_key(), k.private_key());
    assert_eq!(b.chain_code(), k.chain_code());
    assert_eq!(b.depth(), k.depth());

    // A seed opened as an xprv is refused by the container before the
    // plaintext is read: the purpose is in the key.
    let seed_slot = Slot::mnemonic(mnemonic(1), b"").unwrap();
    let m = seal_slot(
        &seed_slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();
    file[5] = 2; // purpose byte: seed → xprv
    assert!(matches!(
        open_slot(&file[..m], CARD_PASSWORD, b"", None),
        Err(BackupError::Container(_))
    ));
}

/// An Argon2id backup opens on a board with the memory and is refused by
/// name on one without (an ESP32-P4's card in an ESP32-S3).
#[test]
fn an_argon2id_backup_needs_the_memory_to_open() {
    let slot = Slot::mnemonic(mnemonic(1), b"secret").unwrap();
    let mut file = [0u8; SEED_FILE_MAX];
    let mut memory = vec![Argon2Block::default(); ARGON2_BLOCKS];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Argon2id(&mut memory),
        &mut file,
    )
    .expect("seal");

    assert_eq!(
        open_slot(&file[..n], CARD_PASSWORD, b"secret", None).err(),
        Some(BackupError::Container(OpenError::KdfMemory {
            needed: ARGON2_BLOCKS
        })),
        "a board without the memory is told so, not told the password is wrong"
    );

    let back = open_slot(&file[..n], CARD_PASSWORD, b"secret", Some(&mut memory)).expect("open");
    let mut slots: Slots<SLOTS> = Slots::new();
    let a = slots.store(slot).unwrap();
    let b = slots.store(back).unwrap();
    assert_eq!(a, b);
}

/// A taken mnemonic leaves nothing behind. A move copies and marks the
/// source dead, and a dead binding gets no `Drop`, so moved words would stay
/// in the caller's frame. `take` and `Slots::store_mnemonic` close the last
/// hand-off; earlier ones are closed by scrubbing the flow's frame.
#[test]
fn taking_a_mnemonic_wipes_the_source() {
    let mut m = mnemonic(1);
    let words: Vec<Option<u16>> = (0..m.len()).map(|i| m.index(i)).collect();
    assert!(!m.is_empty());

    let taken = m.take();
    assert_eq!(
        (0..taken.len()).map(|i| taken.index(i)).collect::<Vec<_>>(),
        words,
        "the copy is the mnemonic"
    );
    assert!(m.is_empty(), "and the source says so");
    assert_eq!(m.len(), 0);
    assert_eq!(m.index(0), None);
    assert_eq!(m.word(0), None);
    assert_eq!(m.entropy_len(), 0);
    assert!(m.entropy(&mut [0u8; 32]).is_err());
}

/// The store takes the caller's mnemonic rather than copying from it.
#[test]
fn storing_a_mnemonic_wipes_the_callers_copy() {
    let mut slots: Slots<4> = Slots::new();
    let mut m = mnemonic(2);
    let words: Vec<Option<u16>> = (0..m.len()).map(|i| m.index(i)).collect();

    let i = slots.store_mnemonic(&mut m, b"").expect("store");
    assert!(m.is_empty(), "the caller's copy is gone");

    match slots.get(i).expect("stored") {
        Slot::Mnemonic { mnemonic, .. } => {
            assert_eq!(
                (0..mnemonic.len())
                    .map(|j| mnemonic.index(j))
                    .collect::<Vec<_>>(),
                words
            );
        }
        other => panic!("{other:?}"),
    }

    // The same secret twice is stored once; the second copy is wiped too.
    let mut again = mnemonic(2);
    assert_eq!(slots.store_mnemonic(&mut again, b"").expect("store"), i);
    assert!(again.is_empty());
    assert_eq!(slots.count(), 1);

    // A passphrase too long refuses, and takes nothing.
    let mut third = mnemonic(3);
    assert_eq!(
        slots.store_mnemonic(&mut third, &[b'x'; 65]).err(),
        Some(SlotError::PassphraseTooLong { len: 65 })
    );
    assert!(
        !third.is_empty(),
        "a refused store leaves the caller's copy"
    );
    assert_eq!(slots.count(), 1, "and stores nothing");

    // A full store refuses the same way, with the caller's copy intact.
    let mut small: Slots<1> = Slots::new();
    let mut first = mnemonic(4);
    small.store_mnemonic(&mut first, b"").expect("store");
    let mut second = mnemonic(5);
    assert_eq!(
        small.store_mnemonic(&mut second, b"").err(),
        Some(SlotError::Full)
    );
    assert!(!second.is_empty());

    // A mnemonic already taken from is refused rather than stored empty.
    let mut husk = mnemonic(6);
    drop(husk.take());
    assert_eq!(
        slots.store_mnemonic(&mut husk, b"").err(),
        Some(SlotError::Bip39(Bip39Error::BadWordCount(0)))
    );
}

/// A passphrase is printable ASCII, all a KasSigner can type. The type
/// enforces it for other keyboards, where another byte could make a wallet
/// no other wallet opens.
#[test]
fn a_passphrase_is_printable_ascii() {
    // Every key on the device's keyboard: v1.0.7's three pages.
    let keys = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+.,?/ ";
    // And the whole printable range.
    let printable: Vec<u8> = (0x20..=0x7E).collect();
    for part in keys
        .chunks(PASSPHRASE_MAX)
        .chain(printable.chunks(PASSPHRASE_MAX))
    {
        assert!(Passphrase::new(part).is_ok(), "{part:?}");
        assert!(Slot::mnemonic(mnemonic(1), part).is_ok());
    }

    for (bad, at) in [
        (&b"ab\x1fcd"[..], 2),
        (&b"ab\x7fcd"[..], 2),
        ("caf\u{e9}".as_bytes(), 3),
        (&b"\xffx"[..], 0),
    ] {
        let refused = Some(SlotError::PassphraseCharacter { at });
        assert_eq!(Passphrase::new(bad).err(), refused, "{bad:?}");
        assert_eq!(Slot::mnemonic(mnemonic(1), bad).err(), refused);
    }

    // A restore with a passphrase outside the set opens nothing, not a
    // wallet under another seed.
    let slot = Slot::mnemonic(mnemonic(1), b"").unwrap();
    let mut file = [0u8; SEED_FILE_MAX];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .expect("seal");
    assert!(matches!(
        open_slot(&file[..n], CARD_PASSWORD, "caf\u{e9}".as_bytes(), None),
        Err(BackupError::Slot(SlotError::PassphraseCharacter { at: 3 }))
    ));
}

/// A seed's fingerprint is its master fingerprint: `73c5da0a` for the
/// "abandon ... about" seed with no passphrase, as BIP39 examples publish
/// it. A passphrase changes it.
#[test]
fn a_seed_shows_its_master_fingerprint() {
    let abandon = bip39::from_entropy(&[0u8; 16]).unwrap();
    let w = open(&Slot::mnemonic(abandon, b"").unwrap());
    assert_eq!(w.fingerprint(), [0x73, 0xc5, 0xda, 0x0a]);

    // rusty-kaspa's master key for the same seed agrees.
    let abandon = bip39::from_entropy(&[0u8; 16]).unwrap();
    let mut scratch = vec![0u8; scratch_for(0)];
    let seed = bip39::to_seed(&abandon, "", &mut scratch).unwrap();
    let upstream = UpXPrv::<SecretKey>::new(seed.as_bytes()).unwrap();
    assert_eq!(w.fingerprint(), upstream.public_key().fingerprint());

    let abandon = bip39::from_entropy(&[0u8; 16]).unwrap();
    let with_passphrase = open(&Slot::mnemonic(abandon, b"TREZOR").unwrap());
    assert_ne!(with_passphrase.fingerprint(), w.fingerprint());
}

/// **A card alone never opens the funds.** A seed with a passphrase may be
/// sealed under no password: the file is sealed all the same, its words not
/// readable in it, and opens under the empty password and no other. A seed
/// with no passphrase, and a key with none to have, is refused the same; so
/// is a weak password typed for a seed that has a passphrase, since only the
/// empty one is the choice of none. The steps hold the same rule and seal
/// the same file.
#[test]
fn a_seed_goes_without_a_password_only_behind_its_passphrase() {
    use kassigner_crypto::backup::{passphrase_guards, seal_slot_with_key, sealing_steps};
    use kassigner_crypto::container::PBKDF2_ITERATIONS;

    let (salt, nonce) = ([7u8; 16], [9u8; 12]);
    let guarded = Slot::mnemonic(mnemonic(3), b"secret").unwrap();
    let bare = Slot::mnemonic(mnemonic(3), b"").unwrap();
    let raw = Slot::RawKey(RawKey::new(&[7; 32]).unwrap());
    assert!(passphrase_guards(&guarded));
    assert!(!passphrase_guards(&bare));
    assert!(!passphrase_guards(&raw));
    assert!(!passphrase_guards(&Slot::Empty));

    let none_typed = Some(BackupError::WeakPassword(Weakness::TooShort {
        have: 0,
        min: kassigner_crypto::password::MIN_LEN,
    }));
    let seal = |slot: &Slot, password: &[u8], file: &mut [u8; SEED_FILE_MAX]| {
        seal_slot(slot, password, &salt, &nonce, SealKdf::Pbkdf2Sha256, file)
    };

    // No passphrase: no password is refused, before anything is written.
    let mut file = [0u8; SEED_FILE_MAX];
    assert_eq!(seal(&bare, b"", &mut file).err(), none_typed);
    assert_eq!(seal(&raw, b"", &mut file).err(), none_typed);
    assert!(file.iter().all(|&b| b == 0), "nothing written");
    assert_eq!(sealing_steps(&bare, b"", &salt).err(), none_typed);
    assert_eq!(
        sealing_steps(&raw, b"", &salt).err(),
        Some(BackupError::NotBackedUp)
    );

    // A passphrase, and a password typed all the same: held to the policy.
    assert!(matches!(
        seal(&guarded, b"short", &mut file),
        Err(BackupError::WeakPassword(Weakness::TooShort {
            have: 5,
            ..
        }))
    ));
    assert!(matches!(
        sealing_steps(&guarded, b"short", &salt),
        Err(BackupError::WeakPassword(_))
    ));
    assert!(file.iter().all(|&b| b == 0), "nothing written");

    // A passphrase and no password: sealed, the words not in the file.
    let n = seal(&guarded, b"", &mut file).expect("no password, behind a passphrase");
    let mut plain = [0u8; SEED_PLAINTEXT_MAX];
    let Slot::Mnemonic { mnemonic, .. } = &guarded else {
        unreachable!()
    };
    let words = seed_plaintext(mnemonic, &mut plain);
    assert!(
        !file[..n].windows(words).any(|w| w == &plain[..words]),
        "sealed: the words are not readable in the file"
    );
    // The empty password opens it, as it opens v1.0.7's; another does not.
    let back = open_slot(&file[..n], b"", b"secret", None).expect("opens under no password");
    let mut slots: Slots<SLOTS> = Slots::new();
    let a = slots.store(guarded.clone()).unwrap();
    let b = slots.store(back).unwrap();
    assert_eq!(a, b, "the same words, once the passphrase is typed again");
    assert!(matches!(
        open_slot(&file[..n], CARD_PASSWORD, b"secret", None),
        Err(BackupError::Container(_))
    ));

    // In steps: the same rule, the same file.
    let mut steps = sealing_steps(&guarded, b"", &salt).expect("the same rule");
    steps.step(PBKDF2_ITERATIONS);
    let key = steps.sealing_key().expect("every round done");
    let mut stepped = [0u8; SEED_FILE_MAX];
    let m = seal_slot_with_key(&guarded, &key, &salt, &nonce, &mut stepped).unwrap();
    assert_eq!(file[..n], stepped[..m], "the same file");
}

/// The stepped PBKDF2 is PBKDF2: in batches of any size its key is the one
/// `derive_key` gives, and a seed sealed with it is the file `seal_slot`
/// writes for the same salt and nonce, which opens. Unfinished, it gives no
/// key, and the steps to seal with refuse a weak password.
#[test]
fn the_stepped_derivation_seals_the_same_file() {
    use kassigner_crypto::backup::{purpose_of, seal_slot_with_key};
    use kassigner_crypto::container::{derive_key, KdfParams, Pbkdf2Steps, PBKDF2_ITERATIONS};

    let (salt, nonce) = ([7u8; 16], [9u8; 12]);
    let slot = Slot::mnemonic(mnemonic(3), b"").unwrap();
    let purpose = purpose_of(&slot).unwrap();
    let whole = derive_key(
        KdfParams::Pbkdf2Sha256 { salt: &salt },
        CARD_PASSWORD,
        purpose,
        None,
    )
    .unwrap();

    let mut steps = Pbkdf2Steps::sealing(CARD_PASSWORD, &salt, purpose).expect("policy");
    assert_eq!(steps.key(), None);
    assert!(steps.sealing_key().is_none());
    let mut last = (0, 0);
    for batch in [1, 999, 37_000, 70_000] {
        last = steps.step(batch);
    }
    assert_eq!(last, (PBKDF2_ITERATIONS, PBKDF2_ITERATIONS));
    assert_eq!(steps.key(), Some(whole));
    let key = steps.sealing_key().expect("every round done");

    let mut a = [0u8; SEED_FILE_MAX];
    let mut b = [0u8; SEED_FILE_MAX];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &salt,
        &nonce,
        SealKdf::Pbkdf2Sha256,
        &mut a,
    )
    .unwrap();
    let m = seal_slot_with_key(&slot, &key, &salt, &nonce, &mut b).unwrap();
    assert_eq!(a[..n], b[..m], "the same file");
    assert!(open_slot(&b[..m], CARD_PASSWORD, b"", None).is_ok());
    assert!(matches!(
        Pbkdf2Steps::sealing(b"short", &salt, purpose),
        Err(Weakness::TooShort { .. })
    ));
}

/// A backup opens with a key derived in steps: its header says how, without
/// the password; that key gives `open_slot`'s slot; another key fails as a
/// wrong password does; a non-container fails before any key.
#[test]
fn a_backup_opens_with_the_stepped_key() {
    use kassigner_crypto::backup::{backup_kdf, open_slot_with_key, BackupKdf};
    use kassigner_crypto::container::Pbkdf2Steps;
    use kassigner_protocol::container::Purpose;

    let (salt, nonce) = ([5u8; 16], [6u8; 12]);
    let slot = Slot::mnemonic(mnemonic(4), b"").unwrap();
    let mut file = [0u8; SEED_FILE_MAX];
    let n = seal_slot(
        &slot,
        CARD_PASSWORD,
        &salt,
        &nonce,
        SealKdf::Pbkdf2Sha256,
        &mut file,
    )
    .unwrap();
    let file = &file[..n];

    let kdf = backup_kdf(file).unwrap();
    assert_eq!(
        kdf,
        BackupKdf::Pbkdf2 {
            salt,
            purpose: Purpose::Seed
        }
    );
    let BackupKdf::Pbkdf2 { salt, purpose } = kdf else {
        unreachable!()
    };
    let mut steps = Pbkdf2Steps::new(CARD_PASSWORD, &salt, purpose);
    steps.step(u32::MAX);
    let key = steps.key().unwrap();
    let a = open_slot_with_key(file, &key, b"pp").unwrap();
    let b = open_slot(file, CARD_PASSWORD, b"pp", None).unwrap();
    let (Slot::Mnemonic { mnemonic: x, .. }, Slot::Mnemonic { mnemonic: y, .. }) = (&a, &b) else {
        panic!("seeds")
    };
    assert!((0..x.len()).all(|i| x.index(i) == y.index(i)));

    assert_eq!(
        open_slot_with_key(file, &[0u8; 32], b"").err(),
        Some(BackupError::Container(OpenError::Authentication))
    );
    assert!(matches!(
        backup_kdf(b"not a backup at all"),
        Err(BackupError::Container(OpenError::Framing(_)))
    ));
}

/// An emptied mnemonic makes no slot and no backup: a slot of it would open
/// the empty phrase's wallet, a backup would restore nothing. Both are
/// refused as a word count of zero, the backup before anything is derived
/// or written.
#[test]
fn an_emptied_mnemonic_makes_no_slot_and_no_backup() {
    let mut m = mnemonic(1);
    let _words = m.take();
    assert!(matches!(
        Slot::mnemonic(m.clone(), b""),
        Err(SlotError::Bip39(bip39::Bip39Error::BadWordCount(0)))
    ));

    // A slot built directly, past that check, as no code in this crate
    // builds one: the backup refuses it too.
    let slot = Slot::Mnemonic {
        mnemonic: m,
        passphrase: Passphrase::new(b"").unwrap(),
    };
    let mut file = [0u8; SEED_FILE_MAX];
    let sealed = seal_slot(
        &slot,
        CARD_PASSWORD,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut file,
    );
    assert!(matches!(
        sealed,
        Err(BackupError::Slot(SlotError::Bip39(
            bip39::Bip39Error::BadWordCount(0)
        )))
    ));
    assert!(file.iter().all(|&b| b == 0), "nothing written");
}
