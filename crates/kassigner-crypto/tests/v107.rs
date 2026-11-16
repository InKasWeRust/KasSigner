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

//! The card files a v1.0.7 unit writes, opened here. They are in
//! `spec/vectors/v107/cards` (listed in its `MANIFEST.md`), made by the
//! tag's own writers: `sd_backup.rs` and the handler's inline `KAS\x03`
//! sealing. What each opens to comes from the other side: the test seeds'
//! words, the keys 1.0.7 and kassigner.org 1.0.7 derive from them, and the
//! unit's reply bytes. A backup that fails here fails to restore on v1.1.0.

use kassigner_crypto::backup::open_slot;
use kassigner_crypto::bip39;
use kassigner_crypto::container::open;
use kassigner_crypto::slot::Slot;
use kassigner_crypto::wallet::Wallet;
use kassigner_kaspa::bip32_public::{ChildNumber, ExtendedPublicKey};
use kassigner_kaspa::derivation::Path;
use kassigner_protocol::container::{parse, Layout, Purpose};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex;

/// A corpus file, built into the test.
macro_rules! corpus {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}

/// The password 1.0.7 sealed every file under but one.
const PASSWORD: &[u8] = b"abc";

/// Receive address 0's key of each test seed: the script kassigner.org 1.0.7
/// spends or pays in the corpus's requests (`20 <key> ac`).
const ABANDON12_RECEIVE0: &str = "1bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058";
const ABANDON24_RECEIVE0: &str = "94f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08";
const ZOO12_RECEIVE0: &str = "4f2e4efeec55d8faaeb5fc41f70597fc68c135bfe81744ccfb2c126f8b5c5bc8";

/// The abandon 12 seed's kpubs as 1.0.7 writes them: `m/44'/111111'/0'`
/// and the cosigner's `m/45'/111111'/0'`.
const ABANDON12_KPUB44: &str = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const ABANDON12_KPUB45: &str = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";

/// Receive address 0's x-only key of the wallet a slot opens.
fn receive0(slot: &Slot) -> [u8; 32] {
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let w = Wallet::open(slot, &mut scratch).expect("the wallet opens");
    w.signing_key(Path::receive(0)).expect("receive 0").x_only()
}

/// The words a mnemonic slot holds.
fn words(slot: &Slot) -> Vec<&'static str> {
    let Slot::Mnemonic { mnemonic, .. } = slot else {
        panic!("not a mnemonic slot");
    };
    (0..mnemonic.len())
        .map(|i| mnemonic.word(i).expect("a word"))
        .collect()
}

/// One seed backup on the card, and what it must restore.
struct Backup {
    name: &'static str,
    file: &'static [u8],
    password: &'static [u8],
    phrase: &'static str,
    receive0: &'static str,
}

/// A seed backup, `KAS\x04` purpose 1: the words, and the wallet they open.
#[test]
fn seed_backups_of_1_0_7_restore() {
    let cases = [
        Backup {
            name: "SD000001.KAS",
            file: corpus!("cards/SD000001.KAS"),
            password: PASSWORD,
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            receive0: ABANDON12_RECEIVE0,
        },
        Backup {
            name: "SD000002.KAS",
            file: corpus!("cards/SD000002.KAS"),
            password: PASSWORD,
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            receive0: ABANDON24_RECEIVE0,
        },
        // v1.0.7 allowed a backup with no password; such cards must open.
        Backup {
            name: "SD000003.KAS",
            file: corpus!("cards/SD000003.KAS"),
            password: b"",
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            receive0: ZOO12_RECEIVE0,
        },
    ];
    for Backup {
        name,
        file,
        password,
        phrase,
        receive0: key,
    } in cases
    {
        let c = parse(file).expect(name);
        assert_eq!(
            (c.layout, c.purpose),
            (Layout::Legacy, Purpose::Seed),
            "{name}"
        );
        let slot = open_slot(file, password, b"", None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(words(&slot).join(" "), phrase, "{name}");
        assert_eq!(receive0(&slot)[..], unhex(key)[..], "{name}");
    }
    // The abandon seed's master fingerprint, as every wallet shows it.
    let slot = open_slot(corpus!("cards/SD000001.KAS"), PASSWORD, b"", None).unwrap();
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let w = Wallet::open(&slot, &mut scratch).unwrap();
    assert_eq!(w.fingerprint(), [0x73, 0xc5, 0xda, 0x0a]);
}

/// A wrong password is refused, not mistaken for another seed.
#[test]
fn a_1_0_7_seed_backup_refuses_a_wrong_password() {
    assert!(open_slot(corpus!("cards/SD000001.KAS"), b"abd", b"", None).is_err());
    assert!(open_slot(corpus!("cards/SD000003.KAS"), PASSWORD, b"", None).is_err());
}

/// An xprv backup, `KAS\x04` purpose 2: the abandon 12 account key, which
/// reaches the seed's receive address 0.
#[test]
fn an_xprv_backup_of_1_0_7_restores() {
    let file = corpus!("cards/XP000001.KAS");
    let c = parse(file).unwrap();
    assert_eq!((c.layout, c.purpose), (Layout::Legacy, Purpose::Xprv));
    let slot = open_slot(file, PASSWORD, b"", None).expect("opens");
    let Slot::Xprv(k) = &slot else {
        panic!("not an xprv slot: {slot:?}");
    };
    assert_eq!(k.depth(), 3, "the 44' account");
    assert_eq!(receive0(&slot)[..], unhex(ABANDON12_RECEIVE0)[..]);
}

/// A raw blob, `KAS\x04` purpose 3: how 1.0.7 seals a steganography hint
/// (read as one in `tests/stego.rs`).
#[test]
fn a_raw_blob_of_1_0_7_opens() {
    let file = corpus!("cards/RAWHINT.KAS");
    let mut out = [0u8; 64];
    let o = open(file, PASSWORD, &mut out, None).expect("opens");
    assert_eq!((o.layout, o.purpose), (Layout::Legacy, Purpose::Raw));
    assert_eq!(&out[..o.len], b"stego hint: abandon 12");
}

/// A kpub's receive address 0 key.
fn kpub_receive0(text: &[u8]) -> [u8; 32] {
    let (_, k) = ExtendedPublicKey::from_text(text).expect("a kpub");
    let k = k.derive_child(ChildNumber(0)).unwrap();
    let k = k.derive_child(ChildNumber(0)).unwrap();
    k.public_key[1..].try_into().unwrap()
}

/// Kpub files, plain and `KAS\x03`: the text 1.0.7 wrote, which still
/// derives the wallet's addresses.
#[test]
fn kpub_files_of_1_0_7_read() {
    let plain: &[u8] = corpus!("cards/KP000001.TXT");
    assert_eq!(plain, ABANDON12_KPUB44.as_bytes());
    assert_eq!(kpub_receive0(plain)[..], unhex(ABANDON12_RECEIVE0)[..]);

    for (name, file, text) in [
        (
            "KP000002.TXT",
            &corpus!("cards/KP000002.TXT")[..],
            ABANDON12_KPUB44,
        ),
        (
            "KP000003.TXT",
            &corpus!("cards/KP000003.TXT")[..],
            ABANDON12_KPUB45,
        ),
    ] {
        let c = parse(file).expect(name);
        assert_eq!(
            (c.layout, c.purpose),
            (Layout::LegacyNoSalt, Purpose::Kspt),
            "{name}"
        );
        let mut out = [0u8; 256];
        let o = open(file, PASSWORD, &mut out, None).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(&out[..o.len], text.as_bytes(), "{name}");
        ExtendedPublicKey::from_text(&out[..o.len]).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// A signed transaction saved to the card, `KAS\x03` and plain: the unit's
/// reply, byte for byte.
#[test]
fn signed_transaction_files_of_1_0_7_read() {
    let reply: &[u8] = corpus!("device/kspt_send_1in.reply.bin");
    let sealed = corpus!("cards/TX000001.KSP");
    let c = parse(sealed).unwrap();
    assert_eq!((c.layout, c.purpose), (Layout::LegacyNoSalt, Purpose::Kspt));
    let mut out = vec![0u8; reply.len()];
    let o = open(sealed, PASSWORD, &mut out, None).expect("opens");
    assert_eq!(&out[..o.len], reply);
    assert_eq!(&corpus!("cards/TX000002.KSP")[..], reply);
}

/// Files a unit on the released v1.0.7 image wrote (abandon 12: a seed
/// backup under `abc`, its kpub sealed under `abc` and plain) open here,
/// checking the released image against the tag's source.
#[test]
fn files_a_released_1_0_7_unit_wrote_open() {
    let backup = corpus!("unit/SD000001.KAS");
    let c = parse(backup).expect("backup");
    assert_eq!((c.layout, c.purpose), (Layout::Legacy, Purpose::Seed));
    let slot = open_slot(backup, PASSWORD, b"", None).expect("opens");
    assert_eq!(
        words(&slot).join(" "),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    assert_eq!(receive0(&slot)[..], unhex(ABANDON12_RECEIVE0)[..]);

    let sealed = corpus!("unit/KP000001.TXT");
    let c = parse(sealed).expect("kpub");
    assert_eq!((c.layout, c.purpose), (Layout::LegacyNoSalt, Purpose::Kspt));
    let mut out = [0u8; 256];
    let o = open(sealed, PASSWORD, &mut out, None).expect("opens");
    assert_eq!(&out[..o.len], ABANDON12_KPUB44.as_bytes());

    let plain: &[u8] = corpus!("unit/KP000002.TXT");
    assert_eq!(plain, ABANDON12_KPUB44.as_bytes());
}
