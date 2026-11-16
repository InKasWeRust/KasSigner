// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit hands over, read, and what follows from it, derived:
//! [`kassigner_sdk::import`] and [`kassigner_sdk::watch`] over owned values.
//!
//! [`read_import`] reads what a unit hands over; an [`Account`], a
//! [`Group`] and a [`Kcc3Address`] derive what to watch, as the unit does.
//! Every address is mainnet.

use kassigner_kaspa::address::MAX_ADDRESS_LEN;
use kassigner_kaspa::script::PAY_TO_SCRIPT_HASH_LEN;
use kassigner_protocol::kpub;
use kassigner_sdk::import::Import;
use kassigner_sdk::watch::{self, MAX_REDEEM};
use kassigner_sdk::{import, request};

use crate::{hex, Fault};

/// A `44'` account, watched through its kpub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    inner: watch::Account,
}

impl Account {
    /// The account behind a kpub, text (`kpub...`) or a unit's raw form.
    ///
    /// # Errors
    ///
    /// `not a kpub`, for anything but a kpub a child derives from.
    pub fn from_kpub(kpub_text: &str) -> Result<Account, Fault> {
        let key = kpub::read(kpub_text.trim().as_bytes())
            .ok_or_else(|| Fault("not a kpub".to_string()))?;
        Ok(Account {
            inner: watch::Account::new(key),
        })
    }

    /// The x-only key at `chain`/`index`, hex. `chain` is 0 for receive, 1
    /// for change.
    pub fn public_key(&self, chain: u32, index: u32) -> Result<String, Fault> {
        Ok(hex(&self
            .inner
            .public_key(chain, index)
            .map_err(Fault::of)?))
    }

    /// The locking script of `chain`/`index`, to match UTXOs against.
    pub fn script(&self, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.script(chain, index).map_err(Fault::of)?.to_vec())
    }

    /// The mainnet address of `chain`/`index`.
    pub fn address(&self, chain: u32, index: u32) -> Result<String, Fault> {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let n = self
            .inner
            .address(chain, index, &mut out)
            .map_err(Fault::of)?;
        Ok(text(&out[..n]))
    }
}

impl Account {
    /// The SDK's account.
    pub const fn inner(&self) -> &watch::Account {
        &self.inner
    }
}

/// A `45'` multisig group: the cosigners' kpubs and the threshold, from a
/// descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    inner: watch::Group,
}

impl Group {
    /// The group a descriptor line describes, `multi_hd45(M,kpub...,...)`,
    /// with or without its `#` header line.
    ///
    /// # Errors
    ///
    /// `Descriptor(..)` for text that does not read as one, with more keys
    /// than a unit signs, or with a bad threshold; `NotAKpub { index }`;
    /// `RepeatedKey { index }`.
    pub fn from_descriptor(descriptor: &str) -> Result<Group, Fault> {
        let line = kassigner_protocol::descriptor::strip_header(descriptor.trim());
        Ok(Group {
            inner: watch::Group::from_descriptor(line).map_err(Fault::of)?,
        })
    }

    /// Signatures the group needs.
    pub fn required(&self) -> u32 {
        self.inner.required() as u32
    }

    /// Keys in the group.
    pub fn total(&self) -> u32 {
        self.inner.total() as u32
    }

    /// The descriptor line of the group, as the SDK writes it.
    pub fn descriptor(&self) -> Result<String, Fault> {
        let mut out = vec![0u8; 64 + self.inner.total() * 128];
        let n = self.inner.write_descriptor(&mut out).map_err(Fault::of)?;
        Ok(text(&out[..n]))
    }

    /// The redeem script at `cosigner`/`chain`/`index`.
    pub fn redeem(&self, cosigner: u32, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        let mut out = [0u8; MAX_REDEEM];
        let n = self
            .inner
            .redeem(cosigner, chain, index, &mut out)
            .map_err(Fault::of)?;
        Ok(out[..n].to_vec())
    }

    /// The locking script at `cosigner`/`chain`/`index`, paying the redeem
    /// script's hash.
    pub fn script(&self, cosigner: u32, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(watch::group_script(&self.inner, cosigner, chain, index)
            .map_err(Fault::of)?
            .to_vec())
    }

    /// The mainnet address at `cosigner`/`chain`/`index`.
    pub fn address(&self, cosigner: u32, chain: u32, index: u32) -> Result<String, Fault> {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let n = watch::group_address(&self.inner, cosigner, chain, index, &mut out)
            .map_err(Fault::of)?;
        Ok(text(&out[..n]))
    }
}

impl Group {
    /// The SDK's group.
    pub const fn inner(&self) -> &watch::Group {
        &self.inner
    }
}

/// A `22'` address a unit made: all an app knows of a `22'` account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc3Address {
    inner: watch::Kcc3Address,
}

impl Kcc3Address {
    /// `address` as a `22'` address: a script-hash address on mainnet.
    pub fn read(address: &str) -> Result<Kcc3Address, Fault> {
        Ok(Kcc3Address {
            inner: watch::Kcc3Address::read(address.as_bytes()).map_err(Fault::of)?,
        })
    }

    /// The address as text.
    pub fn text(&self) -> String {
        text(self.inner.text())
    }

    /// The locking script an output paying this address carries.
    pub fn script(&self) -> Vec<u8> {
        self.inner.script().to_vec()
    }
}

impl Kcc3Address {
    /// The SDK's address.
    pub const fn inner(&self) -> &watch::Kcc3Address {
        &self.inner
    }
}

/// What [`read_import`] read: `kind`, and the fields that kind fills.
#[derive(Clone, Debug)]
pub struct Imported {
    /// `account`, `cosigner`, `descriptor`, `kcc3Address` or
    /// `signedMessage`.
    pub kind: &'static str,
    /// An `account` import's `44'` account, or a `cosigner` import's key
    /// held as an account.
    pub account: Option<Account>,
    /// A `cosigner` import's seed fingerprint, hex.
    pub fingerprint: Option<String>,
    /// A `descriptor` import's group.
    pub group: Option<Group>,
    /// A `descriptor` import's line, header stripped.
    pub descriptor: Option<String>,
    /// A `kcc3Address` import's address.
    pub kcc3_address: Option<Kcc3Address>,
    /// A `signedMessage` import's record, not verified.
    pub signed_message: Option<crate::message::Record>,
}

/// `bytes`, one code, file or pasted text, read as one of the five things
/// a unit hands over.
///
/// # Errors
///
/// `NotRecognised` for anything else; the shape's own error for bytes that
/// begin as one of the five and do not read as it.
pub fn read_import(bytes: &[u8]) -> Result<Imported, Fault> {
    let none = Imported {
        kind: "",
        account: None,
        fingerprint: None,
        group: None,
        descriptor: None,
        kcc3_address: None,
        signed_message: None,
    };
    Ok(match import::read(bytes).map_err(Fault::of)? {
        Import::Account(a) => Imported {
            kind: "account",
            account: Some(Account { inner: a }),
            ..none
        },
        Import::Cosigner { fingerprint, key } => Imported {
            kind: "cosigner",
            account: Some(Account {
                inner: watch::Account::new(key),
            }),
            fingerprint: Some(hex(&fingerprint)),
            ..none
        },
        Import::Descriptor(line) => Imported {
            kind: "descriptor",
            group: Some(Group {
                inner: watch::Group::from_descriptor(line).map_err(Fault::of)?,
            }),
            descriptor: Some(line.to_string()),
            ..none
        },
        Import::Kcc3Address(a) => Imported {
            kind: "kcc3Address",
            kcc3_address: Some(Kcc3Address { inner: a }),
            ..none
        },
        Import::SignedMessage(parts) => Imported {
            kind: "signedMessage",
            signed_message: Some(crate::message::Record::of(bytes, &parts)),
            ..none
        },
    })
}

/// The locking script a mainnet address pays to.
pub fn script_of_address(address: &str) -> Result<Vec<u8>, Fault> {
    let mut out = [0u8; PAY_TO_SCRIPT_HASH_LEN];
    let n = request::script_of_address(address.as_bytes(), &mut out).map_err(Fault::of)?;
    Ok(out[..n].to_vec())
}

/// The mainnet address a locking script pays.
pub fn address_of_script(script: &[u8]) -> Result<String, Fault> {
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = watch::address_of_script(script, &mut out).map_err(Fault::of)?;
    Ok(text(&out[..n]))
}

/// Text the SDK wrote, as a string.
pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
