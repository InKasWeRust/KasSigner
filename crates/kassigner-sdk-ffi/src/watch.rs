// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit hands over, and the keys, scripts and addresses derived
//! from it: [`kassigner_sdk_host::watch`] over the C ABI.

use std::sync::Arc;

use kassigner_sdk_host::watch as host;

use crate::Fault;

/// A `44'` account, watched through its kpub.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Account {
    inner: host::Account,
}

#[uniffi::export]
impl Account {
    /// The account behind a kpub, as text (`kpub...`) or a unit's raw form.
    #[uniffi::constructor]
    pub fn from_kpub(kpub: String) -> Result<Account, Fault> {
        Ok(Account {
            inner: host::Account::from_kpub(&kpub)?,
        })
    }

    /// The x-only key at `chain`/`index`, hex; `chain` is 0 for receive, 1
    /// for change.
    pub fn public_key(&self, chain: u32, index: u32) -> Result<String, Fault> {
        Ok(self.inner.public_key(chain, index)?)
    }

    /// The locking script of `chain`/`index`, to match UTXOs against.
    pub fn script(&self, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.script(chain, index)?)
    }

    /// The mainnet address of `chain`/`index`.
    pub fn address(&self, chain: u32, index: u32) -> Result<String, Fault> {
        Ok(self.inner.address(chain, index)?)
    }
}

impl Account {
    /// The host crate's account.
    pub const fn inner(&self) -> &host::Account {
        &self.inner
    }
}

/// A `45'` multisig group: the cosigners' kpubs and the threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Group {
    inner: host::Group,
}

#[uniffi::export]
impl Group {
    /// The group a descriptor line describes, `multi_hd45(M,kpub...,...)`,
    /// with or without its `#` header line.
    #[uniffi::constructor]
    pub fn from_descriptor(descriptor: String) -> Result<Group, Fault> {
        Ok(Group {
            inner: host::Group::from_descriptor(&descriptor)?,
        })
    }

    /// Signatures the group needs.
    pub fn required(&self) -> u32 {
        self.inner.required()
    }

    /// Keys in the group.
    pub fn total(&self) -> u32 {
        self.inner.total()
    }

    /// The descriptor line of the group, as the SDK writes it.
    pub fn descriptor(&self) -> Result<String, Fault> {
        Ok(self.inner.descriptor()?)
    }

    /// The redeem script at `cosigner`/`chain`/`index`.
    pub fn redeem(&self, cosigner: u32, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.redeem(cosigner, chain, index)?)
    }

    /// The locking script at `cosigner`/`chain`/`index`.
    pub fn script(&self, cosigner: u32, chain: u32, index: u32) -> Result<Vec<u8>, Fault> {
        Ok(self.inner.script(cosigner, chain, index)?)
    }

    /// The mainnet address at `cosigner`/`chain`/`index`.
    pub fn address(&self, cosigner: u32, chain: u32, index: u32) -> Result<String, Fault> {
        Ok(self.inner.address(cosigner, chain, index)?)
    }
}

impl Group {
    /// The host crate's group.
    pub const fn inner(&self) -> &host::Group {
        &self.inner
    }
}

/// A `22'` address a unit made: all an app knows of a `22'` account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Object)]
pub struct Kcc3Address {
    inner: host::Kcc3Address,
}

#[uniffi::export]
impl Kcc3Address {
    /// `address` read as a `22'` address: a mainnet script-hash address.
    #[uniffi::constructor]
    pub fn read(address: String) -> Result<Kcc3Address, Fault> {
        Ok(Kcc3Address {
            inner: host::Kcc3Address::read(&address)?,
        })
    }

    /// The address as text.
    pub fn text(&self) -> String {
        self.inner.text()
    }

    /// The locking script of an output paying it.
    pub fn script(&self) -> Vec<u8> {
        self.inner.script()
    }
}

impl Kcc3Address {
    /// The host crate's address.
    pub const fn inner(&self) -> &host::Kcc3Address {
        &self.inner
    }
}

/// What [`read_import`] read: `kind` says which of the five, and the
/// matching field holds it.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Imported {
    /// `account`, `cosigner`, `descriptor`, `kcc3Address` or
    /// `signedMessage`.
    pub kind: String,
    /// An `account` import's `44'` account, or a `cosigner` import's key as
    /// an account.
    pub account: Option<Arc<Account>>,
    /// A `cosigner` import's seed fingerprint, hex.
    pub fingerprint: Option<String>,
    /// A `descriptor` import's group.
    pub group: Option<Arc<Group>>,
    /// A `descriptor` import's line without its header: what to keep.
    pub descriptor: Option<String>,
    /// A `kcc3Address` import's address.
    pub kcc3_address: Option<Arc<Kcc3Address>>,
    /// A `signedMessage` import's record, unverified
    /// ([`crate::message::verify_message`] verifies it).
    pub signed_message: Option<crate::message::Record>,
}

/// What `bytes` are, of the five things a unit hands over: one code, file
/// or pasted text, as it came.
///
/// # Errors
///
/// `NotRecognised` for anything else; the shape's own error for bytes that
/// begin as one of the five but do not read as it.
#[uniffi::export]
pub fn read_import(bytes: Vec<u8>) -> Result<Imported, Fault> {
    let i = host::read_import(&bytes)?;
    Ok(Imported {
        kind: i.kind.to_string(),
        account: i.account.map(|inner| Arc::new(Account { inner })),
        fingerprint: i.fingerprint,
        group: i.group.map(|inner| Arc::new(Group { inner })),
        descriptor: i.descriptor,
        kcc3_address: i.kcc3_address.map(|inner| Arc::new(Kcc3Address { inner })),
        signed_message: i.signed_message.map(crate::message::Record::from),
    })
}

/// The locking script a mainnet address pays to.
#[uniffi::export]
pub fn script_of_address(address: String) -> Result<Vec<u8>, Fault> {
    Ok(host::script_of_address(&address)?)
}

/// The mainnet address a locking script pays.
#[uniffi::export]
pub fn address_of_script(script: Vec<u8>) -> Result<String, Fault> {
    Ok(host::address_of_script(&script)?)
}
