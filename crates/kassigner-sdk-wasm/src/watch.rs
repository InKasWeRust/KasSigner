// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a unit hands over, read, and the addresses and scripts derived
//! from it: [`kassigner_sdk_host::watch`] for JavaScript.

use wasm_bindgen::prelude::*;

use kassigner_sdk_host::watch as host;

use crate::Fault;

/// A `44'` account, watched through its kpub.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    inner: host::Account,
}

#[wasm_bindgen]
impl Account {
    /// The account behind a kpub, text (`kpub...`) or a unit's raw form.
    #[wasm_bindgen(js_name = fromKpub)]
    pub fn from_kpub(kpub_text: &str) -> Result<Account, Fault> {
        Ok(Account {
            inner: host::Account::from_kpub(kpub_text)?,
        })
    }

    /// The key at `chain`/`index`, x only, as hex. `chain` is 0 for
    /// receive, 1 for change.
    #[wasm_bindgen(js_name = publicKey)]
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

    pub(crate) const fn over(inner: host::Account) -> Account {
        Account { inner }
    }
}

/// A `45'` multisig group: the cosigners' kpubs and the threshold, from a
/// descriptor.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    inner: host::Group,
}

#[wasm_bindgen]
impl Group {
    /// The group a descriptor line describes, `multi_hd45(M,kpub...,...)`,
    /// with or without its `#` header line.
    #[wasm_bindgen(js_name = fromDescriptor)]
    pub fn from_descriptor(descriptor: &str) -> Result<Group, Fault> {
        Ok(Group {
            inner: host::Group::from_descriptor(descriptor)?,
        })
    }

    /// Signatures the group needs.
    #[wasm_bindgen(getter)]
    pub fn required(&self) -> u32 {
        self.inner.required()
    }

    /// Keys in the group.
    #[wasm_bindgen(getter)]
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

    pub(crate) const fn over(inner: host::Group) -> Group {
        Group { inner }
    }
}

/// A `22'` address a unit made, held as text: the one thing an app knows of
/// a `22'` account.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kcc3Address {
    inner: host::Kcc3Address,
}

#[wasm_bindgen]
impl Kcc3Address {
    /// `address` as a `22'` address: a script-hash address on mainnet.
    pub fn read(address: &str) -> Result<Kcc3Address, Fault> {
        Ok(Kcc3Address {
            inner: host::Kcc3Address::read(address)?,
        })
    }

    /// The address as text.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner.text()
    }

    /// The locking script an output paying it carries.
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

/// What [`read_import`] read: `kind` says which of the five things it is,
/// and the matching field holds it.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct Imported {
    inner: host::Imported,
}

#[wasm_bindgen]
impl Imported {
    /// `account`, `cosigner`, `descriptor`, `kcc3Address` or
    /// `signedMessage`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind.to_string()
    }

    /// The `44'` account of an `account` import, or the cosigner's key held
    /// as an account of a `cosigner` import.
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Option<Account> {
        self.inner.account.map(Account::over)
    }

    /// A `cosigner` import's seed fingerprint, hex.
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> Option<String> {
        self.inner.fingerprint.clone()
    }

    /// A `descriptor` import's group.
    #[wasm_bindgen(getter)]
    pub fn group(&self) -> Option<Group> {
        self.inner.group.map(Group::over)
    }

    /// A `descriptor` import's line, header stripped: what to keep.
    #[wasm_bindgen(getter)]
    pub fn descriptor(&self) -> Option<String> {
        self.inner.descriptor.clone()
    }

    /// A `kcc3Address` import's address.
    #[wasm_bindgen(getter, js_name = kcc3Address)]
    pub fn kcc3_address(&self) -> Option<Kcc3Address> {
        self.inner.kcc3_address.map(|inner| Kcc3Address { inner })
    }

    /// A `signedMessage` import's record, not yet verified
    /// ([`crate::message::verify_message`]).
    #[wasm_bindgen(getter, js_name = signedMessage)]
    pub fn signed_message(&self) -> Option<crate::message::Record> {
        self.inner
            .signed_message
            .clone()
            .map(crate::message::Record::over)
    }
}

/// What `bytes` are, of the five things a unit hands over: one code, file
/// or pasted text, as it came.
///
/// Throws `NotRecognised` for anything else, and that thing's own error for
/// bytes that begin as one of the five and do not read as it.
#[wasm_bindgen(js_name = readImport)]
pub fn read_import(bytes: &[u8]) -> Result<Imported, Fault> {
    Ok(Imported {
        inner: host::read_import(bytes)?,
    })
}

/// The locking script a mainnet address pays to.
#[wasm_bindgen(js_name = scriptOfAddress)]
pub fn script_of_address(address: &str) -> Result<Vec<u8>, Fault> {
    Ok(host::script_of_address(address)?)
}

/// The mainnet address a locking script pays.
#[wasm_bindgen(js_name = addressOfScript)]
pub fn address_of_script(script: &[u8]) -> Result<String, Fault> {
    Ok(host::address_of_script(script)?)
}
