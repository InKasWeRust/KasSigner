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

//! Which key signs which input, and at which position among its script's
//! keys.
//!
//! # Hint first, then the bank
//!
//! A request may name the derivation of an input's key: a KSPT through its
//! input hint (cosigner, chain and index below the multisig account) or its
//! KCC-3 input hint (chain and index below the KCC-3 account), a PSKB
//! through `bip32Derivations` (a full path per key, read by [`path_of`]). A
//! hint is a claim by whoever built the request: the key it names is
//! derived and checked against the script, and ignored if the script does
//! not hold it.
//!
//! Otherwise the script's keys are looked up in the bank: the first
//! [`RECEIVE_DEPTH`] receiving and [`CHANGE_DEPTH`] change keys, derived
//! when the keyring is built. A hit gives the path; the private key is
//! derived on demand. The address browser reaches deeper; that is a
//! separate question.
//!
//! # Past the bank
//!
//! A bank miss is "not ours" only after a search: receive and change
//! alternating in batches of [`crate::limits::SEARCH_BATCH`], each key
//! derived, compared and dropped, out to [`crate::limits::SEARCH_DEPTH`] on
//! each chain. The reply refuses if no input is ours. The search runs only
//! for an input the request gave no derivation for, single-key or a
//! covenant redeem, as in a rusty-kaspa 2.1.0 wallet's PSKB, which carries
//! no `bip32Derivations` until a signer writes them. A wrong hint stops at
//! the bank: a PSKB can carry several derivations per input, and searching a
//! thousand keys for each would let a lying request burn minutes.
//!
//! # A multisig is its `45'` hint
//!
//! A multisig redeem is matched through a `45'` hint alone, no bank and no
//! search: its keys are `45'` cosigner keys, which neither holds, and a
//! `45'` multisig carries its hint by rule. A multisig over `44'` keys, as
//! v1.0.5 built, is not recognised (its coins are swept with v1.0.7 or
//! older), so a `44'` path is no hint for one. A raw key has no `45'` tree,
//! and a `45'` address takes a child of every cosigner's kpub, so a raw-key
//! wallet signs no multisig.
//!
//! # KCC-3
//!
//! KCC-3 ("Pay-to-Public-Key-Hash via P2SH") locks a key behind the hash of
//! `<P> OP_CHECKSIG`, with keys under their own purpose, `22'`. A wallet
//! with that tree (a mnemonic or a master xprv) has a second bank there,
//! [`KCC3_BANK`] keys at the same depths, looked up for that redeem alone;
//! the `44'` bank never is. Past it, as past the first: a `22'` path names a
//! key, and with none the KCC-3 chains are searched, here or by the flow's
//! sweep. A `44'` miss sweeps `44'` keys and a KCC-3 miss KCC-3 keys, never
//! both.
//!
//! kassigner.org can watch and spend from a KCC-3 address knowing only its
//! hash: P stays on the device until the spend makes it public. Such an
//! input has no redeem script; when its hash is that of a KCC-3 key found as
//! above, the device supplies the script ([`Match::supplied`]), signs, and
//! the reply carries the script for whoever finishes the spend.
//!
//! # What is matched
//!
//! - Pay-to-public-key: the script's one key, position zero.
//! - A multisig redeem: the key its `45'` hint names, at its position. One
//!   this device does not sign (a threshold of zero, more than
//!   [`crate::limits::MAX_MULTISIG_KEYS`] keys, a key twice, a non-standard
//!   form) is refused, not skipped, which would let it fall through to the
//!   covenant case.
//! - No redeem script: KCC-3's, as above; any other hash is
//!   `NoRedeemScript`.
//! - KCC-3's redeem, exactly `<P> OP_CHECKSIG`, P a KCC-3 key: position
//!   zero. It agrees to nothing but a signature by P, so no page has
//!   anything to show. Any other P falls to the cases below.
//! - A Time-Locked Savings card's program
//!   ([`kassigner_protocol::card::savings`]): the owner's key at position 0
//!   or the recovery wallet's at 1 (the owner's at 0 when there is none),
//!   by a `44'` hint or found as a single key is. Its page shows the card,
//!   so it is signed; a card breaking the card's rules was refused before
//!   ([`kassigner_protocol::check::card`]).
//! - Any other redeem (a covenant, anything else): a key of ours found as
//!   above is refused (`Error::ScriptUnshown`). The review has no page for
//!   an input's script, so what the signature agrees to (a covenant's terms,
//!   an inscription) would go unseen; it is refused before the review, as
//!   covenant bindings and payloads are.
//! - ECDSA and non-standard scripts: not ours.
//!

use core::borrow::Borrow;
use core::cell::Cell;

use crate::limits::{CHANGE_DEPTH, MAX_INPUTS, RECEIVE_DEPTH, SEARCH_BATCH, SEARCH_DEPTH};
use kassigner_crypto::bip32::Bip32Error;
use kassigner_crypto::wallet::{SigningKey, Wallet, WalletError};
use kassigner_kaspa::bip32_public::{parse_path_chars, ChildNumber, ExtendedPublicKey};
use kassigner_kaspa::derivation::{Path, CHANGE, KCC3_ACCOUNT, MULTISIG_ACCOUNT, SINGLE_ACCOUNT};
use kassigner_kaspa::pskb::lexer::ascii;
use kassigner_kaspa::script::{
    classify, kcc3_key, kcc3_redeem, kcc3_script_hash, multisig_shape, redeem_matches,
    schnorr_keys, ScriptClass, KCC3_REDEEM_LEN,
};
use kassigner_kaspa::tx::ScriptPublicKey;
use kassigner_protocol::card::savings::Savings;
use kassigner_protocol::check;
use kassigner_protocol::kspt::{AccountHint, Hint, Kcc3Hint};

/// A KSPT cosigner hint as a path below the multisig account. `None`, read
/// as no hint rather than failing the request, for a hardened number (no
/// derivation below an account takes one) or a chain other than receive and
/// change (it would sign with a key outside the wallet's addresses).
pub const fn path_of_hint(h: Hint) -> Option<Path> {
    if !is_soft(h.cosigner) || !is_chain(h.chain) || !is_soft(h.addr_index) {
        return None;
    }
    Some(Path::Multisig {
        cosigner: h.cosigner,
        chain: h.chain,
        index: h.addr_index,
    })
}

/// A KSPT KCC-3 hint as a path below the KCC-3 account; `None` as for
/// [`path_of_hint`].
pub const fn path_of_kcc3_hint(h: Kcc3Hint) -> Option<Path> {
    if !is_chain(h.chain) || !is_soft(h.addr_index) {
        return None;
    }
    Some(Path::Kcc3 {
        chain: h.chain,
        index: h.addr_index,
    })
}

/// A KSPT single-key hint as a path below the single-key account: where an
/// input's or an output's key is. `None` as for [`path_of_hint`]. Any soft
/// index is taken, however deep: the key it names is derived and compared,
/// never trusted.
pub const fn path_of_account_hint(h: AccountHint) -> Option<Path> {
    if !is_chain(h.chain) || !is_soft(h.addr_index) {
        return None;
    }
    Some(Path::Single {
        chain: h.chain,
        index: h.addr_index,
    })
}

/// A number below the hardened children.
const fn is_soft(v: u32) -> bool {
    v & 0x8000_0000 == 0
}

/// Receive (0) or change (1): the only chains a request's path is taken on.
const fn is_chain(v: u32) -> bool {
    v <= 1
}

/// A bundle's full derivation path as a [`Path`] below one of the wallet's
/// three account nodes. `None` for anything else, including a path the
/// device could derive but does not sign with, such as a chain other than
/// receive and change.
///
/// `text` is the string as the bundle holds it; its escapes are decoded, as
/// upstream decodes them, so a path written with escapes still reads.
pub fn path_of(text: &[u8]) -> Option<Path> {
    let mut levels = [ChildNumber(0); 6];
    let n = parse_path_chars(ascii(text), &mut levels).ok()?;
    let soft = |c: ChildNumber| (!c.is_hardened()).then_some(c.0);
    let chain = |c: ChildNumber| soft(c).filter(|&v| is_chain(v));
    match (n, &levels[..3]) {
        (5, a) if *a == SINGLE_ACCOUNT => Some(Path::Single {
            chain: chain(levels[3])?,
            index: soft(levels[4])?,
        }),
        (6, a) if *a == MULTISIG_ACCOUNT => Some(Path::Multisig {
            cosigner: soft(levels[3])?,
            chain: chain(levels[4])?,
            index: soft(levels[5])?,
        }),
        (5, a) if *a == KCC3_ACCOUNT => Some(Path::Kcc3 {
            chain: chain(levels[3])?,
            index: soft(levels[4])?,
        }),
        _ => None,
    }
}

pub const BANK: usize = (RECEIVE_DEPTH + CHANGE_DEPTH) as usize;

/// The path of the bank's key `k`: the receive chain first, then change.
pub const fn bank_path(k: usize) -> Path {
    if (k as u32) < RECEIVE_DEPTH {
        Path::receive(k as u32)
    } else {
        Path::change(k as u32 - RECEIVE_DEPTH)
    }
}

/// A wallet's two chains' extended public keys, receiving then change, or
/// `None` for a raw key: what [`address`] derives from.
///
/// # Errors
///
/// `Wallet` if a derivation fails.
pub fn chain_keys(wallet: &Wallet) -> Result<Option<[ExtendedPublicKey; 2]>, Error> {
    match (wallet.chain_public(0)?, wallet.chain_public(1)?) {
        (Some(r), Some(c)) => Ok(Some([r, c])),
        _ => Ok(None),
    }
}

/// The x-only public key of the address at `path`: for a single-key path of
/// a wallet with chains, one curve multiplication from the chain's public
/// key; otherwise the wallet's own derivation (a raw key's one key).
///
/// # Errors
///
/// `Wallet` if a derivation fails.
pub fn address(
    wallet: &Wallet,
    chains: Option<&[ExtendedPublicKey; 2]>,
    path: Path,
) -> Result<[u8; 32], Error> {
    let (Some(chains), Path::Single { chain, index }) = (chains, path) else {
        return Ok(wallet.signing_key(path)?.x_only());
    };
    let parent = chains
        .get(chain as usize)
        .ok_or(Error::Wallet(WalletError::Bip32(Bip32Error::InvalidChild)))?;
    let child = parent
        .derive_child(ChildNumber(index))
        .map_err(|_| Error::Wallet(WalletError::Bip32(Bip32Error::InvalidChild)))?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&child.public_key[1..]);
    Ok(x)
}

/// The bank's key `k`, path and x-only key: one derivation, for a caller
/// deriving the bank a key at a time.
///
/// # Errors
///
/// The wallet's, if the derivation fails.
pub fn bank_key(
    wallet: &Wallet,
    chains: Option<&[ExtendedPublicKey; 2]>,
    k: usize,
) -> Result<(Path, [u8; 32]), Error> {
    let path = bank_path(k);
    Ok((path, address(wallet, chains, path)?))
}

/// Keys in the KCC-3 bank: the same depths as the first.
pub const KCC3_BANK: usize = BANK;

/// The path of the KCC-3 bank's key `k`, ordered as [`bank_path`].
pub const fn kcc3_bank_path(k: usize) -> Path {
    match bank_path(k) {
        Path::Single { chain, index } => Path::Kcc3 { chain, index },
        other => other,
    }
}

/// A wallet's two KCC-3 chains' extended public keys, receiving then
/// change; `None` with no `22'` tree (an account xprv, a raw key).
///
/// # Errors
///
/// `Wallet` if a derivation fails.
pub fn kcc3_chain_keys(wallet: &Wallet) -> Result<Option<[ExtendedPublicKey; 2]>, Error> {
    match (wallet.kcc3_chain_public(0)?, wallet.kcc3_chain_public(1)?) {
        (Some(r), Some(c)) => Ok(Some([r, c])),
        _ => Ok(None),
    }
}

/// The KCC-3 bank's key `k`, x-only, from the chains' public keys.
///
/// # Errors
///
/// `Wallet` if the derivation fails.
pub fn kcc3_bank_key(chains: &[ExtendedPublicKey; 2], k: usize) -> Result<[u8; 32], Error> {
    kcc3_key_at(chains, kcc3_bank_path(k))
}

/// The x-only key of the KCC-3 address at `path` from the chains' public
/// keys: one curve multiplication. `InvalidChild` for a path that is not
/// KCC-3's.
fn kcc3_key_at(chains: &[ExtendedPublicKey; 2], path: Path) -> Result<[u8; 32], Error> {
    let invalid = Error::Wallet(WalletError::Bip32(Bip32Error::InvalidChild));
    let Path::Kcc3 { chain, index } = path else {
        return Err(invalid);
    };
    let child = chains
        .get(chain as usize)
        .ok_or(invalid)?
        .derive_child(ChildNumber(index))
        .map_err(|_| invalid)?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&child.public_key[1..]);
    Ok(x)
}

/// The two chains under an account, for the search past the bank.
#[derive(Clone, Copy)]
enum Chain {
    Receive,
    Change,
}

/// Why an input could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A pay-to-script-hash input carries no redeem script, and its hash is
    /// not a KCC-3 address this device supplies one for.
    NoRedeemScript,
    /// A multisig this device does not sign: a threshold of zero, or more
    /// than [`crate::limits::MAX_MULTISIG_KEYS`] keys.
    UnsupportedMultisig { required: u8, keys: u8 },
    /// A multisig holding one key twice, the key at `position` repeating an
    /// earlier one ([`kassigner_protocol::group::repeated_key`]): its M of N
    /// counts the key twice, but a unit signs one of its places and none the
    /// other. Refused whether or not the key is ours.
    RepeatedKey { position: usize },
    /// The redeem script is not the one the input's script locks to. The
    /// network would never run it: the request is malformed or hostile, and
    /// none of it is signed.
    RedeemMismatch,
    /// A pay-to-script-hash input whose redeem script the review has no page
    /// for, so it would be signed unseen: a multisig in a non-standard form,
    /// or a script holding a key of ours that is not a multisig, KCC-3's over
    /// a KCC-3 key, or a Time-Locked Savings card's.
    ScriptUnshown,
    /// The private key derived for an address found among the public keys is
    /// not that address's key: the public derivation disagrees with the
    /// private one. Refused, since a signature by the other key spends
    /// nothing and means nothing on a PSKB.
    KeyMismatch,
    /// Deriving a key failed.
    Wallet(WalletError),
}

impl From<WalletError> for Error {
    fn from(e: WalletError) -> Self {
        Error::Wallet(e)
    }
}

/// The redeem script's keys, the first 256 only, so an index fits the one
/// byte a position travels in.
fn keys_of(redeem: &[u8]) -> impl Iterator<Item = &[u8]> + '_ {
    schnorr_keys(redeem).take(usize::from(u8::MAX) + 1)
}

/// The key for one input, and where it signs.
pub struct Match {
    pub key: SigningKey,
    pub position: u8,
    /// The M of N of the multisig the key signs in, from its redeem;
    /// `None` for any other script.
    pub shape: Option<(u8, u8)>,
    /// KCC-3's redeem script over the key, supplied for an input that came
    /// without one: the reply carries it, and every check of an input's
    /// redeem reads it. `None` for an input that came with its redeem or
    /// needs none.
    pub supplied: Option<[u8; KCC3_REDEEM_LEN]>,
}

/// The wallet's keys, derived once here, ready to be looked up.
///
/// `W` holds the wallet by value (`Keyring<Wallet>`) for the flow, which
/// lives across events and cannot borrow from a frame, or by reference
/// (`Keyring<&Wallet>`) for a caller that opened the wallet and keeps using
/// it.
pub struct Keyring<W: Borrow<Wallet> = Wallet> {
    wallet: W,
    bank: [(Path, [u8; 32]); BANK],
    /// The KCC-3 bank's keys (paths by [`kcc3_bank_path`]) and the KCC-3
    /// chains' public keys, for addresses past it; `None` with no `22'`
    /// tree.
    kcc3: Option<[[u8; 32]; KCC3_BANK]>,
    kcc3_chains: Option<[ExtendedPublicKey; 2]>,
    /// The two chains' public keys, for the sweep: `None` for a raw key.
    chains: Option<[ExtendedPublicKey; 2]>,
    /// Whether a bank miss searches past the bank at once. On by default;
    /// the flow turns it off and sweeps a window at a time instead, so the
    /// screen keeps answering.
    search: bool,
    /// Keys past the bank the sweep found for the request in hand.
    found: [(Path, [u8; 32]); MAX_INPUTS],
    found_len: usize,
    /// The sweep's window: keys past the bank, derived a few at a time.
    window: [(Path, [u8; 32]); WINDOW],
    window_len: usize,
    /// Which of the window's keys a lookup matched, a bit each.
    hits: Cell<u64>,
    /// Lookups that would have searched past the bank and found nothing.
    misses: Cell<usize>,
    /// The same for KCC-3's keys, and whether the flow's KCC-3 sweep has
    /// ended for this request: after that, a KCC-3 address with no redeem
    /// that nothing found is refused rather than pending.
    kcc3_misses: Cell<usize>,
    kcc3_swept: bool,
}

/// Keys in the sweep's window: looked up, then replaced by the next.
pub const WINDOW: usize = 50;

/// How many keys past the bank the sweep derives: both chains, from where
/// the bank stops to [`SEARCH_DEPTH`].
pub const SWEEP: usize = (SEARCH_DEPTH - RECEIVE_DEPTH + SEARCH_DEPTH - CHANGE_DEPTH) as usize;

/// The sweep's key `i`: receive and change alternating a window at a time,
/// each from where the bank stops, so change keys are not left until the
/// whole receive chain is done. `None` at or past [`SWEEP`]: there every
/// window is empty, and the walk below would run until its count overflowed
/// (a panic with overflow checks, no end without).
pub const fn sweep_path(i: usize) -> Option<Path> {
    if i >= SWEEP {
        return None;
    }
    let w = WINDOW as u32;
    let (r, c) = (SEARCH_DEPTH - RECEIVE_DEPTH, SEARCH_DEPTH - CHANGE_DEPTH);
    let (mut left, mut block) = (i as u32, 0u32);
    loop {
        let rb = if block * w < r {
            min(w, r - block * w)
        } else {
            0
        };
        if left < rb {
            return Some(Path::receive(RECEIVE_DEPTH + block * w + left));
        }
        left -= rb;
        let cb = if block * w < c {
            min(w, c - block * w)
        } else {
            0
        };
        if left < cb {
            return Some(Path::change(CHANGE_DEPTH + block * w + left));
        }
        left -= cb;
        block += 1;
    }
}

/// The KCC-3 sweep's key `i`: the same walk as [`sweep_path`]'s, over the
/// KCC-3 chains. `None` at or past [`SWEEP`].
pub const fn kcc3_sweep_path(i: usize) -> Option<Path> {
    match sweep_path(i) {
        Some(Path::Single { chain, index }) => Some(Path::Kcc3 { chain, index }),
        _ => None,
    }
}

const fn min(a: u32, b: u32) -> u32 {
    if a < b {
        a
    } else {
        b
    }
}

const _: () = assert!(WINDOW <= 64, "one bit a window key in `hits`");

impl<W: Borrow<Wallet>> Keyring<W> {
    /// Derive the bank.
    ///
    /// # Errors
    ///
    /// `Wallet` if a derivation fails.
    pub fn new(wallet: W) -> Result<Self, Error> {
        let chains = chain_keys(wallet.borrow())?;
        let mut bank = [(Path::receive(0), [0u8; 32]); BANK];
        for (k, slot) in bank.iter_mut().enumerate() {
            *slot = bank_key(wallet.borrow(), chains.as_ref(), k)?;
        }
        let kcc3 = match kcc3_chain_keys(wallet.borrow())? {
            Some(c) => {
                let mut keys = [[0u8; 32]; KCC3_BANK];
                for (k, slot) in keys.iter_mut().enumerate() {
                    *slot = kcc3_bank_key(&c, k)?;
                }
                Some((keys, c))
            }
            None => None,
        };
        let ring = Self::from_bank(wallet, bank, chains);
        Ok(match kcc3 {
            Some((keys, c)) => ring.with_kcc3(keys, c),
            None => ring,
        })
    }

    /// A keyring over a bank already derived key by key with [`bank_key`],
    /// as the flow does to draw progress between keys. `bank[k]` must be
    /// `bank_key(wallet, chains, k)` and `chains` the wallet's [`chain_keys`].
    pub fn from_bank(
        wallet: W,
        bank: [(Path, [u8; 32]); BANK],
        chains: Option<[ExtendedPublicKey; 2]>,
    ) -> Self {
        Self {
            wallet,
            bank,
            kcc3: None,
            kcc3_chains: None,
            chains,
            search: true,
            found: [(Path::receive(0), [0u8; 32]); MAX_INPUTS],
            found_len: 0,
            window: [(Path::receive(0), [0u8; 32]); WINDOW],
            window_len: 0,
            hits: Cell::new(0),
            misses: Cell::new(0),
            kcc3_misses: Cell::new(0),
            kcc3_swept: false,
        }
    }

    /// Add the KCC-3 bank, derived with [`kcc3_bank_key`] from `chains`, the
    /// wallet's [`kcc3_chain_keys`]: `keys[k]` must be the key at
    /// [`kcc3_bank_path`]`(k)`. A keyring from [`Keyring::from_bank`] has
    /// none until this.
    #[must_use]
    pub fn with_kcc3(
        mut self,
        keys: [[u8; 32]; KCC3_BANK],
        chains: [ExtendedPublicKey; 2],
    ) -> Self {
        self.kcc3 = Some(keys);
        self.kcc3_chains = Some(chains);
        self
    }

    /// The x-only key of the KCC-3 address at `path`: the bank's, else one
    /// derivation from the chain's public key.
    ///
    /// # Errors
    ///
    /// `Wallet(NoKcc3Tree)` for a keyring with no KCC-3 keys; `Wallet` if
    /// the derivation fails or `path` is not KCC-3's.
    pub fn kcc3_address_key(&self, path: Path) -> Result<[u8; 32], Error> {
        let (Some(keys), Some(chains)) = (self.kcc3.as_ref(), self.kcc3_chains.as_ref()) else {
            return Err(Error::Wallet(WalletError::NoKcc3Tree));
        };
        if let Some(k) = (0..KCC3_BANK).find(|&k| kcc3_bank_path(k) == path) {
            return Ok(keys[k]);
        }
        kcc3_key_at(chains, path)
    }

    /// Whether the keyring holds KCC-3 keys: a wallet with a `22'` tree.
    pub fn has_kcc3(&self) -> bool {
        self.kcc3.is_some()
    }

    /// Whether a lookup that misses the bank searches past it itself.
    pub fn set_search(&mut self, on: bool) {
        self.search = on;
    }

    /// Lookups that missed the bank, the keys found and the window, and
    /// would have searched on, since [`Keyring::forget_found`] or
    /// [`Keyring::clear_misses`].
    pub fn misses(&self) -> usize {
        self.misses.get()
    }

    /// The same for KCC-3's keys.
    pub fn kcc3_misses(&self) -> usize {
        self.kcc3_misses.get()
    }

    /// Whether the flow's KCC-3 sweep has ended for this request: from then
    /// on a KCC-3 address with no redeem that nothing found is refused
    /// (`NoRedeemScript`) rather than left for the sweep.
    pub fn set_kcc3_swept(&mut self, swept: bool) {
        self.kcc3_swept = swept;
    }

    /// Start over: no keys found past the bank, an empty window, no misses.
    /// For the next request, or the next look at this one.
    pub fn forget_found(&mut self) {
        self.found_len = 0;
        self.window_len = 0;
        self.hits.set(0);
        self.misses.set(0);
        self.kcc3_misses.set(0);
        self.kcc3_swept = false;
    }

    /// Count misses afresh, keeping what was found.
    pub fn clear_misses(&self) {
        self.misses.set(0);
        self.kcc3_misses.set(0);
    }

    /// The KCC-3 sweep's key `i`, from the KCC-3 chains; `None` with no `22'`
    /// tree, and past the sweep's end.
    ///
    /// # Errors
    ///
    /// `Wallet` if the derivation fails.
    pub fn kcc3_sweep_key(&self, i: usize) -> Result<Option<[u8; 32]>, Error> {
        match (&self.kcc3_chains, kcc3_sweep_path(i)) {
            (Some(chains), Some(path)) => Ok(Some(kcc3_key_at(chains, path)?)),
            _ => Ok(None),
        }
    }

    /// The sweep's key `i`, from the chains' public keys: nothing secret.
    /// `None` for a raw key, which has one key, and past the sweep's end.
    ///
    /// # Errors
    ///
    /// `Wallet` if the derivation fails.
    pub fn sweep_key(&self, i: usize) -> Result<Option<[u8; 32]>, Error> {
        match (&self.chains, sweep_path(i)) {
            (Some(chains), Some(path)) => {
                Ok(Some(address(self.wallet.borrow(), Some(chains), path)?))
            }
            _ => Ok(None),
        }
    }

    /// Whether the wallet has chains to sweep: not a raw key.
    pub fn has_chains(&self) -> bool {
        self.chains.is_some()
    }

    /// The x-only key of the address at `path`: the bank's, else made by
    /// [`address`]. A raw key has one address, whatever the path.
    ///
    /// # Errors
    ///
    /// `Wallet` if the derivation fails.
    pub fn address_key(&self, path: Path) -> Result<[u8; 32], Error> {
        if let Some((_, key)) = self.bank.iter().find(|(p, _)| *p == path) {
            return Ok(*key);
        }
        address(self.wallet(), self.chains.as_ref(), path)
    }

    /// The index of `key` on the seed's change chain among the keys at hand
    /// (the bank and what the sweep found), nothing derived: a change key
    /// past them is unknown here, and a request naming its change has it
    /// checked by [`Keyring::address_key`]. The review's CHANGE title rests
    /// on this: only a key this seed derived earns it. A raw key's one
    /// address matches at index 0, which says nothing: [`Keyring::has_chains`]
    /// tells.
    pub fn change_index(&self, key: &[u8; 32]) -> Option<u32> {
        self.bank
            .iter()
            .chain(&self.found[..self.found_len])
            .find_map(|&(path, k)| match path {
                Path::Single { index, .. } if k == *key && path == Path::change(index) => {
                    Some(index)
                }
                _ => None,
            })
    }

    /// As [`Keyring::change_index`], on the receive chain. The review's YOURS
    /// rests on this. A raw key's one address is its change, not a receive
    /// address, so the caller asks only of a seed with chains.
    pub fn receive_index(&self, key: &[u8; 32]) -> Option<u32> {
        self.bank
            .iter()
            .chain(&self.found[..self.found_len])
            .find_map(|&(path, k)| match path {
                Path::Single { index, .. } if k == *key && path == Path::receive(index) => {
                    Some(index)
                }
                _ => None,
            })
    }

    /// The KCC-3 change index of a pay-to-script-hash output's `hash`, when
    /// it is the script hash of one of the KCC-3 bank's change keys (the
    /// bank only). `None` with no `22'` tree.
    pub fn kcc3_change_index(&self, hash: &[u8; 32]) -> Option<u32> {
        let keys = self.kcc3.as_ref()?;
        keys.iter()
            .enumerate()
            .find_map(|(k, key)| match kcc3_bank_path(k) {
                Path::Kcc3 {
                    chain: CHANGE,
                    index,
                } if kcc3_script_hash(key) == *hash => Some(index),
                _ => None,
            })
    }

    /// Put the sweep's key `i` in the window. False, and nothing put, once
    /// it is full, or for a key past the sweep's end.
    pub fn window_push(&mut self, i: usize, key: [u8; 32]) -> bool {
        let Some(path) = sweep_path(i) else {
            return false;
        };
        if self.window_len == WINDOW {
            return false;
        }
        self.window[self.window_len] = (path, key);
        self.window_len += 1;
        true
    }

    /// Put the KCC-3 sweep's key `i` in the window, as
    /// [`Keyring::window_push`] puts the first's.
    pub fn kcc3_window_push(&mut self, i: usize, key: [u8; 32]) -> bool {
        let Some(path) = kcc3_sweep_path(i) else {
            return false;
        };
        if self.window_len == WINDOW {
            return false;
        }
        self.window[self.window_len] = (path, key);
        self.window_len += 1;
        true
    }

    /// Keys in the window.
    pub fn window_len(&self) -> usize {
        self.window_len
    }

    /// Keep the window's keys a lookup matched, and empty the window.
    pub fn keep_hits(&mut self) {
        let hits = self.hits.replace(0);
        for j in 0..self.window_len {
            let key = self.window[j];
            let known = self.found[..self.found_len].contains(&key);
            if hits & (1 << j) != 0 && !known && self.found_len < MAX_INPUTS {
                self.found[self.found_len] = key;
                self.found_len += 1;
            }
        }
        self.window_len = 0;
    }

    /// The wallet the keys come from.
    pub fn wallet(&self) -> &Wallet {
        self.wallet.borrow()
    }

    /// The path of a key past the bank that `wanted` accepts, if any:
    /// receive and change alternating in batches of [`SEARCH_BATCH`], each
    /// from where the bank stops to [`SEARCH_DEPTH`], one derivation per
    /// candidate, nothing kept. `wanted` sees each candidate's x-only key, so
    /// a script with several keys costs no more derivations than one.
    ///
    /// # Errors
    ///
    /// `Wallet` if a derivation fails.
    fn search(&self, mut wanted: impl FnMut(&[u8; 32]) -> bool) -> Result<Option<Path>, Error> {
        let wallet = self.wallet.borrow();
        let chains = [
            (Chain::Receive, RECEIVE_DEPTH),
            (Chain::Change, CHANGE_DEPTH),
        ];
        let mut from = 0u32;
        while from < SEARCH_DEPTH {
            let to = from + SEARCH_BATCH;
            for (chain, bank_depth) in chains {
                for i in from.max(bank_depth)..to {
                    let path = match chain {
                        Chain::Receive => Path::receive(i),
                        Chain::Change => Path::change(i),
                    };
                    if wanted(&wallet.signing_key(path)?.x_only()) {
                        return Ok(Some(path));
                    }
                }
            }
            from = to;
        }
        Ok(None)
    }

    /// [`Keyring::search`] over the KCC-3 chains, in the sweep's order
    /// ([`kcc3_sweep_path`]): one curve multiplication from the chains'
    /// public keys per candidate.
    ///
    /// # Errors
    ///
    /// `Wallet` if a derivation fails.
    fn kcc3_search(
        &self,
        mut wanted: impl FnMut(&[u8; 32]) -> bool,
    ) -> Result<Option<Path>, Error> {
        let Some(chains) = self.kcc3_chains.as_ref() else {
            return Ok(None);
        };
        let mut i = 0;
        while let Some(path) = kcc3_sweep_path(i) {
            if wanted(&kcc3_key_at(chains, path)?) {
                return Ok(Some(path));
            }
            i += 1;
        }
        Ok(None)
    }

    /// Look in the bank, the keys the sweep found and its window; then, when
    /// `deep`, search past them, or count a miss where the flow sweeps
    /// instead. KCC-3's keys are [`Keyring::kcc3_find`]'s.
    fn find(
        &self,
        deep: bool,
        mut wanted: impl FnMut(&[u8; 32]) -> bool,
    ) -> Result<Option<Path>, Error> {
        if let Some(p) = self.bank.iter().find(|(_, k)| wanted(k)).map(|(p, _)| *p) {
            return Ok(Some(p));
        }
        let found = &self.found[..self.found_len];
        if let Some(p) = found
            .iter()
            .find(|(p, k)| !p.is_kcc3() && wanted(k))
            .map(|(p, _)| *p)
        {
            return Ok(Some(p));
        }
        if let Some(j) = self.window[..self.window_len]
            .iter()
            .position(|(p, k)| !p.is_kcc3() && wanted(k))
        {
            self.hits.set(self.hits.get() | (1 << j));
            return Ok(Some(self.window[j].0));
        }
        if deep {
            if self.search {
                return self.search(wanted);
            }
            self.misses.set(self.misses.get() + 1);
        }
        Ok(None)
    }

    /// Whether a KCC-3 lookup that found nothing is pending: a `deep` one (no
    /// hint), on a keyring with KCC-3 keys that leaves the search to the
    /// flow's sweep, which has not ended.
    fn kcc3_pending(&self, deep: bool) -> bool {
        deep && !self.search && !self.kcc3_swept && self.kcc3.is_some()
    }

    /// [`Keyring::find`] over KCC-3's keys; a miss is counted only while one
    /// is pending ([`Keyring::kcc3_pending`]).
    fn kcc3_find(
        &self,
        deep: bool,
        mut wanted: impl FnMut(&[u8; 32]) -> bool,
    ) -> Result<Option<Path>, Error> {
        let Some(keys) = self.kcc3.as_ref() else {
            return Ok(None);
        };
        if let Some(k) = keys.iter().position(&mut wanted) {
            return Ok(Some(kcc3_bank_path(k)));
        }
        let found = &self.found[..self.found_len];
        if let Some(p) = found
            .iter()
            .find(|(p, k)| p.is_kcc3() && wanted(k))
            .map(|(p, _)| *p)
        {
            return Ok(Some(p));
        }
        if let Some(j) = self.window[..self.window_len]
            .iter()
            .position(|(p, k)| p.is_kcc3() && wanted(k))
        {
            self.hits.set(self.hits.get() | (1 << j));
            return Ok(Some(self.window[j].0));
        }
        if deep && self.search {
            return self.kcc3_search(wanted);
        }
        if self.kcc3_pending(deep) {
            self.kcc3_misses.set(self.kcc3_misses.get() + 1);
        }
        Ok(None)
    }

    /// The key that signs an input locked to `spk`, given its redeem script
    /// and hint, or `None` when no key of ours does (never under a script
    /// version consensus does not run, whose spend no key guards:
    /// [`classify`]).
    ///
    /// A pay-to-script-hash redeem is checked against its hash. Then, for
    /// every shape, the keys are the redeem's 32-byte pushes in order and
    /// `position` is the index among them, never assumed zero; the module
    /// notes say which shapes are signed. [`crate::reply`] reads a position
    /// back with the same rule, so a read-back agrees with what was signed
    /// instead of refusing after a person has confirmed.
    ///
    /// # Errors
    ///
    /// `NoRedeemScript` for a pay-to-script-hash input without one, unless
    /// it is a KCC-3 address of ours or one the flow's sweep may yet find;
    /// `RedeemMismatch` when the redeem is not the one the input locks to;
    /// `UnsupportedMultisig` and `RepeatedKey` for a multisig this device
    /// does not sign; `ScriptUnshown` as [`Error::ScriptUnshown`] says;
    /// `KeyMismatch` when the private key derived for a key found among the
    /// public ones is not it; `Wallet` if a derivation fails.
    pub fn resolve(
        &self,
        spk: ScriptPublicKey<'_>,
        redeem: &[u8],
        hint: Option<Path>,
    ) -> Result<Option<Match>, Error> {
        self.resolve_with(spk, redeem, hint, hint.is_none())
    }

    /// [`Keyring::resolve`] with no hint, looking only in the bank and what
    /// the sweep found: for an input whose request gave derivations, none
    /// naming a key of ours. A bundle's wrong paths stop at the bank, as a
    /// KSPT's wrong hint does, rather than going on to the search.
    ///
    /// # Errors
    ///
    /// As [`Keyring::resolve`].
    pub fn resolve_in_bank(
        &self,
        spk: ScriptPublicKey<'_>,
        redeem: &[u8],
    ) -> Result<Option<Match>, Error> {
        self.resolve_with(spk, redeem, None, false)
    }

    /// [`Keyring::resolve`], `deep` saying whether a miss in the bank goes
    /// on past it.
    fn resolve_with(
        &self,
        spk: ScriptPublicKey<'_>,
        redeem: &[u8],
        hint: Option<Path>,
        deep: bool,
    ) -> Result<Option<Match>, Error> {
        match classify(&spk) {
            ScriptClass::PubKey => self.one_key(&spk.script[1..33], hint, deep),
            ScriptClass::ScriptHash => {
                if redeem.is_empty() {
                    // A KCC-3 address known by its hash alone: the device
                    // supplies the script. Not found yet, it is left for the
                    // flow's sweep; anything else with no redeem is refused.
                    let hash = &spk.script[2..34];
                    let wanted = |k: &[u8; 32]| kcc3_script_hash(k)[..] == *hash;
                    return match self.kcc3_match(wanted, hint, deep, true)? {
                        Some(m) => Ok(Some(m)),
                        None if self.kcc3_pending(deep) => Ok(None),
                        None => Err(Error::NoRedeemScript),
                    };
                }
                if !redeem_matches(&spk, redeem) {
                    return Err(Error::RedeemMismatch);
                }
                // A multisig this device does not sign (see the module
                // notes; a non-standard form's limit and keys nothing here
                // reads) is refused, whoever's keys it holds: "Cannot
                // review". The rule is level 1's, which a companion applies.
                match check::multisig(redeem) {
                    Ok(Some(_)) => return self.cosigner(redeem, hint),
                    Ok(None) => {}
                    Err(check::MultisigError::Unsupported { required, keys }) => {
                        return Err(Error::UnsupportedMultisig { required, keys })
                    }
                    Err(check::MultisigError::Repeated { position }) => {
                        return Err(Error::RepeatedKey { position })
                    }
                    Err(check::MultisigError::NotStandard) => return Err(Error::ScriptUnshown),
                }
                // KCC-3's over a KCC-3 key: signed as that key. Over any
                // other key it falls to the cases below, looked up in the
                // first bank alone: the KCC-3 lookup counted its own miss,
                // and the two never sweep for one key.
                let kcc3 = kcc3_key(redeem);
                if let Some(x) = kcc3 {
                    if let Some(m) = self.kcc3_match(|k| k[..] == *x, hint, deep, false)? {
                        return Ok(Some(m));
                    }
                }
                let deep = deep && kcc3.is_none();
                // A Time-Locked Savings card: signed as whichever of its two
                // keys is ours, since its page shows the card.
                if let Ok(card) = Savings::from_program(redeem) {
                    return self.card(&card, hint, deep);
                }
                // Any other redeem: the hint's key if the script holds it,
                // a key in either bank, or, with no hint at all, one past the
                // first bank. A key of ours under a script nothing shows is
                // refused, a bank's before its private key is derived.
                if let Some(key) = self.hinted(hint)? {
                    let x = key.x_only();
                    if keys_of(redeem).any(|k| k == x) {
                        return Err(Error::ScriptUnshown);
                    }
                }
                let in_kcc3 = self
                    .kcc3
                    .as_ref()
                    .is_some_and(|keys| keys.iter().any(|x| keys_of(redeem).any(|k| k == x)));
                if in_kcc3 {
                    return Err(Error::ScriptUnshown);
                }
                match self.find(deep, |x| keys_of(redeem).any(|k| k == x))? {
                    Some(_) => Err(Error::ScriptUnshown),
                    None => Ok(None),
                }
            }
            ScriptClass::PubKeyEcdsa | ScriptClass::NonStandard => Ok(None),
        }
    }

    /// A multisig's key: the one its `45'` hint names, at its position in the
    /// redeem. No bank and no search: neither holds cosigner keys. With a
    /// `44'` hint (a v1.0.5 multisig's key), or for a raw key, which has no
    /// `45'` tree, the input is not ours. The hint is checked before any key
    /// is derived.
    ///
    /// # Errors
    ///
    /// `Wallet` if the derivation fails.
    fn cosigner(&self, redeem: &[u8], hint: Option<Path>) -> Result<Option<Match>, Error> {
        if !matches!(self.wallet.borrow(), Wallet::Hd { .. }) {
            return Ok(None);
        }
        let Some(path @ Path::Multisig { .. }) = hint else {
            return Ok(None);
        };
        let Some(key) = self.hinted(Some(path))? else {
            return Ok(None);
        };
        let x = key.x_only();
        let shape = multisig_shape(redeem).map(|ms| (ms.required, ms.total));
        Ok(keys_of(redeem).position(|k| k == x).map(|p| Match {
            key,
            position: p as u8,
            shape,
            supplied: None,
        }))
    }

    /// The KCC-3 key `wanted` accepts: a `22'` hint's if it is the one, else
    /// as [`Keyring::kcc3_find`] looks. At position zero, with KCC-3's redeem
    /// over it when `supply` (an input that came without one). `None` for a
    /// key it does not hold, and for a wallet with no `22'` tree whatever the
    /// hint. `wanted` compares a key with a redeem's `<P>`, or, for an
    /// address with no redeem, compares the hash of `<P> OP_CHECKSIG` with
    /// the address's hash.
    ///
    /// # Errors
    ///
    /// `KeyMismatch` when the private key derived for a key found among the
    /// public ones is not it; `Wallet` if a derivation fails.
    fn kcc3_match(
        &self,
        mut wanted: impl FnMut(&[u8; 32]) -> bool,
        hint: Option<Path>,
        deep: bool,
        supply: bool,
    ) -> Result<Option<Match>, Error> {
        let wallet = self.wallet.borrow();
        if !wallet.has_kcc3() {
            return Ok(None);
        }
        let matched = |key: SigningKey| {
            let supplied = supply.then(|| kcc3_redeem(&key.x_only()));
            Match {
                key,
                position: 0,
                shape: None,
                supplied,
            }
        };
        if let Some(path @ Path::Kcc3 { .. }) = hint {
            let key = wallet.signing_key(path)?;
            if wanted(&key.x_only()) {
                return Ok(Some(matched(key)));
            }
        }
        let Some(path) = self.kcc3_find(deep, &mut wanted)? else {
            return Ok(None);
        };
        let key = wallet.signing_key(path)?;
        if !wanted(&key.x_only()) {
            return Err(Error::KeyMismatch);
        }
        Ok(Some(matched(key)))
    }

    /// A single-key script: the hint's key if it is this one, else the
    /// bank's, and past it when `deep`.
    fn one_key(&self, x: &[u8], hint: Option<Path>, deep: bool) -> Result<Option<Match>, Error> {
        if let Some(key) = self.hinted(hint)? {
            if key.x_only() == x {
                return Ok(Some(Match {
                    key,
                    position: 0,
                    shape: None,
                    supplied: None,
                }));
            }
        }
        match self.find(deep, |k| k == x)? {
            Some(path) => {
                let key = self.wallet.borrow().signing_key(path)?;
                if key.x_only() != x {
                    return Err(Error::KeyMismatch);
                }
                Ok(Some(Match {
                    key,
                    position: 0,
                    shape: None,
                    supplied: None,
                }))
            }
            None => Ok(None),
        }
    }

    /// A Time-Locked Savings card's key, found as [`Keyring::one_key`] finds
    /// one: the owner's at position 0 or the recovery wallet's at 1 (with no
    /// recovery wallet, the owner's at 0). A card's keys are `44'` keys: a
    /// `45'` or `22'` hint is no hint for a card, and falls back to the bank
    /// as a wrong hint does.
    ///
    /// # Errors
    ///
    /// `KeyMismatch` when the private key derived for a key found among the
    /// public ones is neither of the card's; `Wallet` if a derivation fails.
    fn card(&self, card: &Savings, hint: Option<Path>, deep: bool) -> Result<Option<Match>, Error> {
        let place = |x: &[u8; 32]| {
            if x == card.owner() {
                Some(0)
            } else if card.recovery() == Some(x) {
                Some(1)
            } else {
                None
            }
        };
        let hint = hint.filter(|p| matches!(p, Path::Single { .. }));
        if let Some(key) = self.hinted(hint)? {
            if let Some(position) = place(&key.x_only()) {
                return Ok(Some(Match {
                    key,
                    position,
                    shape: None,
                    supplied: None,
                }));
            }
        }
        match self.find(deep, |k| place(k).is_some())? {
            Some(path) => {
                let key = self.wallet.borrow().signing_key(path)?;
                let position = place(&key.x_only()).ok_or(Error::KeyMismatch)?;
                Ok(Some(Match {
                    key,
                    position,
                    shape: None,
                    supplied: None,
                }))
            }
            None => Ok(None),
        }
    }

    /// The key a hint names, when the wallet can reach it.
    fn hinted(&self, hint: Option<Path>) -> Result<Option<SigningKey>, Error> {
        let Some(path) = hint else {
            return Ok(None);
        };
        match self.wallet.borrow().signing_key(path) {
            Ok(k) => Ok(Some(k)),
            Err(WalletError::NoMultisigTree | WalletError::NoKcc3Tree) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
