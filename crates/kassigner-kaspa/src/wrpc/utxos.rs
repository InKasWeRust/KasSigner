// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The coins a reply holds: the addresses, the bytes, and each UTXO entry,
//! read whole before they are iterated.

use super::*;

/// An address a node wrote: upstream's `RpcAddress`, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub prefix: Prefix,
    pub version: Version,
    pub(super) payload: [u8; 33],
}

impl Address {
    /// What it pays to: a public key, or a script's hash.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.version.payload_len()]
    }

    /// As text, `kaspa:…`, into `out`: its length.
    ///
    /// # Errors
    ///
    /// `BufferTooSmall` under [`MAX_ADDRESS_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, AddressError> {
        address::encode(self.prefix, self.version, self.payload(), out)
    }

    fn borsh(r: &mut Reader<'_>) -> Result<Address, At> {
        let at = r.at();
        let prefix = prefix_of_byte(r.u8()?).ok_or(at)?;
        let version = Version::from_u8(r.u8()?).ok_or(at + 1)?;
        let at = r.at();
        let bytes = r.vec()?;
        // `Address::try_new`: the payload's length is its version's.
        if bytes.len() != version.payload_len() {
            return Err(at);
        }
        let mut payload = [0u8; 33];
        payload[..bytes.len()].copy_from_slice(bytes);
        Ok(Address {
            prefix,
            version,
            payload,
        })
    }

    fn json(m: &[u8], span: Span) -> Result<Address, At> {
        let text = json::plain(m, span)?;
        let mut payload = [0u8; 33];
        let (prefix, version, _) = address::decode(text, &mut payload).map_err(|_| span.0)?;
        Ok(Address {
            prefix,
            version,
            payload,
        })
    }
}

/// Bytes a node wrote, raw in Borsh and hex in JSON, read as iterated or
/// copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes<'a> {
    src: &'a [u8],
    hex: bool,
}

impl<'a> Bytes<'a> {
    pub fn len(&self) -> usize {
        if self.hex {
            self.src.len() / 2
        } else {
            self.src.len()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.src.is_empty()
    }

    /// Each byte.
    pub fn iter(&self) -> impl Iterator<Item = u8> + 'a {
        let (src, hex) = (self.src, self.hex);
        (0..self.len()).map(move |k| {
            let at = |i: usize| src.get(i).copied().unwrap_or(0);
            if hex {
                let digit = |c: u8| crate::hex::nibble(c).unwrap_or(0);
                digit(at(2 * k)) << 4 | digit(at(2 * k + 1))
            } else {
                at(k)
            }
        })
    }

    /// Into `out`, which must hold [`Bytes::len`]: the length, or none.
    pub fn copy_to(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.len();
        for (slot, b) in out.get_mut(..n)?.iter_mut().zip(self.iter()) {
            *slot = b;
        }
        Some(n)
    }
}

/// A coin at an address: upstream's `RpcUtxosByAddressesEntry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utxo<'a> {
    /// The address that holds it; a node may leave it out.
    pub address: Option<Address>,
    pub outpoint: Outpoint,
    /// Sompi.
    pub amount: u64,
    pub script_version: u16,
    /// The locking script.
    pub script: Bytes<'a>,
    /// When it was accepted, in DAA score.
    pub block_daa_score: u64,
    /// A block reward, which must mature before it is spent.
    pub is_coinbase: bool,
    /// The covenant it is bound to; none from a node before the covenant
    /// hardfork.
    pub covenant_id: Option<[u8; 32]>,
}

impl<'a> Utxo<'a> {
    fn borsh(r: &mut Reader<'a>) -> Result<Utxo<'a>, At> {
        let mut e = r.payload()?;
        let _version = e.u8()?;
        let address = if e.some()? {
            Some(Address::borsh(&mut e)?)
        } else {
            None
        };
        let mut o = e.payload()?;
        let _version = o.u8()?;
        let outpoint = Outpoint {
            transaction_id: o.array()?,
            index: o.u32()?,
        };
        let mut u = e.payload()?;
        let version = u.u8()?;
        let amount = u.u64()?;
        let script_version = u.u16()?;
        let script = u.vec()?;
        let block_daa_score = u.u64()?;
        let is_coinbase = u.bool()?;
        // Version 2, the covenant hardfork's, appends it.
        let covenant_id = if version > 1 && u.some()? {
            Some(u.array()?)
        } else {
            None
        };
        Ok(Utxo {
            address,
            outpoint,
            amount,
            script_version,
            script: Bytes {
                src: script,
                hex: false,
            },
            block_daa_score,
            is_coinbase,
            covenant_id,
        })
    }

    fn json(m: &'a [u8], span: Span) -> Result<Utxo<'a>, At> {
        let address = json::optional(m, span, "address")?
            .map(|a| Address::json(m, a))
            .transpose()?;
        let o = json::required(m, span, "outpoint")?;
        let outpoint = Outpoint {
            transaction_id: hash(m, json::required(m, o, "transactionId")?)?,
            index: json::u32_at(m, json::required(m, o, "index")?)?,
        };
        let u = json::required(m, span, "utxoEntry")?;
        let field = |key| json::required(m, u, key);
        // `ScriptPublicKey` as serde writes it: one hex string, version
        // first, big-endian.
        let spk = field("scriptPublicKey")?;
        let text = json::plain(m, spk)?;
        if text.len() < 4 || text.len() % 2 != 0 {
            return Err(spk.0);
        }
        let mut version = [0u8; 2];
        json::unhex(&text[..4], spk.0 + 1, &mut version)?;
        if let Some(k) = text[4..].iter().position(|c| !c.is_ascii_hexdigit()) {
            return Err(spk.0 + 5 + k);
        }
        let covenant_id = json::optional(m, u, "covenantId")?
            .map(|c| hash(m, c))
            .transpose()?;
        Ok(Utxo {
            address,
            outpoint,
            amount: json::u64_at(m, field("amount")?)?,
            script_version: u16::from_be_bytes(version),
            script: Bytes {
                src: &text[4..],
                hex: true,
            },
            block_daa_score: json::u64_at(m, field("blockDaaScore")?)?,
            is_coinbase: json::bool_at(m, field("isCoinbase")?)?,
            covenant_id,
        })
    }
}

/// A `getUtxosByAddresses` reply's coins, read as iterated; all were
/// checked with the reply.
#[derive(Clone, Debug)]
pub struct Utxos<'a> {
    message: &'a [u8],
    encoding: Encoding,
    at: usize,
    end: usize,
    left: usize,
}

impl<'a> Utxos<'a> {
    /// `GetUtxosByAddressesResponse`: its version, then a payload of a
    /// `u32` count and the entries, each in its own payload.
    pub(super) fn borsh(r: &mut Reader<'a>) -> Result<Utxos<'a>, At> {
        let _version = r.u16()?;
        let mut list = r.payload()?;
        let at = list.at();
        let left = usize::try_from(list.u32()?).map_err(|_| at)?;
        Ok(Utxos {
            message: list.message(),
            encoding: Encoding::Borsh,
            at: list.at(),
            end: list.end(),
            left,
        })
    }

    pub(super) fn json(m: &'a [u8], span: Span) -> Result<Utxos<'a>, At> {
        let entries = json::required(m, span, "entries")?;
        Ok(Utxos {
            message: m,
            encoding: Encoding::Json,
            at: json::ws(m, entries.0 + 1),
            end: entries.1,
            left: json::elements(m, entries)?.count(),
        })
    }

    /// Every entry read once.
    pub(super) fn checked(self) -> Result<Utxos<'a>, At> {
        let mut all = self.clone();
        while let Some(u) = all.entry() {
            u?;
        }
        Ok(self)
    }

    fn entry(&mut self) -> Option<Result<Utxo<'a>, At>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let m = self.message;
        Some(match self.encoding {
            Encoding::Borsh => {
                let mut r = Reader::new(m, self.at, self.end);
                let u = Utxo::borsh(&mut r);
                self.at = r.at();
                u
            }
            Encoding::Json => json::value_end(m, self.at).and_then(|end| {
                let u = Utxo::json(m, (self.at, end));
                self.at = next_element(m, end);
                u
            }),
        })
    }
}

impl<'a> Iterator for Utxos<'a> {
    type Item = Utxo<'a>;

    fn next(&mut self) -> Option<Utxo<'a>> {
        self.entry()?.ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Utxos<'_> {}
