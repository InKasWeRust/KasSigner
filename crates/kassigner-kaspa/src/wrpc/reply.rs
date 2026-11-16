// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What a reply holds, but the coins: text a node wrote, the network, the
//! server's info and the fee estimate with its buckets.

use super::*;

// ── What a reply holds ──────────────────────────────────────────────────────

/// Text a node wrote: an error's message, a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Text<'a> {
    /// What upstream's `Display` puts before an error's own text.
    pub(super) lead: &'static str,
    pub(super) body: &'a str,
    /// `body` holds JSON escapes, undone as it is read.
    pub(super) escaped: bool,
}

impl<'a> Text<'a> {
    /// Its characters.
    pub fn chars(&self) -> TextChars<'a> {
        TextChars {
            lead: self.lead.chars(),
            body: Unescaped::new(self.body),
            escaped: self.escaped,
            plain: self.body.chars(),
        }
    }
}

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        self.chars().try_for_each(|c| f.write_char(c))
    }
}

/// [`Text`]'s characters.
#[derive(Clone, Debug)]
pub struct TextChars<'a> {
    lead: core::str::Chars<'static>,
    body: Unescaped<'a>,
    escaped: bool,
    plain: core::str::Chars<'a>,
}

impl Iterator for TextChars<'_> {
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(c) = self.lead.next() {
            return Some(c);
        }
        if self.escaped {
            self.body.next()
        } else {
            self.plain.next()
        }
    }
}

/// A network as a node names it: upstream's `NetworkId`, a type and, on a
/// testnet, a number (`testnet-10`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkId {
    /// The network's type, also its addresses' prefix.
    pub network_type: Prefix,
    pub suffix: Option<u32>,
}

impl NetworkId {
    /// From its name as upstream's `Display` writes it (`mainnet`,
    /// `testnet-10`). A number past `u32` is refused, as upstream does.
    pub fn parse(name: &[u8]) -> Option<NetworkId> {
        let (kind, suffix) = match name.iter().position(|&c| c == b'-') {
            Some(k) => (&name[..k], Some(&name[k + 1..])),
            None => (name, None),
        };
        let network_type = match kind {
            b"mainnet" => Prefix::Mainnet,
            b"testnet" => Prefix::Testnet,
            b"simnet" => Prefix::Simnet,
            b"devnet" => Prefix::Devnet,
            _ => return None,
        };
        let suffix = match suffix {
            None => None,
            Some(digits) => {
                if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                    return None;
                }
                Some(core::str::from_utf8(digits).ok()?.parse().ok()?)
            }
        };
        Some(NetworkId {
            network_type,
            suffix,
        })
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.network_type {
            Prefix::Mainnet => "mainnet",
            Prefix::Testnet => "testnet",
            Prefix::Simnet => "simnet",
            Prefix::Devnet => "devnet",
        };
        match self.suffix {
            Some(n) => write!(f, "{name}-{n}"),
            None => f.write_str(name),
        }
    }
}

/// The reply to `getServerInfo`: upstream's `GetServerInfoResponse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerInfo<'a> {
    /// [`RPC_API_VERSION`] on a node this module was written for.
    pub rpc_api_version: u16,
    pub rpc_api_revision: u16,
    /// The node's version, such as `2.1.0`.
    pub server_version: Text<'a>,
    /// The network it follows: an app's addresses are of its type.
    pub network: NetworkId,
    /// Whether it keeps the UTXO index `getUtxosByAddresses` needs
    /// (`--utxoindex`).
    pub has_utxo_index: bool,
    /// Whether it has caught up; until then its coins may be stale.
    pub is_synced: bool,
    pub virtual_daa_score: u64,
}

impl<'a> ServerInfo<'a> {
    pub(super) fn borsh(r: &mut Reader<'a>) -> Result<ServerInfo<'a>, At> {
        let _version = r.u16()?;
        let rpc_api_version = r.u16()?;
        let rpc_api_revision = r.u16()?;
        let server_version = r.string()?;
        // `NetworkType`'s declaration order, not `Prefix`'s.
        let at = r.at();
        let network_type = match r.u8()? {
            0 => Prefix::Mainnet,
            1 => Prefix::Testnet,
            2 => Prefix::Devnet,
            3 => Prefix::Simnet,
            _ => return Err(at),
        };
        let suffix = if r.some()? { Some(r.u32()?) } else { None };
        Ok(ServerInfo {
            rpc_api_version,
            rpc_api_revision,
            server_version: Text {
                lead: "",
                body: server_version,
                escaped: false,
            },
            network: NetworkId {
                network_type,
                suffix,
            },
            has_utxo_index: r.bool()?,
            is_synced: r.bool()?,
            virtual_daa_score: r.u64()?,
        })
    }

    pub(super) fn json(m: &'a [u8], span: Span) -> Result<ServerInfo<'a>, At> {
        let field = |key| json::required(m, span, key);
        let network = field("networkId")?;
        Ok(ServerInfo {
            rpc_api_version: json::u16_at(m, field("rpcApiVersion")?)?,
            rpc_api_revision: json::u16_at(m, field("rpcApiRevision")?)?,
            server_version: Text {
                lead: "",
                body: json::string_body(m, field("serverVersion")?)?,
                escaped: true,
            },
            network: NetworkId::parse(json::plain(m, network)?).ok_or(network.0)?,
            has_utxo_index: json::bool_at(m, field("hasUtxoIndex")?)?,
            is_synced: json::bool_at(m, field("isSynced")?)?,
            virtual_daa_score: json::u64_at(m, field("virtualDaaScore")?)?,
        })
    }
}

/// A fee rate and how soon the node expects it confirmed: upstream's
/// `RpcFeerateBucket`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Bucket {
    /// Sompi a gram of mass.
    pub feerate: f64,
    pub estimated_seconds: f64,
}

impl Bucket {
    /// Whole sompi a gram, rounded up, at least one. A request still pays
    /// at least the minimum relay fee.
    pub fn sompi_per_gram(&self) -> u64 {
        if self.feerate.is_nan() || self.feerate <= 1.0 {
            return 1;
        }
        if self.feerate >= u64::MAX as f64 {
            return u64::MAX;
        }
        let whole = self.feerate as u64;
        if (whole as f64) < self.feerate {
            whole + 1
        } else {
            whole
        }
    }

    fn borsh(r: &mut Reader<'_>) -> Result<Bucket, At> {
        Ok(Bucket {
            feerate: r.f64()?,
            estimated_seconds: r.f64()?,
        })
    }

    fn json(m: &[u8], span: Span) -> Result<Bucket, At> {
        Ok(Bucket {
            feerate: json::f64_at(m, json::required(m, span, "feerate")?)?,
            estimated_seconds: json::f64_at(m, json::required(m, span, "estimatedSeconds")?)?,
        })
    }
}

/// The reply to `getFeeEstimate`: upstream's `RpcFeeEstimate`. Priority
/// is fastest, then normal, then low, each list fastest first.
#[derive(Clone, Debug)]
pub struct FeeEstimate<'a> {
    pub priority: Bucket,
    pub normal: Buckets<'a>,
    pub low: Buckets<'a>,
}

impl<'a> FeeEstimate<'a> {
    pub(super) fn borsh(r: &mut Reader<'a>) -> Result<FeeEstimate<'a>, At> {
        let _version = r.u16()?;
        let mut e = r.payload()?;
        let _version = e.u16()?;
        let priority = Bucket::borsh(&mut e)?;
        let normal = Buckets::borsh(&mut e)?;
        let low = Buckets::borsh(&mut e)?;
        Ok(FeeEstimate {
            priority,
            normal,
            low,
        })
    }

    pub(super) fn json(m: &'a [u8], span: Span) -> Result<FeeEstimate<'a>, At> {
        let estimate = json::required(m, span, "estimate")?;
        let field = |key| json::required(m, estimate, key);
        Ok(FeeEstimate {
            priority: Bucket::json(m, field("priorityBucket")?)?,
            normal: Buckets::json(m, field("normalBuckets")?)?,
            low: Buckets::json(m, field("lowBuckets")?)?,
        })
    }
}

/// [`Bucket`]s, read as iterated; all were checked with the reply.
#[derive(Clone, Debug)]
pub struct Buckets<'a> {
    message: &'a [u8],
    encoding: Encoding,
    at: usize,
    left: usize,
}

impl<'a> Buckets<'a> {
    /// A `Vec` of buckets: a `u32` count, then each one's two `f64`s.
    fn borsh(r: &mut Reader<'a>) -> Result<Buckets<'a>, At> {
        let at = r.at();
        let left = usize::try_from(r.u32()?).map_err(|_| at)?;
        let start = r.at();
        r.bytes(left.checked_mul(16).ok_or(at)?)?;
        Buckets {
            message: r.message(),
            encoding: Encoding::Borsh,
            at: start,
            left,
        }
        .checked()
    }

    fn json(m: &'a [u8], span: Span) -> Result<Buckets<'a>, At> {
        Buckets {
            message: m,
            encoding: Encoding::Json,
            at: json::ws(m, span.0 + 1),
            left: json::elements(m, span)?.count(),
        }
        .checked()
    }

    /// Every bucket read once: none NaN or incomplete.
    fn checked(self) -> Result<Buckets<'a>, At> {
        let mut all = self.clone();
        while let Some(b) = all.bucket() {
            b?;
        }
        Ok(self)
    }

    fn bucket(&mut self) -> Option<Result<Bucket, At>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let m = self.message;
        Some(match self.encoding {
            Encoding::Borsh => {
                let mut r = Reader::new(m, self.at, m.len());
                let b = Bucket::borsh(&mut r);
                self.at = r.at();
                b
            }
            Encoding::Json => json::value_end(m, self.at).and_then(|end| {
                let b = Bucket::json(m, (self.at, end));
                self.at = next_element(m, end);
                b
            }),
        })
    }
}

impl Iterator for Buckets<'_> {
    type Item = Bucket;

    fn next(&mut self) -> Option<Bucket> {
        self.bucket()?.ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Buckets<'_> {}
