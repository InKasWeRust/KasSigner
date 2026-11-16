// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A node's message read: its kind, its id and call, a call's result or the
//! node's refusal, and the accessors that read a response whole.

use super::*;

// ── Reading ─────────────────────────────────────────────────────────────────

/// What a node's message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The answer to a request.
    Reply,
    /// The node's refusal of a request ([`Message::error`]).
    Error,
    /// Sent unasked to a subscriber: no id.
    Notification,
}

/// A node's message, its frame read and checked.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    /// The id of the request it answers; none on a notification.
    pub id: Option<u64>,
    pub kind: Kind,
    /// The call it answers or notifies, if named and one of the four.
    /// Borsh names none for a call the node could not make; the id tells.
    pub call: Option<Call>,
    encoding: Encoding,
    message: &'a [u8],
    /// The response or error: Borsh's payload, JSON's `params` or `error`.
    body: Span,
}

/// Read a node's `message` in `encoding`: its frame, and any error.
///
/// # Errors
///
/// `Malformed { at }` for a message that is not one a node writes.
pub fn read(message: &[u8], encoding: Encoding) -> Result<Message<'_>, WrpcError> {
    match encoding {
        Encoding::Borsh => read_borsh(message),
        Encoding::Json => read_json(message),
    }
    .map_err(malformed)
}

fn read_borsh(m: &[u8]) -> Result<Message<'_>, At> {
    let mut r = Reader::new(m, 0, m.len());
    let id = if r.some()? { Some(r.u64()?) } else { None };
    let at = r.at();
    let frame = r.u8()?;
    let at_op = r.at();
    let op = if r.some()? { Some(r.u8()?) } else { None };
    let (kind, body) = match frame {
        // A call made: its `Result` as borsh writes it
        // (`Method::call_with_borsh`): `1` and the response's payload, or
        // `0` and the node's refusal. Nothing after either.
        0 => {
            if id.is_none() || op.is_none() {
                return Err(at_op);
            }
            let tag = r.at();
            let returned = match r.u8()? {
                1 => {
                    let p = r.payload()?;
                    (Kind::Reply, (p.at(), p.end()))
                }
                0 => {
                    let start = r.at();
                    server_error(&mut r)?;
                    (Kind::Error, (start, r.end()))
                }
                _ => return Err(tag),
            };
            r.done()?;
            returned
        }
        // A call the node could not make (an op it does not serve, a
        // request it cannot read): the error alone.
        1 => {
            if id.is_none() {
                return Err(at_op);
            }
            let start = r.at();
            server_error(&mut r)?;
            r.done()?;
            (Kind::Error, (start, r.end()))
        }
        0xff => {
            if op.is_none() {
                return Err(at_op);
            }
            (Kind::Notification, (r.at(), r.end()))
        }
        _ => return Err(at),
    };
    Ok(Message {
        id,
        kind,
        call: op.and_then(Call::from_op),
        encoding: Encoding::Borsh,
        message: m,
        body,
    })
}

fn read_json(m: &[u8]) -> Result<Message<'_>, At> {
    let doc = json::document(m)?;
    let id = json::optional(m, doc, "id")?
        .map(|v| json::u64_at(m, v))
        .transpose()?;
    let call = match json::optional(m, doc, "method")? {
        Some(v) => Call::from_method(json::plain(m, v)?),
        None => None,
    };
    let params = json::optional(m, doc, "params")?;
    let (kind, body) = if let Some(error) = json::optional(m, doc, "error")? {
        // `JsonServerError`: a code and a message, both there.
        json::u64_at(m, json::required(m, error, "code")?)?;
        json::string_body(m, json::required(m, error, "message")?)?;
        (Kind::Error, error)
    } else if id.is_some() {
        (Kind::Reply, params.ok_or(doc.0)?)
    } else {
        (Kind::Notification, params.ok_or(doc.0)?)
    };
    Ok(Message {
        id,
        kind,
        call,
        encoding: Encoding::Json,
        message: m,
        body,
    })
}

/// workflow-rpc's `ServerError` as borsh writes it (an index, then text
/// where the variant has one), read to its end; its message as upstream's
/// `Display` writes it.
fn server_error<'a>(r: &mut Reader<'a>) -> Result<Text<'a>, At> {
    let at = r.at();
    let (lead, text) = match r.u8()? {
        0 => ("connection is closed", ""),
        1 => ("RPC call timed out", ""),
        2 => ("no data", ""),
        3 => ("RPC method not found", ""),
        4 => ("resource lock error", ""),
        5 => ("not a borsh request", ""),
        6 => ("not a serde request", ""),
        7 => ("request serialization error", ""),
        8 => ("request deserialization error", ""),
        9 => ("response serialization error", ""),
        // Upstream's `Display` for these two leaves their text out.
        10 => {
            r.string()?;
            ("request deserialization error", "")
        }
        11 => {
            r.string()?;
            ("response deserialization error", "")
        }
        12 => {
            r.vec()?;
            ("data", "")
        }
        13 => ("", r.string()?),
        14 => ("WebSocket -> ", r.string()?),
        15 => ("Receiver channel", ""),
        16 => ("Receiver channel send", ""),
        _ => return Err(at),
    };
    Ok(Text {
        lead,
        body: text,
        escaped: false,
    })
}

impl<'a> Message<'a> {
    /// The node's error, on [`Kind::Error`]: why it refused.
    pub fn error(&self) -> Option<Text<'a>> {
        if self.kind != Kind::Error {
            return None;
        }
        let m = self.message;
        match self.encoding {
            Encoding::Borsh => server_error(&mut Reader::new(m, self.body.0, self.body.1)).ok(),
            Encoding::Json => {
                let message = json::required(m, self.body, "message").ok()?;
                Some(Text {
                    lead: "",
                    body: json::string_body(m, message).ok()?,
                    escaped: true,
                })
            }
        }
    }

    /// This message as the reply to `call`.
    fn reply_to(&self, call: Call) -> Result<(), WrpcError> {
        match self.kind {
            Kind::Error => Err(WrpcError::Refused),
            Kind::Reply if self.call == Some(call) => Ok(()),
            _ => Err(WrpcError::OtherCall),
        }
    }

    fn borsh(&self) -> Reader<'a> {
        Reader::new(self.message, self.body.0, self.body.1)
    }

    /// The reply to `getServerInfo`.
    ///
    /// # Errors
    ///
    /// `Refused` on the node's error, `OtherCall` on another call's
    /// reply, `Malformed { at }`.
    pub fn server_info(&self) -> Result<ServerInfo<'a>, WrpcError> {
        self.reply_to(Call::GetServerInfo)?;
        match self.encoding {
            Encoding::Borsh => ServerInfo::borsh(&mut self.borsh()),
            Encoding::Json => ServerInfo::json(self.message, self.body),
        }
        .map_err(malformed)
    }

    /// The reply to `getFeeEstimate`, every bucket checked.
    ///
    /// # Errors
    ///
    /// As [`Message::server_info`].
    pub fn fee_estimate(&self) -> Result<FeeEstimate<'a>, WrpcError> {
        self.reply_to(Call::GetFeeEstimate)?;
        match self.encoding {
            Encoding::Borsh => FeeEstimate::borsh(&mut self.borsh()),
            Encoding::Json => FeeEstimate::json(self.message, self.body),
        }
        .map_err(malformed)
    }

    /// The reply to `getUtxosByAddresses`, every entry checked.
    ///
    /// # Errors
    ///
    /// As [`Message::server_info`].
    pub fn utxos(&self) -> Result<Utxos<'a>, WrpcError> {
        self.reply_to(Call::GetUtxosByAddresses)?;
        match self.encoding {
            Encoding::Borsh => Utxos::borsh(&mut self.borsh()),
            Encoding::Json => Utxos::json(self.message, self.body),
        }
        .and_then(Utxos::checked)
        .map_err(malformed)
    }

    /// The reply to `submitTransaction`: the accepted transaction's id.
    ///
    /// # Errors
    ///
    /// As [`Message::server_info`]; on `Refused`, [`Message::error`] says
    /// why.
    pub fn transaction_id(&self) -> Result<TransactionId, WrpcError> {
        self.reply_to(Call::SubmitTransaction)?;
        match self.encoding {
            Encoding::Borsh => {
                let mut r = self.borsh();
                r.u16().and_then(|_version| r.array::<32>())
            }
            Encoding::Json => json::required(self.message, self.body, "transactionId")
                .and_then(|id| hash(self.message, id)),
        }
        .map_err(malformed)
    }
}

/// A hash serde wrote: 64 hex digits.
pub(super) fn hash(m: &[u8], span: Span) -> Result<[u8; 32], At> {
    let mut out = [0u8; 32];
    json::unhex(json::plain(m, span)?, span.0 + 1, &mut out)?;
    Ok(out)
}

/// After a JSON array element ending at `end`: the next one, or the
/// bracket.
pub(super) fn next_element(m: &[u8], end: usize) -> usize {
    let after = json::ws(m, end);
    if m.get(after) == Some(&b',') {
        json::ws(m, after + 1)
    } else {
        after
    }
}
