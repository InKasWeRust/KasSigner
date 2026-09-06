// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

mod merger;
mod parser_compact;
mod parser_transaction;
mod relay;
#[cfg(test)]
mod signatures;

pub use merger::merge_signed_kspt_into_pskb;
#[cfg(test)]
pub(crate) use parser_compact::parse_compact_kspt_signatures;
pub(crate) use parser_compact::xonly_at_position;
pub(crate) use parser_transaction::parse_compact_kspt_transaction;
#[cfg(test)]
pub(crate) use parser_transaction::require_compact_trailer_progress;
#[cfg(test)]
pub(crate) use parser_transaction::{decode_error_for_test, KasSeeSink};
#[cfg(test)]
pub(crate) use relay::first_outpoint;
pub use relay::relay_pskb_as_kspt_hex_for_network;
#[cfg(test)]
pub(crate) use signatures::{
    collect_finalized_covenant_signature, collect_signatures, KsptEncodingMode,
};
