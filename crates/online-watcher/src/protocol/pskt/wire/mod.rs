// KasSee Web — PSKT / PSKB wire handling
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

mod envelope;
mod json;
mod json_fields;
mod mutation;

pub use envelope::detect_format_hex;
pub(crate) use envelope::{
    decode_root, decode_root_for_review, encode_root, first_pskt_from_pskb_mut, pskt_from_root,
    pskt_from_root_for_review, pskt_from_root_mut,
};
#[cfg(test)]
pub(crate) use envelope::{format_wire_error, ErrorStyle};
#[cfg(test)]
pub(crate) use mutation::inject_tx_payload;
pub use mutation::set_tx_lane;

pub(crate) use json_fields::decode_subnetwork_id;
