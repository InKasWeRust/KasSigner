// KasSee Web — PSKT / PSKB protocol subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Organized PSKT/PSKB support. Wire handling, review, KSPT bridging,
//! consensus finalization, and signature-script construction are separate
//! modules behind the existing crate-local `pskt::*` surface.

mod anti_klepto;
mod consensus;
mod error;
pub(crate) mod exact_json;
mod kspt_bridge;
mod model;
pub mod pskb;
mod review;
pub(crate) mod scripts;
pub(crate) mod wire;

pub(crate) use anti_klepto::{
    compact_kspt_sighash_wire, validate_anti_klepto_transaction_wire,
    validate_host_commitment_wire, verify_host_transcript_wire,
};
pub(crate) use consensus::finalize_to_consensus;
pub use kspt_bridge::{merge_signed_kspt_into_pskb, relay_pskb_as_kspt_hex_for_network};
pub use model::{InputSummary, OutputSummary, PartialSigInfo, PsktFormat, PsktSummary};
pub use review::parse_summary;
pub use scripts::push_redeem_script;
pub use wire::{detect_format_hex, set_tx_lane};

#[cfg(test)]
mod unit_tests;
