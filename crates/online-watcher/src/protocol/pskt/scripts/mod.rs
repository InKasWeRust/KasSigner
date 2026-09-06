// KasSee Web — organized PSKT subsystem
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

mod common;
mod contracts;
mod multisig;
mod p2pk;
mod router;

pub(crate) use common::push_data_sigscript;
pub use common::push_redeem_script;
pub(crate) use common::{first_schnorr_signature, push_data_item, push_int_sigscript};
pub(crate) use contracts::*;
pub(crate) use multisig::*;
pub(crate) use p2pk::*;
pub(crate) use router::{build_signature_script, ScriptBuildOptions};

#[cfg(test)]
mod unit_tests;
