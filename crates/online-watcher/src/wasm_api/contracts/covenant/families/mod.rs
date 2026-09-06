//! Covenant-family WASM adapters grouped behind the covenant façade.

#[cfg(test)]
use super::sweep;
use super::{logging, wasm_bindgen, JsValue};

mod additive;
mod allowance;
mod dms;
mod escrow;
mod oracle_v1;
mod payjoin;
mod private_swap;
mod savings;
mod spending_limit;

pub use additive::*;
pub use allowance::*;
pub use dms::*;
pub use escrow::*;
pub use oracle_v1::*;
pub use payjoin::*;
pub use private_swap::*;
pub use savings::*;
pub use spending_limit::*;

#[cfg(test)]
mod unit_tests;
