//! Browser-neutral covenant creation/application services.
//!
//! These modules own input validation, salts, script construction, P2SH address
//! derivation and response serialization. Browser bindings only translate errors.

pub(crate) mod additive;
pub(crate) mod allowance;
pub(crate) mod dms;
pub(crate) mod escrow;
pub(crate) mod payjoin;
pub(crate) mod private_swap;
pub(crate) mod savings;
pub(crate) mod spending_limit;
