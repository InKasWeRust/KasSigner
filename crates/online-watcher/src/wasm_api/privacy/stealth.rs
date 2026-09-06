// KasSee Web — stealth-address WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for stealth addresses: payment generation,
//! announcement scanning, and spend construction.

mod meta;
mod payment;
mod spend;

pub use meta::*;
pub use payment::*;
pub use spend::*;

#[cfg(test)]
mod unit_tests;
