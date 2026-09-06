// KasSee Web — Oracle (Model B) covenant WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the Oracle (Model B) covenant: genesis, heartbeat,
//! publish and consume flows.

mod genesis;
mod publish;

pub use genesis::*;
pub use publish::*;

#[cfg(test)]
mod unit_tests;
