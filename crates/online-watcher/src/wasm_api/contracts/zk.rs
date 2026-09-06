// KasSee Web — merkle-whitelist + commit-reveal WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for hash/proof covenants: merkle-whitelist and commit-reveal.

mod commit_reveal;
mod crowdfund;
mod hashes;
mod merkle;

pub use commit_reveal::*;
pub use crowdfund::*;
pub use hashes::*;
pub use merkle::*;

#[cfg(test)]
mod unit_tests;
