//! Narrow WASM façade for watcher-only KIP-20 tagged and split vault planning.

mod genesis;
mod spend;
mod split;
mod tagged;

pub use split::{split_vault_genesis_pskb, split_vault_spend_pskb};
pub use tagged::{tagged_vault_genesis_pskb, tagged_vault_spend_pskb};

#[cfg(test)]
mod unit_tests;
