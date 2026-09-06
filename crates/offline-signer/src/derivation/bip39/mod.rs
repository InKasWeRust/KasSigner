// BIP39 mnemonic generation, validation, lookup, and seed derivation.

mod encoding;
mod seed;
mod types;
mod words;

pub use encoding::{
    mnemonic_from_entropy_12, mnemonic_from_entropy_24, validate_mnemonic_12, validate_mnemonic_24,
};
pub use seed::{
    seed_from_mnemonic_12, seed_from_mnemonic_12_with_checkpoint, seed_from_mnemonic_24,
    seed_from_mnemonic_24_with_checkpoint, SeedDerivation,
};
pub use types::{Bip39Error, Mnemonic12, Mnemonic24, Seed};
pub use words::{index_to_word, word_to_index};

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "../unit_tests/bip39_tests.rs"]
pub mod unit_tests;
