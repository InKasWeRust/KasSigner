//! Dual-key ECDH stealth-address cryptography with view tags.

mod announcement;
mod derivation;
mod keys;
mod metadata;
mod payment;

pub use announcement::announcement_address;
pub use keys::x_only_pub;
pub use metadata::{decode_stealth_meta, derive_stealth_meta, encode_stealth_meta};
pub use payment::{generate_stealth_payment, StealthPayment};

pub(crate) mod scanner;

#[cfg(test)]
mod unit_tests;
