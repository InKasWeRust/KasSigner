//! Cryptographic primitives used by the offline signer.

pub mod adaptor;
pub mod anti_klepto;
pub mod container_framing;
pub mod credential;
pub mod device_bound_storage;
pub mod ecies;
pub mod legacy_pbkdf2;
pub mod message;
pub mod password_kdf;
pub mod schnorr;

#[cfg(test)]
#[path = "unit_tests/external_input_hardening.rs"]
mod external_input_hardening_tests;
