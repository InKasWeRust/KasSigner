//! SeedQR codec facade.
//!
//! Parsing/encoding lives in signer-firmware-core so firmware, host property tests and
//! fuzz targets exercise exactly one implementation.

pub use signer_firmware_core::backup::seed_qr::{
    decode_compact_seedqr, decode_seedqr, encode_compact_seedqr, encode_seedqr,
};
