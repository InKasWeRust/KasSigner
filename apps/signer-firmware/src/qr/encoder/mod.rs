// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// Minimal no-std, no-alloc QR encoder for versions 1 through 6 at ECC level L.
// This subsystem façade exposes the encoder while focused modules own each stage.

mod bit_writer;
mod modes;
mod ecc;
mod constants;
mod error;
mod matrix;


pub use modes::byte_mode::encode;
#[cfg(not(feature = "qemu"))]
pub use matrix::matrix::QrCode;
#[cfg(not(feature = "qemu"))]
pub use modes::numeric_mode::encode_numeric;

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
#[path = "../unit_tests/encoder_tests.rs"]
pub(crate) mod unit_tests;
