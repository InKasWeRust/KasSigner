// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! QR encoding and decoding, ISO/IEC 18004. Nothing here was designed by
//! us; the encoder is our implementation of the standard.
//!
//! The one way into the vendored decoder, so that everything a decode works
//! in, the binarizer's accumulator included, is the [`Scratch`] a caller
//! lends a [`Decoder`]: two decodes in two scratches share nothing.
//!
//! The crate returns a module matrix; drawing it is the firmware's.
//!
//! A SeedQR is the whole wallet and goes through the same encoder, so an
//! encode's buffers are zeroized when it returns and a [`encode::QrMatrix`]
//! wipes its modules on drop. They are plain arrays: a copy the compiler
//! spilled elsewhere is not wiped, so this shortens the window rather than
//! closing it.
//!
//! The encoder stops at version 9, 53 by 53, the last whose byte-mode
//! length field is eight bits ([`capacity::MAX_VERSION`]); the standard goes
//! to 40. A matrix is two 352-byte bitmaps, its modules and which of them
//! are function patterns; at version 40 each would be about 3.9 KB.

#![no_std]
#![forbid(unsafe_code)]

pub mod capacity;
pub mod decode;
pub mod encode;

pub use capacity::{
    byte_capacity, numeric_capacity, select_version, select_version_numeric, MAX_VERSION,
};
pub use decode::{DecodeError, Decoded, Decoder, Scratch, MAX_PAYLOAD_SIZE, MAX_SIDE};
pub use encode::{encode, encode_at, encode_numeric, QrError, QrMatrix};
