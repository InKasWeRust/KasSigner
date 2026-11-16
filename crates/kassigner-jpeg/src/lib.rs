// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! JPEG and EXIF as their specifications define them: ITU-T T.81, JFIF,
//! EXIF 2.32 and TIFF 6.0. Level 0: nothing here is ours.
//!
//! - [`segment`]: marker segments, dimensions, the EXIF block and its
//!   replacement.
//! - [`scan`]: a baseline scan decoded to quantized coefficients and written
//!   back with any the caller changed. No pixels.
//! - [`exif`]: TIFF entries read and written, either byte order.
//!
//! Hiding a payload is the level above's design. No allocator, no `unsafe`:
//! every output goes to a caller's buffer, and a frame's Huffman tables to
//! the [`scan::Tables`] it passes to [`scan::parse`].
//!
//! Anything but baseline sequential Huffman in one interleaved scan is
//! [`Error::NotBaseline`]. A scan that ends early is [`Error::Truncated`]:
//! zero bits decode as a valid symbol, so a damaged file would otherwise
//! read as empty blocks.

#![no_std]
#![forbid(unsafe_code)]

pub mod exif;
mod huffman;
pub mod scan;
pub mod segment;

/// Why a file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No start-of-image marker where one must be.
    NotJpeg,
    /// A segment length, a table, a component or a header that does not
    /// hold together.
    Malformed,
    /// Not baseline sequential Huffman, in one scan over every component.
    NotBaseline,
    /// The frame declares more blocks than the caller allows.
    TooLarge,
    /// The entropy-coded data ends before the declared blocks do.
    Truncated,
    /// The caller's output buffer cannot hold the result.
    BufferTooSmall,
    /// A changed coefficient needs a Huffman code the file's table lacks
    /// (optimized tables only).
    Unencodable,
}
