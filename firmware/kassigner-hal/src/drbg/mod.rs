// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The generator every board draws from: a ChaCha20 DRBG seeded through
//! SHA-256 from a board's tested raw source.
//!
//! **No hardware**, and no dependencies but `sha2` and `zeroize`: it runs on
//! the host in `tests/drbg.rs`, so the RFC 8439 known-answer test runs in CI.
//! A subtly wrong cipher passes every statistical test and is predictable to
//! whoever knows the bug, so it must be caught before hardware.
//!
//! Every board goes through it: a raw word reaching an ephemeral scalar or
//! a GCM nonce with only a wide health band between would carry its bias
//! there, which a BIP340 `aux_rand` does not mind. The P4's SP 800-90B
//! continuous tests stay in its crate: their cutoffs come from measuring
//! that silicon.
//!
//! ## Layers
//!
//! ```text
//!   board's raw source   --impl Entropy-->   drbg::Drbg   --impl Entropy-->  the flow
//!   with its own health tests               SHA-256 seed,
//!   (S3: window tests; P4: RCT + APT)       ChaCha20 with fast key erasure
//! ```
//!
//! The source is tested and raw, as [`crate::entropy`] requires; the
//! generator conditions.

pub mod chacha20;
pub mod generator;

pub use generator::{Drbg, DrbgError};
