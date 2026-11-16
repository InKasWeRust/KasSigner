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

//! The P4's side of the generator: its SAR ADC noise source behind the
//! SP 800-90B continuous health tests, as the
//! [`kassigner_hal::entropy::Entropy`] the generator seeds from.
//!
//! **No hardware, no esp-hal:** everything here compiles on the host and is
//! exercised by `tests/drbg.rs`; `entropy` provides the raw source.
//!
//! The ChaCha20 DRBG is `kassigner_hal::drbg`, shared with the S3 units.
//! What is this silicon's stays here: [`health`]'s cutoffs come from the
//! assessment of this ADC and would be wrong for another source.
//!
//! ## Layers
//!
//! ```text
//!   entropy::HwSource  --drbg::Entropy-->  health::Guarded  --hal Entropy-->  hal drbg::Drbg
//!      SAR ADC noise                       RCT + APT per 90B                  SHA-256 seed,
//!                                                                             ChaCha20
//! ```

pub mod health;

pub use health::{Guarded, HealthError};
pub use kassigner_hal::drbg::{Drbg, DrbgError};

/// A physical noise source, such as `entropy::HwSource` over the SAR ADC.
///
/// Implementations return raw 32-bit reads and pace them: back-to-back
/// reads of a hardware RNG can correlate if the source has not had time to
/// accumulate.
pub trait Entropy {
    /// Error type; `()` for a source that cannot fail mid-stream.
    type Error: core::fmt::Debug;

    /// One 32-bit sample.
    ///
    /// # Errors
    /// Implementation-defined; the health wrapper treats any error as fatal.
    fn sample(&mut self) -> Result<u32, Self::Error>;
}
