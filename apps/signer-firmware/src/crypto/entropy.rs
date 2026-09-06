// Cryptographic entropy façade.
//
// All hardware sampling and structural health tests live in services::entropy.
// This module remains as the crypto-facing boundary so callers do not access
// device registers directly.

pub use crate::services::entropy::EntropyError;

/// Fill `out` with health-checked hardware entropy.
///
/// Callers must handle failure; there is deliberately no infallible fallback.
pub fn fill(out: &mut [u8]) -> Result<(), EntropyError> {
    crate::services::entropy::fill(out)
}
