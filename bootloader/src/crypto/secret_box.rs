// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// KasSigner — SecretBox: XOR-Masked Container for Secrets
// 100% Rust, no-std
//
// Private keys and seeds must NEVER be stored in cleartext in RAM
// except during the exact instant they are used for signing.
//
// SecretBox stores the secret XORd with a random mask.
// A RAM dump will show data that appears random.
//
// FLUJO:
//   1. Crear: SecretBox::new(secret_bytes, random_mask)
//      → Almacena secret ^ mask, guarda mask
//   2. Usar: secret_box.unmask(|clear_secret| { ... })
//      → Temporarily unmask, execute closure, re-zeroize
//   3. Drop: Automatically zeroized (masked data + mask)
//
// LIMITACIONES:
//   - The mask must be truly random (use ESP32-S3 hardware TRNG)
//   - No protege contra DMA o acceso directo al bus de memoria
//   - Does not protect against cold boot if attacker reads before zeroize


use core::sync::atomic::{compiler_fence, Ordering};
use super::secure_zeroize;

/// XOR-masked container for fixed-size secrets.
/// N is the size in bytes (typically 32 for keys, 64 for seeds).
pub struct SecretBox<const N: usize> {
    /// Datos enmascarados: secret XOR mask
    masked: [u8; N],
    /// Random mask generated at creation
    mask: [u8; N],
}

impl<const N: usize> SecretBox<N> {
    /// Creates a SecretBox from a secret and a random mask.
    /// El secreto original se zeroiza en el caller.
    ///
    /// IMPORTANT: `mask` must be generated with a TRNG, not a PRNG.
    /// On ESP32-S3, use the hardware RNG (available via esp-hal).
    pub fn new(secret: &[u8; N], mask: &[u8; N]) -> Self {
        let mut masked = [0u8; N];

        // XOR each byte of the secret with the mask
        for i in 0..N {
            masked[i] = secret[i] ^ mask[i];
        }

        compiler_fence(Ordering::SeqCst);

        Self {
            masked,
            mask: *mask,
        }
    }

    /// Temporarily unmask the secret and execute a closure with it.
    /// The temporary buffer is ALWAYS zeroized on completion, even if
    /// the closure panics (thanks to the drop guard).
    ///
    /// ```rust
    /// secret_box.unmask(|clear_key| {
    ///     // use clear_key to sign
    ///     sign_transaction(clear_key, &tx);
    /// });
    /// // clear_key ya no existe y fue zeroizado
    /// ```
    pub fn unmask<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; N]) -> R,
    {
        // Desenmascarar en buffer temporal
        let mut clear = [0u8; N];
        for i in 0..N {
            clear[i] = self.masked[i] ^ self.mask[i];
        }
        compiler_fence(Ordering::SeqCst);

        // Ejecutar la closure con el secreto en claro
        let result = f(&clear);

        // Always zeroize the temporary buffer
        secure_zeroize::zeroize_array(&mut clear);

        result
    }
}

impl<const N: usize> Drop for SecretBox<N> {
    fn drop(&mut self) {
        // Zeroize both the masked data and the mask
        secure_zeroize::zeroize_slice(&mut self.masked);
        secure_zeroize::zeroize_slice(&mut self.mask);
    }
}

// SecretBox NO implementa Clone, Copy, Debug, ni Display.
// This prevents accidental copies and leaks via logging.
// If you need to clone a secret, you must do it explicitly
// with unmask() + SecretBox::new().
