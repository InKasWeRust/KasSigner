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

// crypto/secure_zeroize.rs — Secure memory zeroization
// 100% Rust, no-std
//
// El compilador puede optimizar memset(0) si cree que la memoria
// is not used afterwards. This is a security problem: keys and
// seeds can remain in RAM after "erasing" them.
//
// This module guarantees erasure using:
//   1. core::ptr::write_volatile — el compilador no puede eliminar escrituras volatile
//   2. compiler_fence — evita reordenamiento de instrucciones
//   3. Post-zeroization verification (in debug/dev)
//
// USO:
//   zeroize_slice(&mut my_key_bytes);
//   zeroize_array(&mut my_32byte_key);
//
// Para structs que contienen secretos, implementar el trait Zeroize:
//   impl Zeroize for MyStruct { fn zeroize(&mut self) { ... } }


use core::sync::atomic::{compiler_fence, Ordering};

/// Zeroiza un slice mutable de bytes.
/// Guaranteed: will not be eliminated by the optimizer.
#[inline(never)]
/// Securely zero a byte slice. Uses volatile writes to prevent optimizer removal.
pub fn zeroize_slice(data: &mut [u8]) {
    compiler_fence(Ordering::SeqCst);

    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte as *mut u8, 0x00); }
    }

    compiler_fence(Ordering::SeqCst);
}

/// Zeroiza un array de N bytes.
#[inline(never)]
/// Securely zero a fixed-size byte array.
pub fn zeroize_array<const N: usize>(data: &mut [u8; N]) {
    compiler_fence(Ordering::SeqCst);

    for byte in data.iter_mut() {
        unsafe { core::ptr::write_volatile(byte as *mut u8, 0x00); }
    }

    compiler_fence(Ordering::SeqCst);
}

/// Zeroiza una palabra de 32 bits.
#[inline(never)]
/// Securely zero a u32 value.
pub fn zeroize_u32(data: &mut u32) {
    compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(data as *mut u32, 0x0000_0000); }
    compiler_fence(Ordering::SeqCst);
}

/// Zeroiza una palabra de 64 bits.
#[inline(never)]
/// Securely zero a u64 value.
pub fn zeroize_u64(data: &mut u64) {
    compiler_fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(data as *mut u64, 0x0000_0000_0000_0000); }
    compiler_fence(Ordering::SeqCst);
}

/// Trait para structs que contienen material sensible.
/// Implement for each struct that stores keys, seeds, etc.
///
/// ```rust
/// struct MyKey {
///     scalar: [u8; 32],
///     chain_code: [u8; 32],
/// }
///
/// impl Zeroize for MyKey {
///     fn zeroize(&mut self) {
///         secure_zeroize::zeroize_array(&mut self.scalar);
///         secure_zeroize::zeroize_array(&mut self.chain_code);
///     }
/// }
/// ```
pub trait Zeroize {
    /// Borra todo el material sensible de esta estructura.
    fn zeroize(&mut self);
}

/// Guard that automatically zeroizes when going out of scope.
/// Envuelve cualquier tipo que implemente Zeroize.
///
/// ```rust
/// {
///     let mut guard = ZeroizeGuard::new(my_key);
///     // usar guard.inner...
/// } // ← automatically zeroized here
/// ```
pub struct ZeroizeGuard<T: Zeroize> {
    pub inner: T,
}

impl<T: Zeroize> ZeroizeGuard<T> {
    /// Create a new ZeroizeGuard wrapping a value. Zeroizes on drop.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }
}

impl<T: Zeroize> Drop for ZeroizeGuard<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Verifica que un slice ha sido zeroizado correctamente.
/// For testing/debug only — do not use in production code
/// (the verification itself could be a side-channel).
#[cfg(not(feature = "production"))]
/// Verify that a buffer has been zeroized (debug/test only — may leak timing info).
pub fn verify_zeroed(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &byte in data {
        let val = unsafe { core::ptr::read_volatile(&byte as *const u8) };
        acc |= val;
    }
    compiler_fence(Ordering::SeqCst);
    acc == 0
}
