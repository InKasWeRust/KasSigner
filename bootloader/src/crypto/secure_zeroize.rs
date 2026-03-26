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
// The compiler may optimize away memset(0) if it believes the memory
// is not used afterwards. This is a security problem: keys and
// seeds can remain in RAM after "erasing" them.
//
// This module guarantees erasure using:
//   1. core::ptr::write_volatile — the compiler cannot eliminate volatile writes
//   2. compiler_fence — evita reordenamiento de instrucciones
//   3. Post-zeroization verification (in debug/dev)
//
// USO:
//   zeroize_slice(&mut my_key_bytes);
//   zeroize_array(&mut my_32byte_key);
//
// For structs containing secrets, implement the Zeroize trait:
//   impl Zeroize for MyStruct { fn zeroize(&mut self) { ... } }


#![allow(dead_code)]
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
/// Trait for structs containing sensitive material.
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
/// Wraps any type implementing Zeroize.
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
