// KasSigner — Operaciones en Tiempo Constante
// 100% Rust, no-std
//
// NEVER use == to compare cryptographic material.
// El operador == cortocircuita en el primer byte diferente,
// enabling timing attacks that deduce how many bytes match.
//
// All functions here iterate over ALL bytes every time,
// taking the same time regardless of content.


use core::sync::atomic::{compiler_fence, Ordering};

/// Compara dos slices de bytes en tiempo constante.
/// Returns true if and only if they are identical byte-by-byte.
/// Siempre recorre todos los bytes — nunca cortocircuita.
#[inline(never)]
/// Constant-time equality comparison for byte slices.
/// Returns false if lengths differ. Prevents timing side-channels.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff: u8 = 0;

    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    compiler_fence(Ordering::SeqCst);
    diff == 0
}

/// Compara dos arrays de 32 bytes en tiempo constante.
/// Specialized version for SHA256 hashes.
#[inline(never)]
/// Constant-time equality for 32-byte arrays (keys, hashes).
pub fn eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;

    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }

    compiler_fence(Ordering::SeqCst);
    diff == 0
}

/// Verifica si un slice es todo ceros en tiempo constante.
/// Useful for detecting uninitialized buffers.
#[inline(never)]
/// Constant-time check if all bytes are zero.
pub fn is_zero(data: &[u8]) -> bool {
    let mut acc: u8 = 0;

    for &byte in data {
        acc |= byte;
    }

    compiler_fence(Ordering::SeqCst);
    acc == 0
}

/// Select condicional en tiempo constante.
/// Retorna `a` si `condition` es true, `b` si es false.
/// No branches — operates with bit masks.
#[inline(never)]
/// Constant-time conditional select: returns `a` if condition is true, `b` otherwise.
pub fn select(condition: bool, a: u8, b: u8) -> u8 {
    // Convert bool to mask: true → 0xFF, false → 0x00
    let mask = (-(condition as i8)) as u8;
    compiler_fence(Ordering::SeqCst);
    (a & mask) | (b & !mask)
}
