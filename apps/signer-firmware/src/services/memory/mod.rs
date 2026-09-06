//! Runtime memory ownership for security-sensitive firmware services.
//!
//! Argon2 password derivation must use an explicitly external-PSRAM-backed
//! workspace. The PSRAM region is recorded from ESP-HAL after initialization;
//! no board-specific virtual address is hard-coded here.

pub(crate) mod password_kdf;
pub(crate) mod psram;

/// Allocate a bounded zeroed runtime byte buffer without invoking the OOM handler.
pub(crate) fn zeroed_bytes(len: usize) -> Result<alloc::vec::Vec<u8>, ()> {
    let mut out = alloc::vec::Vec::new();
    out.try_reserve_exact(len).map_err(|_| ())?;
    out.resize(len, 0);
    Ok(out)
}

/// Reserve a bounded runtime vector without invoking the OOM handler.
#[cfg(feature = "rng-probe")]
pub(crate) fn fallible_vec<T>(capacity: usize) -> Result<alloc::vec::Vec<T>, ()> {
    let mut out = alloc::vec::Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| ())?;
    Ok(out)
}
