//! Firmware Argon2id adapter with mandatory PSRAM workspace provenance.
//!
//! The cryptographic core lives in `offline_signer::crypto::password_kdf`.
//! This adapter is the only current-format password derivation entry point in
//! firmware and guarantees that the complete Argon2 workspace was allocated
//! from esp-alloc's External capability and lies inside the runtime ESP-HAL
//! PSRAM mapping. Allocation/provenance failure is fail-closed; there is no
//! internal-SRAM fallback and no parameter reduction.

use offline_signer::crypto::password_kdf::{
    self, PasswordKdfBlock, PasswordKdfError, PasswordKdfParams, PasswordKdfPurpose,
    MAX_PASSWORD_SIZE, SALT_SIZE, WORKSPACE_BLOCK_ALIGN, WORKSPACE_BLOCK_BYTES,
};

use super::psram::{PsramAllocation, PsramError};
#[cfg(feature = "argon2-bench")]
use super::psram::{self, PsramRegion};

#[cfg(feature = "argon2-bench")]
pub(crate) struct WorkspaceInfo {
    pub psram: PsramRegion,
    pub workspace_start: usize,
    pub workspace_len: usize,
}

struct Argon2Workspace {
    allocation: PsramAllocation,
    block_count: usize,
}

impl Argon2Workspace {
    fn allocate(parameters: PasswordKdfParams) -> Result<Self, PasswordKdfError> {
        let block_count = password_kdf::workspace_block_count(parameters)?;
        let bytes = block_count
            .checked_mul(WORKSPACE_BLOCK_BYTES)
            .ok_or(PasswordKdfError::AllocationFailed)?;
        let allocation = PsramAllocation::allocate(bytes, WORKSPACE_BLOCK_ALIGN)
            .map_err(map_psram_error)?;
        Ok(Self { allocation, block_count })
    }

    fn blocks(&mut self) -> &mut [PasswordKdfBlock] {
        debug_assert_eq!(self.allocation.len(), self.block_count * WORKSPACE_BLOCK_BYTES);
        debug_assert_eq!(self.allocation.start() % WORKSPACE_BLOCK_ALIGN, 0);
        // SAFETY: `PsramAllocation::allocate` proves runtime PSRAM provenance,
        // honors the requested Block alignment, and zero-initializes every raw
        // byte before returning. An all-zero byte representation is exactly
        // `PasswordKdfBlock::default()`, so the typed slice begins its lifetime
        // only after the complete backing region contains valid Block values.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.allocation.as_mut_bytes().as_mut_ptr().cast::<PasswordKdfBlock>(),
                self.block_count,
            )
        }
    }

    fn validate_provenance(&self) -> Result<(), PasswordKdfError> {
        if self.allocation.has_valid_provenance() {
            Ok(())
        } else {
            Err(PasswordKdfError::AllocationFailed)
        }
    }

    #[cfg(feature = "argon2-bench")]
    fn info(&self) -> Result<WorkspaceInfo, PasswordKdfError> {
        self.validate_provenance()?;
        Ok(WorkspaceInfo {
            psram: psram::region().map_err(map_psram_error)?,
            workspace_start: self.allocation.start(),
            workspace_len: self.allocation.len(),
        })
    }

    #[cfg(feature = "argon2-bench")]
    fn full_buffer_integrity_test(&mut self) -> bool {
        let bytes = self.allocation.as_mut_bytes();
        for (index, byte) in bytes.iter_mut().enumerate() {
            let expected = integrity_pattern(index);
            unsafe { core::ptr::write_volatile(byte, expected) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut valid = true;
        for (index, byte) in bytes.iter().enumerate() {
            let observed = unsafe { core::ptr::read_volatile(byte) };
            valid &= observed == integrity_pattern(index);
        }
        shared_signer::bytes::zeroize_bytes(bytes);
        valid
    }
}

#[cfg(feature = "argon2-bench")]
fn integrity_pattern(index: usize) -> u8 {
    (index as u8).wrapping_mul(0x5d) ^ ((index >> 8) as u8).wrapping_add(0xa7)
}

fn map_psram_error(_: PsramError) -> PasswordKdfError {
    PasswordKdfError::AllocationFailed
}

pub(crate) fn derive_key_32(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; 32], PasswordKdfError> {
    derive_key_32_with_params(purpose, password, salt, PasswordKdfParams::current())
}

pub(crate) fn derive_key_32_with_params(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<[u8; 32], PasswordKdfError> {
    validate_inputs(password, parameters)?;
    // Prior hardware qualification used this topology successfully: the application
    // event loop performs Argon2 synchronously on its normal foreground core
    // while the already-running peer derivation worker remains untouched.
    // Do not hard-stall a live peer core around allocator/PSRAM work.
    #[cfg(feature = "m5stack")]
    crate::log!(
        "   Argon2 PSRAM foreground BEGIN free={} bytes",
        super::psram::free_bytes(),
    );
    let result = derive_key_32_foreground(purpose, password, salt, parameters);
    #[cfg(feature = "m5stack")]
    match &result {
        Ok(_) => crate::log!(
            "   Argon2 PSRAM foreground DONE ok=true free={} bytes",
            super::psram::free_bytes(),
        ),
        Err(error) => crate::log!(
            "   Argon2 PSRAM foreground DONE error={:?} free={} bytes",
            error,
            super::psram::free_bytes(),
        ),
    }
    result
}

fn validate_inputs(
    password: &[u8],
    parameters: PasswordKdfParams,
) -> Result<(), PasswordKdfError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_SIZE {
        return Err(PasswordKdfError::InvalidPasswordLength);
    }
    if !parameters.is_current() || !parameters.meets_v1_minimum() {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

#[inline(never)]
fn derive_key_32_foreground(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<[u8; 32], PasswordKdfError> {
    let mut workspace = Argon2Workspace::allocate(parameters)?;
    workspace.validate_provenance()?;
    password_kdf::derive_key_32_with_workspace(
        purpose,
        password,
        salt,
        parameters,
        workspace.blocks(),
    )
}

#[cfg(feature = "argon2-bench")]
pub(crate) struct BenchmarkResult {
    pub info: WorkspaceInfo,
    pub integrity_ok: bool,
    pub key: Result<[u8; 32], PasswordKdfError>,
}

#[cfg(feature = "argon2-bench")]
pub(crate) fn derive_benchmark_key_32(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<BenchmarkResult, PasswordKdfError> {
    derive_benchmark_key_32_foreground(purpose, password, salt, parameters)
}

#[cfg(feature = "argon2-bench")]
#[inline(never)]
fn derive_benchmark_key_32_foreground(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<BenchmarkResult, PasswordKdfError> {
    let mut workspace = Argon2Workspace::allocate(parameters)?;
    let info = workspace.info()?;
    let integrity_ok = workspace.full_buffer_integrity_test();
    if !integrity_ok {
        return Ok(BenchmarkResult {
            info,
            integrity_ok: false,
            key: Err(PasswordKdfError::AllocationFailed),
        });
    }
    let key = password_kdf::derive_benchmark_key_32_with_workspace(
        purpose,
        password,
        salt,
        parameters,
        workspace.blocks(),
    );
    Ok(BenchmarkResult { info, integrity_ok, key })
}
