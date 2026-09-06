use super::embedded_expected_hash;
// ─── ESP32-S3 memory map ─────────────────────────────────────
//
// The ESP32-S3 has SEPARATE buses for instructions and data:
//
//   Bus de instrucciones (IRAM/ICache): 0x4200_0000 — 0x43FF_FFFF
//     → Execute only. CANNOT read data with load instructions.
//
//   Data bus (DRAM/DCache):         0x3C00_0000 — 0x3DFF_FFFF
//     → Can read data normally. Same physical flash.
//
// The same flash is mapped on both buses. To READ the firmware
// contents (compute SHA256), we MUST use the data bus (0x3C...).
//
// Conversion: data_addr = iram_addr - 0x4200_0000 + 0x3C00_0000
//
// From the ESP-IDF bootloader log:
//   segment 0: paddr=00010020 vaddr=3c000020 size=05e84h  → data (rodata)
//   segment 4: paddr=00020020 vaddr=42010020 size=0af5ch  → code (text)
//
// The code segment is on the instruction bus (0x4201_0020),
// but we can read it as data from 0x3C01_0020.

/// Instruction bus base for mapped flash
pub(super) const IRAM_FLASH_BASE: u32 = 0x4200_0000;

/// Data bus base for mapped flash
pub(super) const DRAM_FLASH_BASE: u32 = 0x3C00_0000;

/// Maximum code segment size (1MB, more than enough)
pub const CODE_SEGMENT_MAX_SIZE: usize = 0x0010_0000;

// Exports for main.rs
/// Maximum allowed firmware size in bytes.
pub const FIRMWARE_MAX_SIZE: usize = CODE_SEGMENT_MAX_SIZE;

// ─── Magic values for anti-glitch ────────────────────────────────────

pub(super) const CANARY_PRE_VERIFY: u32  = 0xDEAD_BEEF;
#[cfg(feature = "production")]
pub(super) const CANARY_POST_VERIFY: u32 = 0xCAFE_BABE;

// Flow counter and constant_time now come from crate::crypto
// Stages per pass of do_verify_mapped_code:
//   +1 Start read
//   +1 Data read OK
//   +1 Hash computed
//   +1 Comparison completed
// Total per pass: 4
//
// Production (2 passes): 2 (prior) + 4 + 4 = 10
// Development (1 pass):  2 (prior) + 4     = 6

// ─── Public types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
/// Firmware verification outcome.
pub enum VerificationResult {
    Valid,
    InvalidHash,
    InvalidSignature,
    VersionTooOld,
    #[cfg(all(feature = "m5stack", feature = "production"))]
    AntiRollbackUnprovisioned,
    ReadError,
    #[cfg(feature = "production")]
    FlowViolation,
    CanaryCorrupt,
}

/// Firmware metadata loaded from the embedded hash constants.
pub struct FirmwareInfo {
    pub version_major: u8,
    pub version_minor: u8,
    pub version_patch: u8,
    pub expected_hash: [u8; 32],
}

impl FirmwareInfo {
pub fn new() -> Self {
        Self {
            version_major: crate::version::MAJOR,
            version_minor: crate::version::MINOR,
            version_patch: crate::version::PATCH,
            expected_hash: embedded_expected_hash(),
        }
    }
}
