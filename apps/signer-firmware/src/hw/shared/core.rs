//! Shared ESP32-S3 peer-core coordination for flash-critical sections.
//!
//! ROM flash erase/write/read paths have historically required the peer core
//! to be stalled while cache/flash access is unavailable. Memory-hard PSRAM
//! work is deliberately not routed through this primitive: credential Argon2
//! uses the normal foreground application core with the peer worker left alive.

use esp_hal::{
    peripherals::CPU_CTRL,
    system::{is_running, Cpu, CpuControl},
};

/// Run one flash-critical closure with every other running core parked, then
/// always restore it after the flash-critical operation returns.
///
/// This primitive is intentionally scoped to raw flash ownership. Argon2 and
/// other ordinary external-PSRAM work must not use it.
pub(crate) fn with_other_core_parked<T>(operation: impl FnOnce() -> T) -> T {
    let parked = park_other_core();
    let result = operation();
    restore_other_core(parked);
    result
}

// Memory-hard work used to run on the foreground application core while the
// peer derivation worker remained alive. That hardware-proven topology is the
// firmware policy again. Keeping these comments here also makes the separation
// from this low-level flash primitive explicit at the unsafe review boundary.
//
// In particular, callers must not use this helper merely to reduce PSRAM/cache
// concurrency. A hard stall is suitable only when the flash critical section
// itself requires the other core not to execute cached flash instructions.
//
// Credential and backup KDF code therefore owns no CPU_CTRL capability and
// cannot stall or restart the peer core as part of password derivation.
//
// The flash service remains the only production consumer of this primitive.
// This separation is part of the reviewed hardware ownership contract.
// The KDF adapter has no import path to this helper.
// The operation engine never manipulates CPU control registers.
// Future memory-hard work must preserve that same boundary.
//

fn park_other_core() -> bool {
    // SAFETY: startup relinquishes its CpuControl handle before services run.
    // This temporary handle only parks Cpu::other(), never the executing core.
    let mut cpu_control = CpuControl::new(unsafe { CPU_CTRL::steal() });
    for other_cpu in Cpu::other() {
        if is_running(other_cpu) {
            // SAFETY: Cpu::other() cannot yield the core executing this function.
            unsafe { cpu_control.park_core(other_cpu) };
            return true;
        }
    }
    false
}

fn restore_other_core(parked: bool) {
    if !parked {
        return;
    }
    // SAFETY: recreates the short-lived control handle only to reverse the park.
    let mut cpu_control = CpuControl::new(unsafe { CPU_CTRL::steal() });
    for other_cpu in Cpu::other() {
        cpu_control.unpark_core(other_cpu);
    }
}
