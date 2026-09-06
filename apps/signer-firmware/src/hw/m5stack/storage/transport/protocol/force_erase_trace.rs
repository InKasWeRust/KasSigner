//! Locked-card force-erase diagnostics that do not alter erase state.

use super::{status::card_status_r2, wire::require_success};

const CARD_LOCKED: u8 = 0x01;
const LOCK_UNLOCK_FAILED: u8 = 0x02;

pub(super) fn log_pre_force_erase_status() -> Result<(), &'static str> {
    let [r1, r2] = card_status_r2(true)?;
    crate::log!(
        "[SD-DIAG] pre-CMD42 CMD13 R1=0x{:02x} R2=0x{:02x} CARD_LOCKED={} LOCK_UNLOCK_FAILED={}",
        r1,
        r2,
        r2 & CARD_LOCKED != 0,
        r2 & LOCK_UNLOCK_FAILED != 0,
    );
    require_success(r1, "CMD13 before force erase failed")
}

pub(super) fn probe_due(elapsed_ms: u64) -> bool {
    matches!(elapsed_ms, 100 | 1_000 | 5_000)
        || (elapsed_ms >= 30_000 && elapsed_ms % 30_000 == 0)
}

pub(super) fn log_provenance_samples(elapsed_ms: u64, samples: [u8; 3]) {
    log_provenance(elapsed_ms, samples[0], samples[1], samples[2]);
}

fn log_provenance(elapsed_ms: u64, selected_before: u8, deselected: u8, reselected: u8) {
    let card_driven_busy = selected_before == 0x00 && deselected == 0xFF && reselected == 0x00;
    let bus_stuck_low = deselected == 0x00;
    crate::log!(
        "[SD-DIAG] BUSY provenance t={}ms CS_LOW_before=0x{:02x} CS_HIGH=0x{:02x} CS_LOW_after=0x{:02x} card_driven_busy={} bus_stuck_low={}",
        elapsed_ms,
        selected_before,
        deselected,
        reselected,
        card_driven_busy,
        bus_stuck_low,
    );
    if unexpected_wire_value(selected_before, deselected, reselected) {
        crate::log!(
            "[SD-DIAG] BUSY provenance unexpected wire value; expected selected 0x00/0xff and deselected 0xff",
        );
    }
}

fn unexpected_wire_value(a: u8, b: u8, c: u8) -> bool {
    !matches!(a, 0x00 | 0xFF) || b != 0xFF || !matches!(c, 0x00 | 0xFF)
}

