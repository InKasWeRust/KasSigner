// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Cooperative work that advances only in short event-loop-owned chunks.

use crate::runtime::data::AppData;
#[cfg(all(any(feature = "m5stack", feature = "waveshare"), feature = "workflow-runtime-auto"))]
use crate::runtime::input::AppState;

mod address_cache;
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) use address_cache::workflow_drive_address_cache;

mod kpub;
pub(in crate::runtime::event_loop) use kpub::{cancel_operation, service_operation};
#[cfg(not(feature = "workflow-test-auto"))]
pub(in crate::runtime::event_loop) use kpub::service;


#[cfg(feature = "argon2-bench")]
#[inline(never)]
pub(in crate::runtime::event_loop) fn service_request(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) {
    address_cache::service(ad, watchdog_feed);
    service_argon2_benchmark(ad, boot_display, delay, watchdog_feed);
}

#[cfg(not(feature = "argon2-bench"))]
pub(in crate::runtime::event_loop) fn service_request(
    ad: &mut AppData,
    watchdog_feed: &mut impl FnMut(),
) {
    address_cache::service(ad, watchdog_feed);
}


#[cfg(feature = "argon2-bench")]
#[inline(never)]
fn service_argon2_benchmark(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) {
    if !ad.runtime.take_argon2_benchmark_request() { return; }
    boot_display.draw_loading_screen("Argon2 benchmark...");
    let passed = crate::diagnostics::argon2_bench::run(watchdog_feed);
    boot_display.draw_loading_screen(if passed {
        "Argon2 benchmark PASS"
    } else {
        "Argon2 benchmark FAIL"
    });
    crate::services::timing::pause(delay, 1_500);
    watchdog_feed();
    ad.runtime.needs_redraw = true;
}


#[cfg(all(any(feature = "m5stack", feature = "waveshare"), feature = "workflow-runtime-auto"))]
fn workflow_drive_kpub_export(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    use crate::runtime::data::{OperationKind, OperationPhase};

    let Some(kind) = crate::runtime::presentation::operation_kind(ad) else { return false; };
    if !matches!(kind, OperationKind::ConnectKasSee | OperationKind::DeriveMultisigKpub) {
        return false;
    }

    // Runtime-auto drives the real cooperative worker outside the normal event
    // loop, but it must still cross the same ownership boundary as production:
    // Queued is physically rendered first, then Presented becomes Running once.
    match crate::runtime::presentation::operation_phase(ad) {
        OperationPhase::Presented => {
            if crate::runtime::presentation::take_ready_operation(ad) != Some(kind) {
                return false;
            }
            crate::log!("   Workflow operation {:?} BEGIN after loading surface", kind);
        }
        OperationPhase::Running | OperationPhase::Progress(_) => {}
        _ => return false,
    }

    for _ in 0..8192u32 {
        kpub::service_operation(ad, boot_display, watchdog_feed);
        if ad.navigation.app.state == AppState::ExportKpub && ad.export.kpub_len > 0 {
            return true;
        }
        watchdog_feed();
        delay.delay_millis(1);
    }
    false
}

#[cfg(all(any(feature = "m5stack", feature = "waveshare"), feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_drive_connect_kassee(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    workflow_drive_kpub_export(ad, boot_display, delay, watchdog_feed)
}

#[cfg(all(any(feature = "m5stack", feature = "waveshare"), feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_drive_multisig_kpub(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    workflow_drive_kpub_export(ad, boot_display, delay, watchdog_feed)
}

