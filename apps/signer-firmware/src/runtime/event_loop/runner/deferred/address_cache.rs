//! Cooperative receive/change public-key cache derivation.

use crate::runtime::{data::AppData, input::AppState};

#[cfg(feature = "m5stack")]
const PBKDF2_ROUNDS_PER_STEP: u16 = 1;
#[cfg(feature = "m5stack")]
const ADDRESS_TOTAL_BUDGET_MS: u64 = 75_000;
#[cfg(feature = "m5stack")]
const ADDRESS_STALL_BUDGET_MS: u64 = 20_000;

#[cfg(feature = "waveshare")]
pub(super) fn service(ad: &mut AppData, watchdog_feed: &mut impl FnMut()) {
    let address_screen = matches!(ad.navigation.app.state, AppState::ShowAddress | AppState::ShowAddressQR);
    if !address_screen
        || !ad.runtime.needs_redraw
        || ad.qr.scan.address_length != 0
        || ad.wallet.addresses.pubkeys_cached
    {
        return;
    }
    watchdog_feed();
    crate::log!("   ADDRESS cache derivation BEGIN");
    match crate::runtime::signing::populate_active_pubkeys_with_checkpoint(ad, watchdog_feed) {
        Ok(()) => crate::log!("   ADDRESS cache derivation DONE"),
        Err(error) => crate::log!("   ADDRESS cache derivation failed: {}", error),
    }
    watchdog_feed();
}

#[cfg(feature = "m5stack")]
fn cancel(ad: &mut AppData) {
    use crate::services::wallet_keys::worker as kpub_worker;
    ad.wallet.addresses.cache_seed_derivation = None;
    if let Some(generation) = ad.wallet.addresses.cache_worker_generation.take() {
        kpub_worker::cancel(generation);
    }
    ad.wallet.addresses.cache_progress = 0;
    ad.wallet.addresses.cache_started_at_ms = 0;
    ad.wallet.addresses.cache_last_progress_at_ms = 0;
}

#[cfg(feature = "m5stack")]
fn service_worker(ad: &mut AppData, watchdog_feed: &mut impl FnMut(), generation: u8) {
    use crate::services::wallet_keys::worker as kpub_worker;
    let progress = kpub_worker::progress(generation);
    if progress != ad.wallet.addresses.cache_progress {
        ad.wallet.addresses.cache_progress = progress;
        ad.wallet.addresses.cache_last_progress_at_ms = now_millis();
        ad.runtime.needs_redraw = true;
    }
    let Some(mut result) = kpub_worker::take_result(generation) else { return; };
    ad.wallet.addresses.cache_worker_generation = None;
    if let Some(error) = result.error() {
        crate::log!("   ADDRESS Core1 derivation failed: {}", error);
        fail(ad);
        return;
    }
    if let Err(error) = crate::runtime::signing::install_worker_address_cache(ad, &mut result) {
        crate::log!("   ADDRESS Core1 result rejected: {}", error);
        fail(ad);
        return;
    }
    ad.wallet.addresses.cache_progress = 100;
    ad.wallet.addresses.cache_started_at_ms = 0;
    ad.wallet.addresses.cache_last_progress_at_ms = 0;
    ad.runtime.needs_redraw = true;
    crate::log!("   ADDRESS cache derivation DONE");
    watchdog_feed();
}

#[cfg(feature = "m5stack")]
fn fail(ad: &mut AppData) {
    cancel(ad);
    crate::runtime::presentation::show_error_spec_previous(
        ad, crate::runtime::presentation::ADDRESS_DERIVE,
    );
}

#[cfg(feature = "m5stack")]
pub(super) fn service(ad: &mut AppData, watchdog_feed: &mut impl FnMut()) {
    use crate::services::wallet_keys::worker as kpub_worker;
    let address_screen = matches!(ad.navigation.app.state, AppState::ShowAddress | AppState::ShowAddressQR);
    if !address_screen || ad.qr.scan.address_length != 0 {
        cancel(ad);
        return;
    }
    if ad.wallet.addresses.pubkeys_cached { return; }
    if timeout_if_stalled(ad) { return; }
    watchdog_feed();
    if let Some(generation) = ad.wallet.addresses.cache_worker_generation {
        service_worker(ad, watchdog_feed, generation);
        return;
    }
    if advance_seed(ad, watchdog_feed) { return; }
    if !kpub_worker::is_idle() { return; }
    start(ad);
    watchdog_feed();
}

#[cfg(feature = "m5stack")]
fn advance_seed(ad: &mut AppData, watchdog_feed: &mut impl FnMut()) -> bool {
    use crate::services::wallet_keys::worker as kpub_worker;
    let Some(work) = ad.wallet.addresses.cache_seed_derivation.as_mut() else { return false; };
    let seed = work.advance(PBKDF2_ROUNDS_PER_STEP);
    let progress = ((u16::from(work.progress_percent()) * 85) / 100) as u8;
    if progress != ad.wallet.addresses.cache_progress {
        ad.wallet.addresses.cache_progress = progress;
        ad.wallet.addresses.cache_last_progress_at_ms = now_millis();
        ad.runtime.needs_redraw = true;
    }
    let Some(mut seed) = seed else { return true; };
    ad.wallet.addresses.cache_seed_derivation = None;
    match kpub_worker::submit_address_seed(&mut seed) {
        Ok(generation) => {
            ad.wallet.addresses.cache_worker_generation = Some(generation);
            crate::log!("   ADDRESS PBKDF2 DONE; Core1 cache finalizer submitted");
        }
        Err(error) => {
            shared_signer::bytes::zeroize_bytes(&mut seed.bytes);
            crate::log!("   ADDRESS Core1 submit failed: {}", error);
            fail(ad);
        }
    }
    watchdog_feed();
    true
}

#[cfg(feature = "m5stack")]
fn start(ad: &mut AppData) {
    use crate::services::wallet_keys::worker as kpub_worker;
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        crate::log!("   ADDRESS cache derivation failed: no active wallet");
        crate::runtime::presentation::show_error_spec_previous(
            ad, crate::runtime::presentation::ADDRESS_DERIVE,
        );
        return;
    };
    crate::log!("   ADDRESS cooperative cache derivation BEGIN");
    let now = now_millis();
    ad.wallet.addresses.cache_started_at_ms = now;
    ad.wallet.addresses.cache_last_progress_at_ms = now;
    if slot.is_mnemonic() {
        match crate::runtime::signing::begin_mnemonic_seed(slot) {
            Ok(work) => {
                ad.wallet.addresses.cache_seed_derivation = Some(work);
                ad.wallet.addresses.cache_progress = 1;
                ad.runtime.needs_redraw = true;
            }
            Err(error) => {
                crate::log!("   ADDRESS PBKDF2 start failed: {}", error);
                fail(ad);
            },
        }
        return;
    }
    match kpub_worker::submit_address_slot(slot) {
        Ok(generation) => {
            ad.wallet.addresses.cache_worker_generation = Some(generation);
            ad.wallet.addresses.cache_progress = 85;
            ad.runtime.needs_redraw = true;
        }
        Err(error) => {
            crate::log!("   ADDRESS cache submit failed: {}", error);
            fail(ad);
        },
    }
}

#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
pub(crate) fn workflow_drive_address_cache(
    ad: &mut AppData,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    for _ in 0..8192u32 {
        service(ad, watchdog_feed);
        if ad.wallet.addresses.pubkeys_cached { return true; }
        watchdog_feed();
        esp_hal::delay::Delay::new().delay_millis(1);
    }
    false
}

#[cfg(feature = "m5stack")]
fn timeout_if_stalled(ad: &mut AppData) -> bool {
    let started = ad.wallet.addresses.cache_started_at_ms;
    if started == 0 { return false; }
    let now = now_millis();
    let total_expired = now.saturating_sub(started) >= ADDRESS_TOTAL_BUDGET_MS;
    let progress_expired = now
        .saturating_sub(ad.wallet.addresses.cache_last_progress_at_ms)
        >= ADDRESS_STALL_BUDGET_MS;
    if !total_expired && !progress_expired { return false; }
    crate::log!("   ADDRESS derivation timed out before watchdog");
    cancel(ad);
    crate::runtime::presentation::show_error_spec_previous(
        ad, crate::runtime::presentation::ADDRESS_TIMEOUT,
    );
    true
}

#[cfg(feature = "m5stack")]
fn now_millis() -> u64 {
    esp_hal::time::Instant::now().duration_since_epoch().as_millis()
}
