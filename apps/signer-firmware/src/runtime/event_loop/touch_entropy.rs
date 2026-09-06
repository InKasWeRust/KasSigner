//! Per-poll Touch Seed entropy collection.

use crate::{
    hw::{display::BootDisplay, touch::TouchState},
    runtime::{data::AppData, input::AppState},
};

/// Fold one raw touch-controller observation into the active Touch Seed
/// transcript. Returns true when the state changed and the normal touch action
/// from the same poll must be discarded.
#[inline(never)]
pub fn process_step(
    touch_state: TouchState,
    ad: &mut AppData,
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    if ad.navigation.app.state != AppState::TouchEntropy {
        return false;
    }
    let TouchState::One(point) = touch_state else { return false; };

    // Keep navigation chrome out of the entropy transcript. Only points in the
    // visible canvas are recorded and painted.
    if !(21..299).contains(&point.x) || !(76..214).contains(&point.y) {
        return false;
    }

    let before = ad.wallet.seeds.touch_collector.count();
    let timestamp = crate::services::entropy::touch_timestamp();
    if !ad.wallet.seeds.touch_collector.record(timestamp, point.x, point.y) {
        return false;
    }
    let after = ad.wallet.seeds.touch_collector.count();
    boot_display.draw_touch_entropy_point(
        point.x,
        point.y,
        after,
        ad.wallet.seeds.touch_collector.target(),
    );
    if after < ad.wallet.seeds.touch_collector.target() || after == before {
        return false;
    }

    boot_display.draw_saving_screen("Hardening entropy...");
    let Some(mut touch_digest) = ad.wallet.seeds.touch_collector.finish() else {
        fail(ad, boot_display, delay, "Touch entropy incomplete");
        return true;
    };
    if ad.wallet.seeds.pending_seed_entropy_valid {
        crate::services::entropy::mix_additive_touch(
            &mut ad.wallet.seeds.pending_seed_entropy,
            &mut touch_digest,
        );
        if crate::runtime::interactions::menu::seed_generation::finalize_staged_entropy(ad) {
            log!("   Added touch transcript to checked staged entropy");
        } else {
            fail(ad, boot_display, delay, "Staged entropy unavailable");
        }
        ad.runtime.needs_redraw = true;
        return true;
    }

    match crate::services::entropy::harden_touch_entropy(&mut touch_digest) {
        Ok(mut pool) => {
            let wc = if ad.wallet.seeds.word_count == 24 { 24 } else { 12 };
            let entropy_len = if wc == 24 { 32 } else { 16 };
            ad.wallet.seeds.mnemonic_indices =
                crate::wallet::mnemonic::generate_from_entropy(wc, &pool[..entropy_len]);
            crate::services::entropy::zeroize(&mut pool);
            ad.wallet.seeds.pp_input.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice));
            true
        }
        Err(error) => {
            crate::services::entropy::zeroize(&mut touch_digest);
            fail(ad, boot_display, delay, error.message());
            true
        }
    }
}

fn fail(
    ad: &mut AppData,
    boot_display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    message: &'static str,
) {
    ad.wallet.seeds.touch_collector.reset();
    crate::runtime::interactions::feedback::show_rejection(
        boot_display,
        delay,
        message,
        2_000,
        crate::runtime::interactions::feedback::ErrorSound::Silent,
    );
    if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
        ad.wallet.seeds.clear_pending_seed_entropy();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedWordCountChoice { action: 0 }));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedToolsMenu));
    }
}
