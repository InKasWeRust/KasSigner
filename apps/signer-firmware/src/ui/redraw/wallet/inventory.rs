use super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SeedList => draw_seed_list(ad, boot_display),
        AppState::ConfirmDeleteSeed => draw_delete_confirmation(ad, boot_display),
        _ => return false,
    }
    true
}

fn draw_seed_list(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    boot_display.draw_seed_list_screen(
        &ad.wallet.seeds.seed_mgr,
        ad.wallet.seeds.seed_list_scroll,
    );
}

fn draw_delete_confirmation(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let slot_index = ad.wallet.seeds.pending_delete_slot as usize;
    #[cfg(feature = "m5stack")]
    crate::log!("   UI wallet delete confirm BEGIN slot={}", slot_index);
    let Some(slot) = ad.wallet.seeds.seed_mgr.slots.get(slot_index) else {
        #[cfg(feature = "m5stack")]
        crate::log!("   UI wallet delete confirm ABORT invalid slot");
        return;
    };
    if slot.is_empty() {
        #[cfg(feature = "m5stack")]
        crate::log!("   UI wallet delete confirm ABORT empty slot");
        return;
    }
    let mut fingerprint = [0u8; 8];
    slot.fingerprint_hex(&mut fingerprint);
    let fingerprint = core::str::from_utf8(&fingerprint).unwrap_or("????????");
    boot_display.draw_confirm_delete_screen(fingerprint, slot.source);
    #[cfg(feature = "m5stack")]
    crate::log!("   UI wallet delete confirm DONE");
}
