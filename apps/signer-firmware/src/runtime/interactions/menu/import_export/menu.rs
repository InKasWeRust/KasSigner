use super::{display, scanning, touch, AppData, Delay, I2c};
use crate::services::storage_files;
use crate::runtime::interactions::{
    feedback::{show_rejection, ErrorSound},
    menu_selection::selected_visible_item,
};
use crate::runtime::input::AppState;



pub(super) fn handle_pure(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::ImportExportChoice => handle_choice_pure(ad, x, y, is_back),
        AppState::ImportMenu => handle_import_menu_pure(ad, list_zones, x, y, is_back),
        _ => None,
    }
}

fn handle_choice_pure(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> Option<bool> {
    if is_back { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu)); return Some(true); }
    if (22..=152).contains(&x) && (100..=155).contains(&y) {
        ad.navigation.import_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportMenu)); return Some(true);
    }
    if (168..=298).contains(&x) && (100..=155).contains(&y) {
        if ad.wallet.seeds.seed_loaded { ad.navigation.export_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice)); return Some(true); }
        return None;
    }
    Some(false)
}

fn handle_import_menu_pure(
    ad: &mut AppData, list_zones: &[touch::TouchZone; 4], x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    if is_back { ad.navigation.import_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportExportChoice)); return Some(true); }
    let Some(item) = selected_visible_item(&ad.navigation.import_menu, list_zones, x, y) else { return Some(false); };
    match item {
        0 => {  ad.navigation.sd_import_menu.reset(); crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdImportMenu)); Some(true) }
        2 => { ad.wallet.keys.hex_input_len = 0; crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportPrivKey)); Some(true) }
        1 | 3 => None,
        _ => Some(false),
    }
}

pub(super) fn handle_choice(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut Delay,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedsMenu));
    } else if (22..=152).contains(&x) && (100..=155).contains(&y) {
        ad.navigation.import_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportMenu));
    } else if (168..=298).contains(&x) && (100..=155).contains(&y) {
        if ad.wallet.seeds.seed_loaded {
            ad.navigation.export_menu.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportChoice));
        } else {
            show_rejection(
                boot_display,
                delay,
                "Load a seed first",
                1_500,
                ErrorSound::Silent,
            );
        }
    } else {
        return false;
    }
    true
}

pub(super) fn handle_import_menu(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut Delay,
    i2c: &mut I2c<'_>,
    list_zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.navigation.import_menu.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportExportChoice));
        return true;
    }
    let Some(item) = selected_visible_item(&ad.navigation.import_menu, list_zones, x, y) else {
        return false;
    };
    match item {
        0 => {
            
            ad.navigation.sd_import_menu.reset();
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdImportMenu));
        }
        1 => {
            boot_display.draw_loading_screen("Scanning SD...");
            let scanned = storage_files::scan_jpeg_files(
                &mut ad.stego.import.jpeg_names,
                &mut ad.stego.import.jpeg_display,
                &mut ad.stego.import.jpeg_display_lens,
                &mut ad.stego.import.jpeg_count,
                delay,
                i2c,
            );
            if matches!(scanned, Ok(count) if count > 0) {
                ad.stego.import.jpeg_selected = 0;
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPick));
            } else {
                show_rejection(boot_display, delay, "No .JPG files on SD", 2_000, ErrorSound::Beep);
            }
        }
        2 => {
            ad.wallet.keys.hex_input_len = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportPrivKey));
        }
        3 => scanning::scan_covenant_backups(ad, boot_display, delay, i2c),
        _ => return false,
    }
    true
}
