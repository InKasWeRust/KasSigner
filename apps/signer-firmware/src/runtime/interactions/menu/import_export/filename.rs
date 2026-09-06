use super::{display, AppData};
use crate::{
    runtime::interactions::keyboard::{handle_keyboard, KeyboardAction, KeyboardPolicy},
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        ad.wallet.seeds.pp_input.reset();
        ad.qr.outgoing.covenant_backup_length = 0;
        crate::runtime::effects::home(ad);
        return true;
    }
    match handle_keyboard(
        &mut ad.wallet.seeds.pp_input,
        boot_display,
        x,
        y,
        KeyboardPolicy::COMPACT_TEXT,
    ) {
        KeyboardAction::Submitted => {
            complete_filename(ad);
            true
        }
        KeyboardAction::Edited | KeyboardAction::None => false,
    }
}

fn complete_filename(ad: &mut AppData) {
    if ad.wallet.seeds.pp_input.len == 0 {
        let hex = b"0123456789ABCDEF";
        for index in 0..5usize {
            if index + 4 < ad.qr.outgoing.covenant_backup_length {
                ad.wallet.seeds.pp_input.buf[index] =
                    hex[(ad.qr.outgoing.buffer[4 + index] >> 4) as usize];
            }
        }
        ad.wallet.seeds.pp_input.len = 5;
    }
    ad.storage.browser.file_list[0] = crate::runtime::interactions::sd::build_filename_83(
        &ad.wallet.seeds.pp_input.buf,
        ad.wallet.seeds.pp_input.len,
        b"COV",
    );
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MainMenu));
    crate::runtime::effects::redraw(ad);
}
