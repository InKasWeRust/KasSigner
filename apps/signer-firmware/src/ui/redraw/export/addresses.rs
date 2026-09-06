use super::{display, draw_address, draw_address_qr};
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::ShowAddress => draw_address(ad, boot_display),
        AppState::ShowAddressQR => draw_address_qr(ad, boot_display),
        AppState::ExportPrivKeyIndex | AppState::AddrIndexPicker => {
            let input = core::str::from_utf8(
                &ad.wallet.addresses.input_buf[..ad.wallet.addresses.input_len as usize],
            ).unwrap_or("");
            boot_display.draw_addr_index_screen(input);
        }
        _ => return false,
    }
    true
}
