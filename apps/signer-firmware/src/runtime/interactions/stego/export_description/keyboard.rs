use crate::{
    hw::display,
    runtime::data::AppData,
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
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescChoice));
        return true;
    }

    match handle_keyboard(
        &mut ad.wallet.seeds.pp_input,
        boot_display,
        x,
        y,
        KeyboardPolicy::PASSPHRASE,
    ) {
        KeyboardAction::Submitted => return accept_description(ad),
        KeyboardAction::Edited | KeyboardAction::None => {}
    }
    false
}

fn accept_description(ad: &mut AppData) -> bool {
    let text = ad.wallet.seeds.pp_input.as_str();
    let copy_len = text.len().min(96);
    ad.stego.export_flow.jpeg_desc_buf[..copy_len]
        .copy_from_slice(&text.as_bytes()[..copy_len]);
    ad.stego.export_flow.jpeg_desc_len = copy_len;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescPreview));
    true
}
