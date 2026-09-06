use crate::{
    runtime::interactions::TouchInput,
    runtime::data::AppData,
    ui::keyboard::{hit_test, KeyAction, KeyboardMode},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EditAction {
    None,
    Edited,
    Submitted,
}

pub(super) fn edit(input: TouchInput, ad: &mut AppData, numeric: bool) -> EditAction {
    let mode = if numeric {
        KeyboardMode::Numeric
    } else {
        KeyboardMode::Full
    };
    let action = hit_test(input.x, input.y, mode, ad.wallet.seeds.pp_input.page);
    let pp = &mut ad.wallet.seeds.pp_input;
    match action {
        KeyAction::Char(character) => pp.push_char(character),
        KeyAction::Backspace => pp.backspace(),
        KeyAction::Page if !numeric => pp.next_page(),
        KeyAction::Space if !numeric => pp.push_char(b' '),
        KeyAction::CursorLeft => pp.cursor_left(),
        KeyAction::CursorRight => pp.cursor_right(),
        KeyAction::Ok => return EditAction::Submitted,
        _ => return EditAction::None,
    }
    EditAction::Edited
}

#[cfg(feature = "m5stack")]
pub(super) fn return_to_advanced(ad: &mut AppData) -> Option<bool> {
    ad.wallet.seeds.pp_input.reset();
    ad.storage.persistence.advanced.clear_pending();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedFeatures));
    Some(true)
}
