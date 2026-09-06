//! Pure keyboard layout, hit testing, and suggestion selection.

pub const SCREEN_WIDTH: i32 = 320;
pub const KEY_CORNER: u32 = 4;
pub const KEY_WIDTH: u32 = 33;
pub const KEY_GAP: i32 = 2;
pub const DELETE_WIDTH: u32 = 50;
pub const OK_WIDTH: u32 = 50;
pub const ARROW_WIDTH: u32 = 38;

const FULL_KEY_HEIGHT: u32 = 34;
const COMPACT_KEY_HEIGHT: u32 = 28;
const FULL_ROW_Y: [i32; 3] = [80, 118, 156];
const COMPACT_ROW_Y: [i32; 3] = [96, 130, 164];
const FULL_ACTION_Y: i32 = 194;
const COMPACT_ACTION_Y: i32 = 196;
const FULL_ACTION_HEIGHT: u32 = 38;
const COMPACT_ACTION_HEIGHT: u32 = 32;
const NUMERIC_PAGE: u8 = 98;
const HEX_PAGE: u8 = 99;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardMode {
    Alpha,
    Full,
    Hex,
    Numeric,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAction {
    None,
    Char(u8),
    Backspace,
    Space,
    Ok,
    Page,
    CursorLeft,
    CursorRight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardLayout {
    pub row_y: [i32; 3],
    pub key_height: u32,
    pub action_y: i32,
    pub action_height: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionRow {
    pub left_arrow_x: i32,
    pub space_x: i32,
    pub space_width: i32,
    pub right_arrow_x: i32,
    pub ok_x: i32,
}

pub const fn keyboard_layout(mode: KeyboardMode) -> KeyboardLayout {
    match mode {
        KeyboardMode::Alpha => KeyboardLayout {
            row_y: COMPACT_ROW_Y,
            key_height: COMPACT_KEY_HEIGHT,
            action_y: COMPACT_ACTION_Y,
            action_height: COMPACT_ACTION_HEIGHT,
        },
        KeyboardMode::Full | KeyboardMode::Hex | KeyboardMode::Numeric => KeyboardLayout {
            row_y: FULL_ROW_Y,
            key_height: FULL_KEY_HEIGHT,
            action_y: FULL_ACTION_Y,
            action_height: FULL_ACTION_HEIGHT,
        },
    }
}

pub const fn action_row() -> ActionRow {
    let left_arrow_x = 2 + DELETE_WIDTH as i32 + KEY_GAP;
    let space_width = SCREEN_WIDTH
        - 4
        - DELETE_WIDTH as i32
        - KEY_GAP
        - ARROW_WIDTH as i32
        - KEY_GAP
        - ARROW_WIDTH as i32
        - KEY_GAP
        - OK_WIDTH as i32
        - KEY_GAP;
    let space_x = left_arrow_x + ARROW_WIDTH as i32 + KEY_GAP;
    let right_arrow_x = space_x + space_width + KEY_GAP;
    let ok_x = right_arrow_x + ARROW_WIDTH as i32 + KEY_GAP;
    ActionRow {
        left_arrow_x,
        space_x,
        space_width,
        right_arrow_x,
        ok_x,
    }
}

pub fn rows_for_mode(mode: KeyboardMode, page: u8) -> [&'static [u8]; 3] {
    rows_for_page(match mode {
        KeyboardMode::Full => page,
        KeyboardMode::Hex => HEX_PAGE,
        KeyboardMode::Numeric => NUMERIC_PAGE,
        KeyboardMode::Alpha => 0,
    })
}

pub const fn display_page(mode: KeyboardMode, page: u8) -> u8 {
    match mode {
        KeyboardMode::Full => page,
        KeyboardMode::Hex => HEX_PAGE,
        KeyboardMode::Numeric => NUMERIC_PAGE,
        KeyboardMode::Alpha => 0,
    }
}

pub fn row_start(key_count: usize) -> i32 {
    let width = key_count as i32 * (KEY_WIDTH as i32 + KEY_GAP) - KEY_GAP;
    (SCREEN_WIDTH - width) / 2
}

pub fn third_row_start(key_count: usize) -> i32 {
    let letter_width = key_count as i32 * (KEY_WIDTH as i32 + KEY_GAP) - KEY_GAP;
    let total = KEY_WIDTH as i32 + KEY_GAP + letter_width;
    (SCREEN_WIDTH - total) / 2
}

pub const fn page_label(page: u8) -> &'static str {
    match page {
        0 => "Aa",
        1 => "#",
        2 => "@",
        _ => "ab",
    }
}

pub const fn is_active(character: u8, mode: KeyboardMode) -> bool {
    if character == b' ' {
        return false;
    }
    match mode {
        KeyboardMode::Full => true,
        KeyboardMode::Alpha => character.is_ascii_lowercase(),
        KeyboardMode::Hex => character.is_ascii_digit() || (character >= b'A' && character <= b'F'),
        KeyboardMode::Numeric => character.is_ascii_digit(),
    }
}

pub const fn page_active(mode: KeyboardMode) -> bool {
    matches!(mode, KeyboardMode::Full)
}

pub const fn space_active(mode: KeyboardMode) -> bool {
    matches!(mode, KeyboardMode::Full)
}

pub fn hit_test(x: u16, y: u16, mode: KeyboardMode, page: u8) -> KeyAction {
    let x = i32::from(x);
    let y = i32::from(y);
    let layout = keyboard_layout(mode);
    let rows = rows_for_mode(mode, page);

    top_rows_hit_test(x, y, layout, rows, mode)
        .or_else(|| third_row_hit_test(x, y, layout, rows[2], mode))
        .unwrap_or_else(|| action_hit_test(x, y, layout, mode))
}

fn top_rows_hit_test(
    x: i32,
    y: i32,
    layout: KeyboardLayout,
    rows: [&[u8]; 3],
    mode: KeyboardMode,
) -> Option<KeyAction> {
    (0..2usize).find_map(|row_index| {
        in_row(y, layout, row_index)
            .then(|| character_action(x, rows[row_index], row_start(rows[row_index].len()), mode))
            .flatten()
    })
}

fn third_row_hit_test(
    x: i32,
    y: i32,
    layout: KeyboardLayout,
    row: &[u8],
    mode: KeyboardMode,
) -> Option<KeyAction> {
    if !in_row(y, layout, 2) {
        return None;
    }
    let start_x = third_row_start(row.len());
    if x >= start_x && x < start_x + KEY_WIDTH as i32 {
        return Some(if page_active(mode) {
            KeyAction::Page
        } else {
            KeyAction::None
        });
    }
    character_action(x, row, start_x + KEY_WIDTH as i32 + KEY_GAP, mode)
}

fn in_row(y: i32, layout: KeyboardLayout, row: usize) -> bool {
    y >= layout.row_y[row] && y < layout.row_y[row] + layout.key_height as i32
}

fn action_hit_test(x: i32, y: i32, layout: KeyboardLayout, mode: KeyboardMode) -> KeyAction {
    if y < layout.action_y - 4 {
        return KeyAction::None;
    }
    let row = action_row();
    if x < row.left_arrow_x {
        KeyAction::Backspace
    } else if x < row.left_arrow_x + ARROW_WIDTH as i32 {
        KeyAction::CursorLeft
    } else if x >= row.space_x && x < row.space_x + row.space_width {
        if space_active(mode) {
            KeyAction::Space
        } else {
            KeyAction::None
        }
    } else if x >= row.right_arrow_x && x < row.right_arrow_x + ARROW_WIDTH as i32 {
        KeyAction::CursorRight
    } else if x >= row.ok_x {
        KeyAction::Ok
    } else {
        KeyAction::None
    }
}

fn character_action(x: i32, row: &[u8], start_x: i32, mode: KeyboardMode) -> Option<KeyAction> {
    row.iter()
        .copied()
        .enumerate()
        .find_map(|(column, character)| {
            let key_x = start_x + column as i32 * (KEY_WIDTH as i32 + KEY_GAP);
            (x >= key_x && x < key_x + KEY_WIDTH as i32).then(|| {
                if is_active(character, mode) {
                    KeyAction::Char(character)
                } else {
                    KeyAction::None
                }
            })
        })
}

pub fn suggestion_hit_test(
    x: u16,
    y: u16,
    suggestion_count: u8,
    suggestions: &[u16],
) -> Option<u16> {
    if !(72..=96).contains(&y) || suggestion_count <= 1 {
        return None;
    }
    (0..usize::from(suggestion_count.min(3)).min(suggestions.len())).find_map(|index| {
        let left = 4 + index as u16 * 106;
        (x >= left && x < left + 102).then_some(suggestions[index])
    })
}

fn rows_for_page(page: u8) -> [&'static [u8]; 3] {
    match page {
        0 => [b"abcdefghi", b"jklmnopqr", b"stuvwxyz"],
        1 => [b"ABCDEFGHI", b"JKLMNOPQR", b"STUVWXYZ"],
        2 => [b"123456789", b"0!@#$%^&*", b"()-_=+.,"],
        3 => [b"?/\\|~`<>;", b"\"'{}[]:-!", b"@#$%^&*+"],
        NUMERIC_PAGE => [b"123456789", b"    0    ", b"         "],
        _ => [b"123456789", b" 0ABCDEF ", b"        "],
    }
}
