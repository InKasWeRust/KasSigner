use crate::input::keyboard::{
    action_row, display_page, hit_test, keyboard_layout, page_label, row_start, rows_for_mode,
    suggestion_hit_test, third_row_start, KeyAction, KeyboardMode, ARROW_WIDTH, KEY_GAP, KEY_WIDTH,
};

fn center(start: i32) -> u16 {
    (start + KEY_WIDTH as i32 / 2) as u16
}

#[test]
fn keyboard_hits_characters_pages_and_disabled_keys() {
    let alpha = keyboard_layout(KeyboardMode::Alpha);
    let first = row_start(9);
    assert_eq!(
        hit_test(center(first), alpha.row_y[0] as u16, KeyboardMode::Alpha, 0),
        KeyAction::Char(b'a')
    );
    assert_eq!(
        hit_test(
            center(third_row_start(8)),
            alpha.row_y[2] as u16,
            KeyboardMode::Alpha,
            0
        ),
        KeyAction::None
    );

    let full = keyboard_layout(KeyboardMode::Full);
    assert_eq!(
        hit_test(
            center(third_row_start(8)),
            full.row_y[2] as u16,
            KeyboardMode::Full,
            0
        ),
        KeyAction::Page
    );
    assert_eq!(
        hit_test(
            center(row_start(9)),
            full.row_y[0] as u16,
            KeyboardMode::Full,
            1
        ),
        KeyAction::Char(b'A')
    );

    let hex = keyboard_layout(KeyboardMode::Hex);
    let second_row = rows_for_mode(KeyboardMode::Hex, 0)[1];
    let second_start = row_start(second_row.len());
    assert_eq!(
        hit_test(
            center(second_start),
            hex.row_y[1] as u16,
            KeyboardMode::Hex,
            0
        ),
        KeyAction::None
    );
    assert_eq!(
        hit_test(
            center(second_start + (KEY_WIDTH as i32 + KEY_GAP)),
            hex.row_y[1] as u16,
            KeyboardMode::Hex,
            0
        ),
        KeyAction::Char(b'0')
    );
}

#[test]
fn keyboard_action_row_is_half_open_and_mode_aware() {
    let row = action_row();
    let y = keyboard_layout(KeyboardMode::Full).action_y as u16;
    assert_eq!(hit_test(0, y, KeyboardMode::Full, 0), KeyAction::Backspace);
    assert_eq!(
        hit_test(row.left_arrow_x as u16, y, KeyboardMode::Full, 0),
        KeyAction::CursorLeft
    );
    assert_eq!(
        hit_test(row.space_x as u16, y, KeyboardMode::Full, 0),
        KeyAction::Space
    );
    assert_eq!(
        hit_test(row.space_x as u16, y, KeyboardMode::Alpha, 0),
        KeyAction::None
    );
    assert_eq!(
        hit_test(row.right_arrow_x as u16, y, KeyboardMode::Full, 0),
        KeyAction::CursorRight
    );
    assert_eq!(
        hit_test(row.ok_x as u16, y, KeyboardMode::Full, 0),
        KeyAction::Ok
    );
    assert_eq!(hit_test(319, 0, KeyboardMode::Full, 0), KeyAction::None);
}

#[test]
fn suggestions_require_multiple_candidates_and_respect_chip_gaps() {
    let values = [10, 20, 30];
    assert_eq!(suggestion_hit_test(4, 72, 3, &values), Some(10));
    assert_eq!(suggestion_hit_test(110, 96, 3, &values), Some(20));
    assert_eq!(suggestion_hit_test(216, 80, 9, &values), Some(30));
    assert_eq!(suggestion_hit_test(106, 80, 3, &values), None);
    assert_eq!(suggestion_hit_test(4, 71, 3, &values), None);
    assert_eq!(suggestion_hit_test(4, 80, 1, &values), None);
    assert_eq!(suggestion_hit_test(110, 80, 3, &[10]), None);
}

#[test]
fn keyboard_page_metadata_covers_every_mode_and_label() {
    assert_eq!(display_page(KeyboardMode::Full, 2), 2);
    assert_eq!(display_page(KeyboardMode::Hex, 2), 99);
    assert_eq!(display_page(KeyboardMode::Alpha, 2), 0);
    assert_eq!(page_label(0), "Aa");
    assert_eq!(page_label(1), "#");
    assert_eq!(page_label(2), "@");
    assert_eq!(page_label(3), "ab");
    assert_eq!(page_label(u8::MAX), "ab");
}

#[test]
fn keyboard_hit_testing_covers_third_row_letters_and_action_gaps() {
    let full = keyboard_layout(KeyboardMode::Full);
    let third = rows_for_mode(KeyboardMode::Full, 0)[2];
    let letters_start = third_row_start(third.len()) + KEY_WIDTH as i32 + KEY_GAP;
    assert_eq!(
        hit_test(
            center(letters_start),
            full.row_y[2] as u16,
            KeyboardMode::Full,
            0
        ),
        KeyAction::Char(b's'),
    );
    assert_eq!(
        hit_test(0, full.row_y[2] as u16, KeyboardMode::Full, 0),
        KeyAction::None,
    );

    let first_start = row_start(9);
    assert_eq!(
        hit_test(
            (first_start + KEY_WIDTH as i32) as u16,
            full.row_y[0] as u16,
            KeyboardMode::Full,
            0,
        ),
        KeyAction::None,
    );

    let row = action_row();
    let y = full.action_y as u16;
    assert_eq!(
        hit_test(
            (row.left_arrow_x + ARROW_WIDTH as i32) as u16,
            y,
            KeyboardMode::Full,
            0
        ),
        KeyAction::None,
    );
    assert_eq!(
        hit_test(
            (row.space_x + row.space_width) as u16,
            y,
            KeyboardMode::Full,
            0
        ),
        KeyAction::None,
    );
    assert_eq!(
        hit_test(
            (row.right_arrow_x + ARROW_WIDTH as i32) as u16,
            y,
            KeyboardMode::Full,
            0
        ),
        KeyAction::None,
    );
    assert_eq!(
        hit_test(0, (full.action_y - 5) as u16, KeyboardMode::Full, 0),
        KeyAction::None,
    );
}
