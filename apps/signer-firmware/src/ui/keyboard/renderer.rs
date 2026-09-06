use embedded_graphics::image::Image;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{CornerRadii, PrimitiveStyle, Rectangle, RoundedRectangle};
use embedded_iconoir::icons::size24px;
use embedded_iconoir::prelude::*;

use crate::ui::display::*;

use signer_firmware_core::input::keyboard::{
    action_row, display_page, is_active, keyboard_layout, page_active, page_label, row_start,
    rows_for_mode, space_active, third_row_start, KeyboardMode, ARROW_WIDTH, DELETE_WIDTH,
    KEY_CORNER, KEY_GAP, KEY_WIDTH, OK_WIDTH,
};

const SHADOW_BG: Rgb565 = Rgb565::new(0b00010, 0b000100, 0b00010);
const SHADOW_BORDER: Rgb565 = Rgb565::new(0b00011, 0b000110, 0b00011);
const SHADOW_TEXT: Rgb565 = Rgb565::new(0b00110, 0b001100, 0b00110);

#[derive(Clone, Copy)]
struct ButtonStyle {
    fill: Rgb565,
    border: Rgb565,
    text: Rgb565,
    corner: CornerRadii,
}

pub fn draw_keyboard(
    display: &mut impl DrawTarget<Color = Rgb565>,
    mode: KeyboardMode,
    page: u8,
) {
    let key_corner = CornerRadii::new(Size::new(KEY_CORNER, KEY_CORNER));
    let button_corner = CornerRadii::new(Size::new(5, 5));
    let layout = keyboard_layout(mode);
    let shown_page = display_page(mode, page);
    let rows = rows_for_mode(mode, page);

    for row_index in 0..2usize {
        let row = rows[row_index];
        let start_x = row_start(row.len());
        for (column, &character) in row.iter().enumerate() {
            let x = start_x + column as i32 * (KEY_WIDTH as i32 + KEY_GAP);
            draw_character_key(
                display,
                x,
                layout.row_y[row_index],
                layout.key_height,
                character,
                mode,
                key_corner,
            );
        }
    }

    let third_row = rows[2];
    let third_start = third_row_start(third_row.len());
    draw_page_key(
        display,
        third_start,
        layout.row_y[2],
        layout.key_height,
        mode,
        shown_page,
        button_corner,
    );

    let letters_start = third_start + KEY_WIDTH as i32 + KEY_GAP;
    for (column, &character) in third_row.iter().enumerate() {
        let x = letters_start + column as i32 * (KEY_WIDTH as i32 + KEY_GAP);
        draw_character_key(
            display,
            x,
            layout.row_y[2],
            layout.key_height,
            character,
            mode,
            key_corner,
        );
    }

    draw_action_row(display, mode, layout.action_y, layout.action_height, button_corner);
}

fn draw_character_key(
    display: &mut impl DrawTarget<Color = Rgb565>,
    x: i32,
    y: i32,
    height: u32,
    character: u8,
    mode: KeyboardMode,
    corner: CornerRadii,
) {
    let (background, border, text) = if is_active(character, mode) {
        (COLOR_CARD, COLOR_CARD_BORDER, COLOR_TEXT)
    } else {
        (SHADOW_BG, SHADOW_BORDER, SHADOW_TEXT)
    };
    draw_key(
        display,
        Rectangle::new(Point::new(x, y), Size::new(KEY_WIDTH, height)),
        character,
        ButtonStyle { fill: background, border, text, corner },
    );
}

fn draw_page_key(
    display: &mut impl DrawTarget<Color = Rgb565>,
    x: i32,
    y: i32,
    height: u32,
    mode: KeyboardMode,
    page: u8,
    corner: CornerRadii,
) {
    let rectangle = Rectangle::new(Point::new(x, y), Size::new(KEY_WIDTH, height));
    if !page_active(mode) {
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_fill(SHADOW_BG))
            .draw(display)
            .ok();
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_stroke(SHADOW_BORDER, 1))
            .draw(display)
            .ok();
        return;
    }

    if page == 0 {
        draw_shift_icon(display, x, y, KEY_WIDTH, height, corner);
        return;
    }

    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
        .draw(display)
        .ok();
    let label = page_label(page);
    let width = measure_header(label);
    draw_oswald_header(
        display,
        label,
        x + (KEY_WIDTH as i32 - width) / 2,
        y + height as i32 - 8,
        KASPA_TEAL,
    );
}

fn draw_action_row(
    display: &mut impl DrawTarget<Color = Rgb565>,
    mode: KeyboardMode,
    y: i32,
    height: u32,
    corner: CornerRadii,
) {
    let row = action_row();
    draw_delete_icon(display, 2, y, DELETE_WIDTH, height, corner);
    draw_arrow_button(display, row.left_arrow_x, y, height, false, corner);

    if space_active(mode) {
        draw_button(
            display,
            Rectangle::new(
                Point::new(row.space_x, y),
                Size::new(row.space_width as u32, height),
            ),
            "SPACE",
            ButtonStyle {
                fill: COLOR_CARD,
                border: COLOR_CARD_BORDER,
                text: COLOR_TEXT_DIM,
                corner,
            },
        );
    } else {
        let rectangle = Rectangle::new(
            Point::new(row.space_x, y),
            Size::new(row.space_width as u32, height),
        );
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_fill(SHADOW_BG))
            .draw(display)
            .ok();
        RoundedRectangle::new(rectangle, corner)
            .into_styled(PrimitiveStyle::with_stroke(SHADOW_BORDER, 1))
            .draw(display)
            .ok();
        let width = measure_18("SPACE");
        draw_lato_18(
            display,
            "SPACE",
            row.space_x + (row.space_width - width) / 2,
            y + (height as i32 + 15) / 2,
            SHADOW_TEXT,
        );
    }

    draw_arrow_button(display, row.right_arrow_x, y, height, true, corner);
    draw_button(
        display,
        Rectangle::new(Point::new(row.ok_x, y), Size::new(OK_WIDTH, height)),
        "OK",
        ButtonStyle {
            fill: COLOR_GREEN_BTN,
            border: COLOR_GREEN_BTN,
            text: COLOR_TEXT,
            corner,
        },
    );
}

fn draw_arrow_button(
    display: &mut impl DrawTarget<Color = Rgb565>,
    x: i32,
    y: i32,
    height: u32,
    right: bool,
    corner: CornerRadii,
) {
    let rectangle = Rectangle::new(Point::new(x, y), Size::new(ARROW_WIDTH, height));
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
        .draw(display)
        .ok();
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
        .draw(display)
        .ok();
    let icon_x = x + (ARROW_WIDTH as i32 - 24) / 2;
    let icon_y = y + (height as i32 - 24) / 2;
    if right {
        let icon = size24px::navigation::ArrowRight::new(KASPA_TEAL);
        Image::new(&icon, Point::new(icon_x, icon_y)).draw(display).ok();
    } else {
        let icon = size24px::navigation::ArrowLeft::new(KASPA_TEAL);
        Image::new(&icon, Point::new(icon_x, icon_y)).draw(display).ok();
    }
}

fn draw_key(
    display: &mut impl DrawTarget<Color = Rgb565>,
    rectangle: Rectangle,
    character: u8,
    style: ButtonStyle,
) {
    RoundedRectangle::new(rectangle, style.corner)
        .into_styled(PrimitiveStyle::with_fill(style.fill))
        .draw(display)
        .ok();
    RoundedRectangle::new(rectangle, style.corner)
        .into_styled(PrimitiveStyle::with_stroke(style.border, 1))
        .draw(display)
        .ok();
    let bytes = [character];
    if let Ok(text) = core::str::from_utf8(&bytes) {
        let text_width = measure_22(text);
        draw_lato_22(
            display,
            text,
            rectangle.top_left.x + (rectangle.size.width as i32 - text_width) / 2,
            rectangle.top_left.y + (rectangle.size.height as i32 + 19) / 2,
            style.text,
        );
    }
}

fn draw_button(
    display: &mut impl DrawTarget<Color = Rgb565>,
    rectangle: Rectangle,
    label: &str,
    style: ButtonStyle,
) {
    RoundedRectangle::new(rectangle, style.corner)
        .into_styled(PrimitiveStyle::with_fill(style.fill))
        .draw(display)
        .ok();
    if style.fill != style.border {
        RoundedRectangle::new(rectangle, style.corner)
            .into_styled(PrimitiveStyle::with_stroke(style.border, 1))
            .draw(display)
            .ok();
    }
    let label_width = measure_18(label);
    draw_lato_18(
        display,
        label,
        rectangle.top_left.x + (rectangle.size.width as i32 - label_width) / 2,
        rectangle.top_left.y + (rectangle.size.height as i32 + 15) / 2,
        style.text,
    );
}

fn draw_delete_icon(
    display: &mut impl DrawTarget<Color = Rgb565>,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    corner: CornerRadii,
) {
    use embedded_graphics::image::{Image, ImageRawLE};

    let rectangle = Rectangle::new(Point::new(x, y), Size::new(width, height));
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
        .draw(display)
        .ok();
    let icon_width = crate::ui::display::icon_data::ICON_DEL_W as i32;
    let icon_height = crate::ui::display::icon_data::ICON_DEL_H as i32;
    let icon_x = x + (width as i32 - icon_width) / 2;
    let icon_y = y + (height as i32 - icon_height) / 2;
    let raw: ImageRawLE<Rgb565> = ImageRawLE::new(
        crate::ui::display::icon_data::ICON_DEL,
        icon_width as u32,
    );
    Image::new(&raw, Point::new(icon_x, icon_y)).draw(display).ok();
}

fn draw_shift_icon(
    display: &mut impl DrawTarget<Color = Rgb565>,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    corner: CornerRadii,
) {
    use embedded_graphics::image::{Image, ImageRawLE};

    let rectangle = Rectangle::new(Point::new(x, y), Size::new(width, height));
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 2))
        .draw(display)
        .ok();
    let icon_width = crate::ui::display::icon_data::ICON_SHIFT_W as i32;
    let icon_height = crate::ui::display::icon_data::ICON_SHIFT_H as i32;
    let icon_x = x + (width as i32 - icon_width) / 2;
    let icon_y = y + (height as i32 - icon_height) / 2;
    let raw: ImageRawLE<Rgb565> = ImageRawLE::new(
        crate::ui::display::icon_data::ICON_SHIFT,
        icon_width as u32,
    );
    Image::new(&raw, Point::new(icon_x, icon_y)).draw(display).ok();
}
