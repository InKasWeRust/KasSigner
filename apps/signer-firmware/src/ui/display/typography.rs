// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use embedded_graphics::{pixelcolor::Rgb565, prelude::DrawTarget};

use crate::ui::prop_fonts;

/// Return a prefix containing at most `max_chars` Unicode scalar values.
/// The returned slice always ends on a UTF-8 character boundary.
pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> &str {
    text.char_indices()
        .nth(max_chars)
        .map_or(text, |(byte_index, _)| &text[..byte_index])
}

pub(crate) fn draw_lato_title<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::LATO_BOLD_18_WIDTHS,
        &prop_fonts::LATO_BOLD_18_OFFSETS,
        &prop_fonts::LATO_BOLD_18_DATA,
        prop_fonts::LATO_BOLD_18_HEIGHT,
        prop_fonts::LATO_BOLD_18_ASCENT,
        prop_fonts::LATO_BOLD_18_FIRST,
        prop_fonts::LATO_BOLD_18_LAST,
    )
}

pub(crate) fn draw_lato_title_opaque<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    fg: Rgb565,
    bg: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text_opaque(
        d,
        text,
        x,
        y,
        fg,
        bg,
        &prop_fonts::LATO_BOLD_18_WIDTHS,
        &prop_fonts::LATO_BOLD_18_OFFSETS,
        &prop_fonts::LATO_BOLD_18_DATA,
        prop_fonts::LATO_BOLD_18_HEIGHT,
        prop_fonts::LATO_BOLD_18_ASCENT,
        prop_fonts::LATO_BOLD_18_FIRST,
        prop_fonts::LATO_BOLD_18_LAST,
    )
}

pub(crate) fn draw_lato_body<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::LATO_15_WIDTHS,
        &prop_fonts::LATO_15_OFFSETS,
        &prop_fonts::LATO_15_DATA,
        prop_fonts::LATO_15_HEIGHT,
        prop_fonts::LATO_15_ASCENT,
        prop_fonts::LATO_15_FIRST,
        prop_fonts::LATO_15_LAST,
    )
}

pub(crate) fn draw_lato_18<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::LATO_18_WIDTHS,
        &prop_fonts::LATO_18_OFFSETS,
        &prop_fonts::LATO_18_DATA,
        prop_fonts::LATO_18_HEIGHT,
        prop_fonts::LATO_18_ASCENT,
        prop_fonts::LATO_18_FIRST,
        prop_fonts::LATO_18_LAST,
    )
}

pub(crate) fn draw_lato_22<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::LATO_22_WIDTHS,
        &prop_fonts::LATO_22_OFFSETS,
        &prop_fonts::LATO_22_DATA,
        prop_fonts::LATO_22_HEIGHT,
        prop_fonts::LATO_22_ASCENT,
        prop_fonts::LATO_22_FIRST,
        prop_fonts::LATO_22_LAST,
    )
}

pub(crate) fn draw_lato_22_opaque<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    fg: Rgb565,
    bg: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text_opaque(
        d,
        text,
        x,
        y,
        fg,
        bg,
        &prop_fonts::LATO_22_WIDTHS,
        &prop_fonts::LATO_22_OFFSETS,
        &prop_fonts::LATO_22_DATA,
        prop_fonts::LATO_22_HEIGHT,
        prop_fonts::LATO_22_ASCENT,
        prop_fonts::LATO_22_FIRST,
        prop_fonts::LATO_22_LAST,
    )
}

pub(crate) fn draw_lato_hint<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::LATO_12_WIDTHS,
        &prop_fonts::LATO_12_OFFSETS,
        &prop_fonts::LATO_12_DATA,
        prop_fonts::LATO_12_HEIGHT,
        prop_fonts::LATO_12_ASCENT,
        prop_fonts::LATO_12_FIRST,
        prop_fonts::LATO_12_LAST,
    )
}

pub(crate) fn draw_oswald_header<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    let width = measure_header(text);
    let centered_x = (320 - width) / 2;
    let x = if y <= 40 && x == centered_x {
        crate::ui::layout::nav_header_x(centered_x, width)
    } else {
        x
    };
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::OSWALD_BOLD_22_WIDTHS,
        &prop_fonts::OSWALD_BOLD_22_OFFSETS,
        &prop_fonts::OSWALD_BOLD_22_DATA,
        prop_fonts::OSWALD_BOLD_22_HEIGHT,
        prop_fonts::OSWALD_BOLD_22_ASCENT,
        prop_fonts::OSWALD_BOLD_22_FIRST,
        prop_fonts::OSWALD_BOLD_22_LAST,
    )
}

pub(crate) fn draw_rubik_big<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    text: &str,
    x: i32,
    y: i32,
    color: Rgb565,
) -> i32 {
    prop_fonts::draw_prop_text(
        d,
        text,
        x,
        y,
        color,
        &prop_fonts::RUBIK_BOLD_26_WIDTHS,
        &prop_fonts::RUBIK_BOLD_26_OFFSETS,
        &prop_fonts::RUBIK_BOLD_26_DATA,
        prop_fonts::RUBIK_BOLD_26_HEIGHT,
        prop_fonts::RUBIK_BOLD_26_ASCENT,
        prop_fonts::RUBIK_BOLD_26_FIRST,
        prop_fonts::RUBIK_BOLD_26_LAST,
    )
}
pub(crate) fn measure_title(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::LATO_BOLD_18_WIDTHS,
        prop_fonts::LATO_BOLD_18_FIRST,
        prop_fonts::LATO_BOLD_18_LAST,
        prop_fonts::LATO_BOLD_18_HEIGHT,
    )
}

pub(crate) fn measure_body(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::LATO_15_WIDTHS,
        prop_fonts::LATO_15_FIRST,
        prop_fonts::LATO_15_LAST,
        prop_fonts::LATO_15_HEIGHT,
    )
}

pub(crate) fn measure_18(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::LATO_18_WIDTHS,
        prop_fonts::LATO_18_FIRST,
        prop_fonts::LATO_18_LAST,
        prop_fonts::LATO_18_HEIGHT,
    )
}

pub(crate) fn measure_22(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::LATO_22_WIDTHS,
        prop_fonts::LATO_22_FIRST,
        prop_fonts::LATO_22_LAST,
        prop_fonts::LATO_22_HEIGHT,
    )
}

pub(crate) fn measure_header(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::OSWALD_BOLD_22_WIDTHS,
        prop_fonts::OSWALD_BOLD_22_FIRST,
        prop_fonts::OSWALD_BOLD_22_LAST,
        prop_fonts::OSWALD_BOLD_22_HEIGHT,
    )
}

pub(crate) fn measure_big(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::RUBIK_BOLD_26_WIDTHS,
        prop_fonts::RUBIK_BOLD_26_FIRST,
        prop_fonts::RUBIK_BOLD_26_LAST,
        prop_fonts::RUBIK_BOLD_26_HEIGHT,
    )
}
pub(crate) fn measure_hint(text: &str) -> i32 {
    prop_fonts::measure_prop_text(
        text,
        &prop_fonts::LATO_12_WIDTHS,
        prop_fonts::LATO_12_FIRST,
        prop_fonts::LATO_12_LAST,
        prop_fonts::LATO_12_HEIGHT,
    )
}
