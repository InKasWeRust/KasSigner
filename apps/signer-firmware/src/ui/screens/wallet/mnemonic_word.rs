// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::super::{
    BootDisplay,
    COLOR_HINT,
    COLOR_TEXT,
    Drawable,
    KASPA_TEAL,
    Line,
    Point,
    Primitive,
    PrimitiveStyle,
    draw_lato_hint,
    draw_lato_title,
    draw_oswald_header,
    draw_rubik_big,
    measure_big,
    measure_header,
    measure_hint,
    measure_title};

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_mnemonic_word(
        &mut self,
        title_prefix: &str,
        word_num: u8,
        total_words: u8,
        word: &str,
    ) {
        self.clear_keep_nav();

        let mut title: heapless::String<24> = heapless::String::new();
        core::fmt::Write::write_fmt(
            &mut title,
            format_args!("{} {}/{}", title_prefix, word_num + 1, total_words),
        )
        .ok();
        let title_width = measure_header(title.as_str());
        draw_oswald_header(
            &mut self.display,
            title.as_str(),
            (320 - title_width) / 2,
            40,
            COLOR_TEXT,
        );

        Line::new(Point::new(60, 55), Point::new(260, 55))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display)
            .ok();

        let mut number: heapless::String<8> = heapless::String::new();
        core::fmt::Write::write_fmt(&mut number, format_args!("#{}", word_num + 1)).ok();
        let number_width = measure_title(number.as_str());
        draw_lato_title(
            &mut self.display,
            number.as_str(),
            (320 - number_width) / 2,
            100,
            KASPA_TEAL,
        );

        let word_width = measure_big(word);
        draw_rubik_big(
            &mut self.display,
            word,
            (320 - word_width) / 2,
            135,
            COLOR_TEXT,
        );

        const HINT: &str = "Write it down! Tap for next.";
        let hint_width = measure_hint(HINT);
        draw_lato_hint(
            &mut self.display,
            HINT,
            (320 - hint_width) / 2,
            210,
            COLOR_HINT,
        );
    }
}
