use super::super::{
    BootDisplay, COLOR_TEXT, COLOR_TEXT_DIM, draw_lato_body, draw_lato_title, measure_body,
    measure_title,
};

impl<'a> BootDisplay<'a> {
    pub(crate) fn draw_centered_wrapped_title(
        &mut self,
        message: &str,
        start_y: i32,
        line_step: i32,
        baseline_offset: i32,
        ellipsis_y: i32,
    ) {
        const CHARACTERS_PER_LINE: usize = 20;
        const MAX_LINES: usize = 3;
        let character_count = message.chars().count();
        for line_index in 0..MAX_LINES {
            let start_char = line_index * CHARACTERS_PER_LINE;
            if start_char >= character_count { break; }
            let end_char = (start_char + CHARACTERS_PER_LINE).min(character_count);
            let start = message.char_indices().nth(start_char).map(|(index, _)| index).unwrap_or(message.len());
            let end = message.char_indices().nth(end_char).map(|(index, _)| index).unwrap_or(message.len());
            let line = &message[start..end];
            let width = measure_title(line);
            draw_lato_title(
                &mut self.display,
                line,
                (320 - width) / 2,
                start_y + line_index as i32 * line_step + baseline_offset,
                COLOR_TEXT,
            );
        }
        if character_count > CHARACTERS_PER_LINE * MAX_LINES {
            let width = measure_body("...");
            draw_lato_body(
                &mut self.display,
                "...",
                (320 - width) / 2,
                ellipsis_y,
                COLOR_TEXT_DIM,
            );
        }
    }
}
