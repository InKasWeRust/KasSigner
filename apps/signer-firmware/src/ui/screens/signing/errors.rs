// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Shared error presentation surface.
//!
//! Error screens deliberately share one renderer. The action shown on-screen
//! must match the action the input layer actually accepts: persistent
//! `Rejected` and recoverable-modal errors expose OK, stable-state faults expose
//! Back, timed transient feedback exposes no fake button, and fatal errors stay
//! fail-closed with no actionable control.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_TEXT,
    COLOR_TEXT_DIM, CornerRadii, DrawTarget, Drawable, Line, Point, Primitive,
    PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_body, draw_lato_title,
    draw_oswald_header, measure_body, measure_header, measure_title, sound,
    KASPA_TEAL,
};

#[derive(Clone, Copy)]
enum ErrorAction {
    None,
    Back,
    Acknowledge { ready: bool, label: &'static str },
}

const ERROR_TEXT_WIDTH: i32 = 280;
const ERROR_MAX_LINES: usize = 7;
const ERROR_LINE_Y: [i32; ERROR_MAX_LINES] = [62, 79, 96, 113, 130, 147, 164];

#[derive(Clone, Copy)]
struct WrappedErrorText<'a> {
    lines: [Option<&'a str>; ERROR_MAX_LINES],
    count: usize,
}

fn wrap_error_text(message: &str) -> WrappedErrorText<'_> {
    let mut lines = [None; ERROR_MAX_LINES];
    let mut count = 0usize;
    let mut remaining = message.trim();
    while !remaining.is_empty() && count < ERROR_MAX_LINES {
        if measure_body(remaining) <= ERROR_TEXT_WIDTH {
            lines[count] = Some(remaining);
            count += 1;
            remaining = "";
            break;
        }
        let split = body_wrap_split(remaining);
        let (line, rest) = remaining.split_at(split);
        lines[count] = Some(line.trim_end());
        count += 1;
        remaining = rest.trim_start();
    }
    // Seven body-font lines fit above the action zone and cover every current
    // user-facing error string. Keep a hard assertion in debug/test builds so
    // future text cannot silently regress to clipping.
    debug_assert!(remaining.is_empty(), "error message exceeds wrapped display capacity");
    WrappedErrorText { lines, count }
}

fn body_wrap_split(text: &str) -> usize {
    let mut last_boundary = 0usize;
    let mut last_space = None;
    for (index, ch) in text.char_indices().skip(1) {
        if measure_body(&text[..index]) > ERROR_TEXT_WIDTH {
            break;
        }
        last_boundary = index;
        if ch == ' ' {
            last_space = Some(index);
        }
    }
    last_space.or_else(|| (last_boundary > 0).then_some(last_boundary)).unwrap_or_else(|| {
        text.char_indices().nth(1).map(|(index, _)| index).unwrap_or(text.len())
    })
}


impl<'a> BootDisplay<'a> {
    fn draw_error_surface(
        &mut self,
        primary: &str,
        secondary: Option<&str>,
        action: ErrorAction,
    ) {
        sound::stop_ticking();
        self.display.clear(COLOR_BG).ok();

        let title_width = measure_header("ERROR");
        draw_oswald_header(
            &mut self.display,
            "ERROR",
            (320 - title_width) / 2,
            30,
            COLOR_DANGER,
        );
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
            .draw(&mut self.display)
            .ok();

        let primary_lines = wrap_error_text(primary);
        let secondary_lines = secondary.map(wrap_error_text);
        let total_lines = primary_lines.count
            + secondary_lines.as_ref().map_or(0, |lines| lines.count);
        debug_assert!(total_lines <= ERROR_MAX_LINES, "error surface exceeds display line budget");

        let mut line_index = 0usize;
        for line in primary_lines.lines.iter().flatten() {
            if line_index >= ERROR_MAX_LINES { break; }
            let width = measure_body(line);
            draw_lato_body(
                &mut self.display,
                line,
                (320 - width) / 2,
                ERROR_LINE_Y[line_index],
                COLOR_TEXT,
            );
            line_index += 1;
        }
        if let Some(lines) = secondary_lines {
            for line in lines.lines.iter().flatten() {
                if line_index >= ERROR_MAX_LINES { break; }
                let width = measure_body(line);
                draw_lato_body(
                    &mut self.display,
                    line,
                    (320 - width) / 2,
                    ERROR_LINE_Y[line_index],
                    COLOR_TEXT_DIM,
                );
                line_index += 1;
            }
        }

        match action {
            ErrorAction::None => {}
            ErrorAction::Back => self.draw_back_button(),
            ErrorAction::Acknowledge { ready, label } => self.draw_error_acknowledge(ready, label),
        }
    }

    fn draw_error_acknowledge(&mut self, ready: bool, action_label: &'static str) {
        let rect = Rectangle::new(
            Point::new(
                i32::from(crate::ui::layout::ERROR_OK_ZONE.x),
                i32::from(crate::ui::layout::ERROR_OK_ZONE.y),
            ),
            Size::new(
                u32::from(crate::ui::layout::ERROR_OK_ZONE.w),
                u32::from(crate::ui::layout::ERROR_OK_ZONE.h),
            ),
        );
        let corners = CornerRadii::new(Size::new(6, 6));
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
            .draw(&mut self.display)
            .ok();
        RoundedRectangle::new(rect, corners)
            .into_styled(PrimitiveStyle::with_stroke(
                if ready { KASPA_TEAL } else { COLOR_CARD_BORDER },
                1,
            ))
            .draw(&mut self.display)
            .ok();
        let label = if ready { action_label } else { "PLEASE WAIT" };
        let label_width = measure_title(label);
        draw_lato_title(
            &mut self.display,
            label,
            (320 - label_width) / 2,
            205,
            if ready { KASPA_TEAL } else { COLOR_TEXT_DIM },
        );
    }

    /// Persistent Rejected state: OK is a real touch target handled by the
    /// production input router.
    pub fn draw_rejected_screen(&mut self, reason: &str) {
        self.draw_error_surface(
            reason,
            None,
            ErrorAction::Acknowledge { ready: true, label: "OK" },
        );
    }

    /// Stable-state fault: Back is the only action advertised because the
    /// underlying state owns normal navigation rather than ERROR_OK_ZONE.
    pub fn draw_error_back_screen(&mut self, reason: &str) {
        self.draw_error_surface(reason, None, ErrorAction::Back);
    }

    /// Timed controller feedback: do not draw an OK button while input is
    /// synchronously blocked by the controller hold.
    pub fn draw_transient_error_screen(&mut self, reason: &str) {
        self.draw_error_surface(reason, None, ErrorAction::None);
    }

    /// Short entropy-generation failure displayed during a timed retry path.
    pub fn draw_entropy_error_screen(&mut self, reason: &str, hint: &str) {
        self.draw_error_surface(reason, Some(hint), ErrorAction::None);
    }

    /// Two-line stable-state error. Back is intentionally the sole action.
    pub fn draw_tx_error_screen(&mut self, line1: &str, line2: &str) {
        self.draw_error_surface(line1, Some(line2), ErrorAction::Back);
    }

    /// Recoverable modal. OK is disabled until the retry-delay boundary is
    /// reached, then becomes the same shared ERROR_OK_ZONE action as Rejected.
    pub fn draw_recoverable_error_screen(&mut self, message: &str, code: &str, ready: bool) {
        self.draw_recoverable_error_screen_with_action(message, code, ready, "OK");
    }

    /// Recoverable modal with an action label that describes the actual stable
    /// navigation target (for example HOME after a scanner rejection).
    pub fn draw_recoverable_error_screen_with_action(
        &mut self,
        message: &str,
        code: &str,
        ready: bool,
        action_label: &'static str,
    ) {
        self.draw_error_surface(
            message,
            Some(code),
            ErrorAction::Acknowledge { ready, label: action_label },
        );
    }

    /// Fatal errors are intentionally non-interactive and cannot imply that OK
    /// or Back will recover the device.
    pub fn draw_fatal_error_screen(&mut self, message: &str, code: &str) {
        self.draw_error_surface(message, Some(code), ErrorAction::None);
    }
}
