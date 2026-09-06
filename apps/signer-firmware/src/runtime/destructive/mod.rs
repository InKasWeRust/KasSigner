//! Event-loop-owned hold-to-confirm state for destructive actions.
//!
//! The touch transport is sampled exactly once by the outer event loop. This
//! module consumes that already-sampled state and therefore never polls I2C or
//! sleeps while waiting for a finger to move/release.

use crate::{
    hw::{display::BootDisplay, sound, touch::TouchState},
    runtime::data::AppData,
    ui::display::{
        COLOR_BG, COLOR_DANGER, COLOR_RED_BTN, COLOR_TEXT, COLOR_TEXT_DIM,
        draw_lato_body, draw_lato_hint, draw_lato_title, draw_oswald_header,
        measure_body, measure_header, measure_hint, measure_title,
    },
};
use embedded_graphics::{
    geometry::Size,
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{CornerRadii, Line, PrimitiveStyle, Rectangle, RoundedRectangle},
};
use esp_hal::{Blocking, i2c::master::I2c, time::Instant};

const HOLD_MILLIS: u64 = 4_000;
const PROGRESS_STEPS: u8 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DestructiveAction {
    None,
    DeleteSeed,
    DeleteSdFile,
    FormatSd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TouchRect {
    pub(crate) left: u16,
    pub(crate) top: u16,
    pub(crate) right: u16,
    pub(crate) bottom: u16,
}

impl TouchRect {
    pub(crate) const fn new(left: u16, top: u16, right: u16, bottom: u16) -> Self {
        Self { left, top, right, bottom }
    }

    pub(crate) fn contains(self, x: u16, y: u16) -> bool {
        (self.left..=self.right).contains(&x) && (self.top..=self.bottom).contains(&y)
    }
}

pub(crate) fn begin(ad: &mut AppData, action: DestructiveAction) {
    let hold = &mut ad.runtime.destructive;
    hold.action = action;
    hold.awaiting_release = true;
    hold.started_at_ms = 0;
    hold.progress_step = 0;
    hold.prompt_drawn = false;
    ad.runtime.needs_redraw = false;
}

/// Service one destructive-confirmation iteration using the touch sample already
/// collected by the event loop. Returns true while the modal owns this sample.
#[inline(never)]
pub(crate) fn service_step(
    touch: TouchState,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
) -> bool {
    let action = ad.runtime.destructive.action;
    if action == DestructiveAction::None {
        return false;
    }
    if !ad.runtime.destructive.prompt_drawn {
        draw_prompt(display, action);
        ad.runtime.destructive.prompt_drawn = true;
    }
    if ad.runtime.destructive.awaiting_release {
        if matches!(touch, TouchState::NoTouch) {
            ad.runtime.destructive.awaiting_release = false;
        }
        return true;
    }
    service_active_hold(touch, ad, display, delay, i2c, liveness, action);
    true
}

fn service_active_hold(
    touch: TouchState,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
    action: DestructiveAction,
) {
    match touch {
        TouchState::One(point) if is_cancel(action, point.x, point.y) => {
            cancel(ad, action);
        }
        TouchState::One(point) if confirm_rect(action).contains(point.x, point.y) => {
            advance_hold(ad, display, delay, i2c, liveness, action);
        }
        TouchState::One(_) if ad.runtime.destructive.started_at_ms != 0 => cancel(ad, action),
        TouchState::NoTouch if ad.runtime.destructive.started_at_ms != 0 => cancel(ad, action),
        _ => {}
    }
}

fn advance_hold(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
    action: DestructiveAction,
) {
    let now = now_millis();
    if ad.runtime.destructive.started_at_ms == 0 {
        ad.runtime.destructive.started_at_ms = now.max(1);
    }
    let elapsed = now.saturating_sub(ad.runtime.destructive.started_at_ms);
    let step = ((elapsed.saturating_mul(u64::from(PROGRESS_STEPS))) / HOLD_MILLIS)
        .min(u64::from(PROGRESS_STEPS)) as u8;
    if step != ad.runtime.destructive.progress_step {
        ad.runtime.destructive.progress_step = step;
        draw_progress(display, action, step, PROGRESS_STEPS);
    }
    if elapsed >= HOLD_MILLIS {
        complete(ad, display, delay, i2c, liveness, action);
    }
}

fn complete(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
    action: DestructiveAction,
) {
    clear(ad);
    execute(action, ad, display, delay, i2c, liveness);
}

fn execute(
    action: DestructiveAction,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
) {
    match action {
        DestructiveAction::DeleteSeed => {
            if crate::services::destructive::delete_seed(ad) {
                sound::warning();
            }
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        }
        DestructiveAction::DeleteSdFile => {
            let return_state = ad.storage.confirmation.delete_return;
            display.draw_saving_screen("Deleting...");
            let success = crate::services::destructive::delete_sd_file(ad, delay, i2c);
            sound::stop_ticking();
            if success {
                display.draw_success_screen("Backup deleted");
                sound::success();
                delay.delay_millis(1_500);
            } else {
                display.draw_transient_error_screen("Delete failed");
                sound::beep_error();
                delay.delay_millis(2_000);
            }
            ad.storage.confirmation.delete_return = crate::runtime::navigation::continuation!(MainMenu);
            crate::runtime::effects::continue_to(ad, return_state);
        }
        DestructiveAction::FormatSd => {
            display.draw_sdcard_formatting();
            match crate::services::destructive::format_sd(i2c, delay, liveness) {
                crate::services::destructive::FormatSdOutcome::Complete => {
                    display.draw_sdcard_format_done(true);
                    sound::success();
                    delay.delay_millis(3_000);
                    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings));
                }
                crate::services::destructive::FormatSdOutcome::Failed => {
                    crate::runtime::presentation::show_recoverable_error_to(
                        ad,
                        crate::runtime::input::AppState::SdCardSettings,
                        "SD format failed",
                        "SD-FMT-02",
                        0,
                    );
                }
            }
        }
        DestructiveAction::None => return,
    }
    crate::runtime::effects::redraw(ad);
}

fn draw_prompt(display: &mut BootDisplay<'_>, action: DestructiveAction) {
    match action {
        DestructiveAction::FormatSd => draw_format_warning(display),
        DestructiveAction::DeleteSeed | DestructiveAction::DeleteSdFile => {
            draw_hold_button(display, "HOLD 4s");
        }
        DestructiveAction::None => {}
    }
}

fn draw_progress(
    display: &mut BootDisplay<'_>,
    action: DestructiveAction,
    step: u8,
    total_steps: u8,
) {
    let (left, top, width, height) = match action {
        DestructiveAction::FormatSd => (60, 180, 200u32, 24u32),
        _ => (170, 190, 120u32, 20u32),
    };
    let fill = u32::from(step).saturating_mul(width) / u32::from(total_steps.max(1));
    if fill == 0 {
        return;
    }
    Rectangle::new(Point::new(left, top), Size::new(fill.min(width), height))
        .into_styled(PrimitiveStyle::with_fill(Rgb565::new(0b11111, 0, 0)))
        .draw(&mut display.display)
        .ok();
}

fn draw_hold_button(display: &mut BootDisplay<'_>, label: &str) {
    let rectangle = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
    RoundedRectangle::new(rectangle, CornerRadii::new(Size::new(8, 8)))
        .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
        .draw(&mut display.display)
        .ok();
    let width = measure_title(label);
    draw_lato_title(&mut display.display, label, 170 + (120 - width) / 2, 212, COLOR_TEXT);
}

fn draw_format_warning(display: &mut BootDisplay<'_>) {
    display.display.clear(COLOR_BG).ok();
    let header_width = measure_header("WARNING");
    draw_oswald_header(
        &mut display.display,
        "WARNING",
        (320 - header_width) / 2,
        30,
        COLOR_DANGER,
    );
    Line::new(Point::new(20, 40), Point::new(300, 40))
        .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 1))
        .draw(&mut display.display)
        .ok();
    centered_title(display, "ALL DATA WILL BE LOST", 80, COLOR_DANGER);
    centered_body(display, "This will erase the entire", 110);
    centered_body(display, "SD card. This is permanent.", 130);
    let rectangle = Rectangle::new(Point::new(50, 170), Size::new(220, 44));
    RoundedRectangle::new(rectangle, CornerRadii::new(Size::new(8, 8)))
        .into_styled(PrimitiveStyle::with_fill(COLOR_DANGER))
        .draw(&mut display.display)
        .ok();
    centered_title(display, "HOLD 4s TO FORMAT", 200, COLOR_BG);
    let hint = "Release or Back to cancel";
    let hint_width = measure_hint(hint);
    draw_lato_hint(
        &mut display.display,
        hint,
        (320 - hint_width) / 2,
        232,
        COLOR_TEXT_DIM,
    );
    display.draw_back_button();
}

fn centered_title(display: &mut BootDisplay<'_>, text: &str, y: i32, color: Rgb565) {
    let width = measure_title(text);
    draw_lato_title(&mut display.display, text, (320 - width) / 2, y, color);
}

fn centered_body(display: &mut BootDisplay<'_>, text: &str, y: i32) {
    let width = measure_body(text);
    draw_lato_body(&mut display.display, text, (320 - width) / 2, y, COLOR_TEXT_DIM);
}

fn cancel(ad: &mut AppData, action: DestructiveAction) {
    clear(ad);
    match action {
        DestructiveAction::DeleteSeed => {
            ad.wallet.seeds.pending_delete_slot = 0xFF;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        }
        DestructiveAction::DeleteSdFile => {
            let return_state = ad.storage.confirmation.delete_return;
            ad.storage.confirmation.delete_return = crate::runtime::navigation::continuation!(MainMenu);
            crate::runtime::effects::continue_to(ad, return_state);
        }
        DestructiveAction::FormatSd => {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdCardSettings));
        }
        DestructiveAction::None => {}
    }
    ad.runtime.needs_redraw = true;
}

fn clear(ad: &mut AppData) {
    ad.runtime.destructive = crate::runtime::data::DestructiveHoldState::new();
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_fast_forward_active_hold(ad: &mut AppData) -> bool {
    let hold = &mut ad.runtime.destructive;
    if hold.action == DestructiveAction::None || hold.started_at_ms == 0 {
        return false;
    }
    // Workflow E2E can reach a destructive hold before the device has four
    // seconds of uptime. Backdating an Instant-derived millisecond counter then
    // saturates at zero and fails to advance the hold. Mark terminal progress
    // instead; the next still-held sample goes through the real completion and
    // destructive service path deterministically.
    hold.progress_step = PROGRESS_STEPS;
    true
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_service_step(
    touch: TouchState,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
) -> bool {
    let action = ad.runtime.destructive.action;
    if action == DestructiveAction::None {
        return false;
    }
    if cfg!(feature = "workflow-hil-auto") {
        return service_step(touch, ad, display, delay, i2c, liveness);
    }
    ad.runtime.destructive.prompt_drawn = true;
    if ad.runtime.destructive.awaiting_release {
        if matches!(touch, TouchState::NoTouch) {
            ad.runtime.destructive.awaiting_release = false;
        }
        return true;
    }
    workflow_service_active_hold(touch, ad, display, delay, i2c, liveness, action);
    true
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_service_active_hold(
    touch: TouchState,
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
    action: DestructiveAction,
) {
    match touch {
        TouchState::One(point) if is_cancel(action, point.x, point.y) => cancel(ad, action),
        TouchState::One(point) if confirm_rect(action).contains(point.x, point.y) => {
            workflow_advance_hold(ad, display, delay, i2c, liveness, action);
        }
        TouchState::One(_) if ad.runtime.destructive.started_at_ms != 0 => cancel(ad, action),
        TouchState::NoTouch if ad.runtime.destructive.started_at_ms != 0 => cancel(ad, action),
        _ => {}
    }
}

#[cfg(feature = "workflow-test-auto")]
fn workflow_advance_hold(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut I2c<'_, Blocking>,
    liveness: &mut dyn FnMut(),
    action: DestructiveAction,
) {
    if ad.runtime.destructive.progress_step == PROGRESS_STEPS {
        complete(ad, display, delay, i2c, liveness, action);
        return;
    }
    let now = now_millis();
    if ad.runtime.destructive.started_at_ms == 0 {
        ad.runtime.destructive.started_at_ms = now.max(1);
    }
    let elapsed = now.saturating_sub(ad.runtime.destructive.started_at_ms);
    ad.runtime.destructive.progress_step = ((elapsed.saturating_mul(u64::from(PROGRESS_STEPS))) / HOLD_MILLIS)
        .min(u64::from(PROGRESS_STEPS)) as u8;
    if elapsed >= HOLD_MILLIS {
        complete(ad, display, delay, i2c, liveness, action);
    }
}

fn confirm_rect(action: DestructiveAction) -> TouchRect {
    match action {
        DestructiveAction::FormatSd => TouchRect::new(50, 170, 270, 214),
        _ => TouchRect::new(170, 180, 290, 230),
    }
}

fn is_cancel(action: DestructiveAction, x: u16, y: u16) -> bool {
    match action {
        DestructiveAction::FormatSd => (x <= 52 && y <= 52) || (x >= 268 && y <= 52),
        _ => TouchRect::new(30, 180, 150, 230).contains(x, y),
    }
}

fn now_millis() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}
