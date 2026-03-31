// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// handlers/settings.rs — Touch handlers for settings states
//
// Covers: SettingsMenu, DisplaySettings, SdCardSettings, About

use crate::log;
use crate::{app::data::AppData, hw::display, hw::sdcard, hw::sound, hw::touch};
use crate::ui::helpers::format_test_line;

#[cfg(not(feature = "silent"))]
/// Handle touch events for settings screens (display, audio, SD card, about).
#[inline(never)]
pub fn handle_settings_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    bb_card_type: &Option<sdcard::SdCardType>,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    #[allow(unused_assignments)]
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SettingsMenu => {
                        if is_back {
                            ad.settings_menu.reset();
                            ad.app.go_main_menu();
                        } else if page_up_zone.contains(x, y) && ad.settings_menu.can_page_up() {
                            ad.settings_menu.page_up();
                        } else if page_down_zone.contains(x, y) && ad.settings_menu.can_page_down() {
                            ad.settings_menu.page_down();
                        } else {
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.settings_menu.visible_to_absolute(slot);
                                    if abs < ad.settings_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                #[cfg(feature = "waveshare")]
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::DisplaySettings; }
                                    1 => { ad.app.state = crate::app::input::AppState::SdCardSettings; }
                                    2 => { ad.app.state = crate::app::input::AppState::About; }
                                    _ => {}
                                }
                                #[cfg(feature = "m5stack")]
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::DisplaySettings; }
                                    1 => { ad.app.state = crate::app::input::AppState::AudioSettings; }
                                    2 => { ad.app.state = crate::app::input::AppState::SdCardSettings; }
                                    3 => { ad.app.state = crate::app::input::AppState::About; }
                                    _ => {}
                                }
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::DisplaySettings => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SettingsMenu;
                            needs_redraw = true;
                        } else {
                            if x <= 68 && (70..=120).contains(&y) {
                                ad.brightness = (ad.brightness).saturating_sub(25);
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            } else if x >= 252 && (70..=120).contains(&y) {
                                ad.brightness = (ad.brightness).saturating_add(25).min(255);
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            } else if (70..=250).contains(&x) && (75..=115).contains(&y) {
                                let pct = ((x as u32 - 70) * 255 / 180).min(255) as u8;
                                ad.brightness = pct;
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            }
                            needs_redraw = true;
                        }
                    }
                    #[cfg(feature = "m5stack")]
                    crate::app::input::AppState::AudioSettings => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SettingsMenu;
                        } else {
                            if x <= 68 && (70..=120).contains(&y) {
                                ad.volume = (ad.volume).saturating_sub(25);
                                sound::set_volume(ad.volume);
                            } else if x >= 252 && (70..=120).contains(&y) {
                                ad.volume = (ad.volume).saturating_add(25).min(255);
                                sound::set_volume(ad.volume);
                            } else if (70..=250).contains(&x) && (75..=115).contains(&y) {
                                let pct = ((x as u32 - 70) * 255 / 180).min(255) as u8;
                                ad.volume = pct;
                                sound::set_volume(ad.volume);
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdCardSettings => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SettingsMenu;
                        } else if (10..=155).contains(&x) && (100..=130).contains(&y) {
                            // Format button — show confirmation first
                            if let Some(ct) = bb_card_type {
                                // Draw warning screen
                                boot_display.display.clear(crate::hw::display::COLOR_BG).ok();
                                let tw = crate::hw::display::measure_header("WARNING");
                                crate::hw::display::draw_oswald_header(
                                    &mut boot_display.display, "WARNING",
                                    (320 - tw) / 2, 30, crate::hw::display::COLOR_DANGER);
                                use embedded_graphics::primitives::{Line, PrimitiveStyle};
                                use embedded_graphics::prelude::*;
                                Line::new(Point::new(20, 40), Point::new(300, 40))
                                    .into_styled(PrimitiveStyle::with_stroke(crate::hw::display::COLOR_DANGER, 1))
                                    .draw(&mut boot_display.display).ok();

                                let s1 = "ALL DATA WILL BE LOST";
                                let s1w = crate::hw::display::measure_title(s1);
                                crate::hw::display::draw_lato_title(
                                    &mut boot_display.display, s1, (320 - s1w) / 2, 80,
                                    crate::hw::display::COLOR_DANGER);

                                let s2 = "This will erase the entire";
                                let s2w = crate::hw::display::measure_body(s2);
                                crate::hw::display::draw_lato_body(
                                    &mut boot_display.display, s2, (320 - s2w) / 2, 110,
                                    crate::hw::display::COLOR_TEXT_DIM);
                                let s3 = "SD card. This is permanent.";
                                let s3w = crate::hw::display::measure_body(s3);
                                crate::hw::display::draw_lato_body(
                                    &mut boot_display.display, s3, (320 - s3w) / 2, 130,
                                    crate::hw::display::COLOR_TEXT_DIM);

                                // Red "HOLD 4s TO FORMAT" button
                                use embedded_graphics::primitives::{Rectangle, RoundedRectangle, CornerRadii};
                                let btn_corner = CornerRadii::new(embedded_graphics::geometry::Size::new(8, 8));
                                let btn_rect = Rectangle::new(Point::new(50, 170),
                                    embedded_graphics::geometry::Size::new(220, 44));
                                RoundedRectangle::new(btn_rect, btn_corner)
                                    .into_styled(PrimitiveStyle::with_fill(crate::hw::display::COLOR_DANGER))
                                    .draw(&mut boot_display.display).ok();
                                let bl = "HOLD 4s TO FORMAT";
                                let bw = crate::hw::display::measure_title(bl);
                                crate::hw::display::draw_lato_title(
                                    &mut boot_display.display, bl, 50 + (220 - bw) / 2, 200,
                                    crate::hw::display::COLOR_BG);

                                let hw = crate::hw::display::measure_hint("Release or tap to cancel");
                                crate::hw::display::draw_lato_hint(
                                    &mut boot_display.display, "Release or tap to cancel",
                                    (320 - hw) / 2, 232, crate::hw::display::COLOR_TEXT_DIM);

                                boot_display.draw_back_button();

                                // Wait for finger release from initial tap before starting hold detection
                                loop {
                                    delay.delay_millis(30);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::NoTouch => break,
                                        _ => {}
                                    }
                                }
                                // Small debounce gap
                                delay.delay_millis(100);

                                // Now wait for user to press the red button and hold for 4 seconds
                                let mut held_ms: u32 = 0;
                                let mut confirmed = false;
                                let mut waiting_for_press = true;
                                loop {
                                    delay.delay_millis(50);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::One(pt) => {
                                            // Back button or Home button = cancel
                                            if (pt.x <= 40 && pt.y <= 40) || (pt.x >= 268 && pt.y <= 52) {
                                                sound::click(delay);
                                                break;
                                            }
                                            if pt.x >= 50 && pt.x <= 270 && pt.y >= 170 && pt.y <= 214 {
                                                waiting_for_press = false;
                                                held_ms += 50;
                                                let fill = (held_ms * 200 / 4000).min(200);
                                                if fill > 0 {
                                                    Rectangle::new(Point::new(60, 180),
                                                        embedded_graphics::geometry::Size::new(fill, 24))
                                                        .into_styled(PrimitiveStyle::with_fill(
                                                            embedded_graphics::pixelcolor::Rgb565::new(0b11111, 0b000000, 0b00000)))
                                                        .draw(&mut boot_display.display).ok();
                                                }
                                                if held_ms >= 4000 {
                                                    confirmed = true;
                                                    break;
                                                }
                                            } else if !waiting_for_press {
                                                break; // was holding but moved off button = cancel
                                            }
                                        }
                                        _ => {
                                            if !waiting_for_press {
                                                break; // was holding, released = cancel
                                            }
                                            // Still waiting for initial press — keep looping
                                        }
                                    }
                                }

                                if confirmed {
                                    boot_display.draw_sdcard_formatting();
                                    let fmt_ok = sdcard::format_fat32(*ct, i2c, delay);
                                    boot_display.draw_sdcard_format_done(fmt_ok);
                                    if fmt_ok { sound::success(delay); } else { sound::beep_error(delay); }
                                    delay.delay_millis(3000);
                                }
                            }
                        } else if (165..=310).contains(&x) && (100..=130).contains(&y) {
                            // Test R/W button
                            if bb_card_type.is_some() {
                                boot_display.draw_sdcard_testing();
                                let test_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                    let fat32 = sdcard::mount_fat32(ct)?;
                                    let test_data = b"KasSigner SD test 1234567890ABCDEF";
                                    let name = sdcard::to_83_name(b"TEST.TXT");
                                    let _ = sdcard::delete_file(ct, &fat32, &name);
                                    sdcard::create_file(ct, &fat32, &name, test_data)?;
                                    let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &name)?;
                                    if entry.file_size != test_data.len() as u32 {
                                        return Err("Size mismatch");
                                    }
                                    let mut readback = [0u8; 512];
                                    let bytes_read = sdcard::read_file(ct, &fat32, &entry, &mut readback)?;
                                    if bytes_read != test_data.len() {
                                        return Err("Read size mismatch");
                                    }
                                    if &readback[..test_data.len()] != test_data {
                                        return Err("Data mismatch");
                                    }
                                    let mut file_count = 0u32;
                                    sdcard::list_root_dir(ct, &fat32, |_| { file_count += 1; true })?;
                                    sdcard::delete_file(ct, &fat32, &name)?;
                                    Ok((bytes_read, file_count))
                                });

                                match test_result {
                                    Ok((bytes, files)) => {
                                        log!("[SD-TEST] PASS: {}/{} bytes, {} files", bytes, 34, files);
                                        let mut l1 = [0u8; 40];
                                        let mut l2 = [0u8; 40];
                                        let s1 = format_test_line(&mut l1, "Write+Read: ", bytes as u32, " bytes OK");
                                        let s2 = format_test_line(&mut l2, "Root dir: ", files, " files");
                                        let lines: [&str; 3] = [s1, s2, "Data verify: match"];
                                        boot_display.draw_sdcard_test_result(&lines, true);
                                        sound::success(delay);
                                    }
                                    Err(e) => {
                                        log!("[SD-TEST] FAIL: {}", e);
                                        let lines: [&str; 2] = ["SD card test failed:", e];
                                        boot_display.draw_sdcard_test_result(&lines, false);
                                        sound::beep_error(delay);
                                    }
                                }
                                delay.delay_millis(5000);
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::About => {
                        ad.app.state = crate::app::input::AppState::SettingsMenu;
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
