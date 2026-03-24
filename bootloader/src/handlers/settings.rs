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
                                match item {
                                    0 => { ad.app.state = crate::app::input::AppState::DisplaySettings; }
                                    1 => { ad.app.state = crate::app::input::AppState::SdCardSettings; }
                                    2 => { ad.app.state = crate::app::input::AppState::About; }                                    _ => {}
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
                            let old = ad.brightness;
                            if x <= 68 && y >= 70 && y <= 120 {
                                ad.brightness = (ad.brightness).saturating_sub(25);
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            } else if x >= 252 && y >= 70 && y <= 120 {
                                ad.brightness = (ad.brightness).saturating_add(25).min(255);
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            } else if x >= 70 && x <= 250 && y >= 75 && y <= 115 {
                                let pct = ((x as u32 - 70) * 255 / 180).min(255) as u8;
                                ad.brightness = pct;
                                crate::hw::pmu::set_brightness(i2c, ad.brightness);
                            }
                            if ad.brightness != old { needs_redraw = true; }
                        }
                    }
                    crate::app::input::AppState::SdCardSettings => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SettingsMenu;
                        } else if x >= 10 && x <= 155 && y >= 100 && y <= 130 {
                            // Format button
                            if let Some(ct) = bb_card_type {
                                boot_display.draw_sdcard_formatting();
                                let fmt_ok = sdcard::format_fat32(*ct, i2c, delay);
                                boot_display.draw_sdcard_format_done(fmt_ok);
                                if fmt_ok { sound::success(delay); } else { sound::beep_error(delay); }
                                delay.delay_millis(3000);
                            }
                        } else if x >= 165 && x <= 310 && y >= 100 && y <= 130 {
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
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SettingsMenu;
                        }
                        needs_redraw = true;
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
