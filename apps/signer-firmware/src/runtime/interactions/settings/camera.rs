// KasSigner — Air-gapped offline signing device for Kaspa
// Focused settings controller component.
use super::AppData;
use crate::hw::display as hw_display;
use crate::services::audio as sound;
pub(super) fn handle_camera_settings(
    ad: &mut AppData,
    boot_display: &mut hw_display::BootDisplay<'_>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back || camera_exit_tapped(x, y) {
        exit_camera_settings(ad, !is_back);
        return true;
    }
    if y >= 190 {
        update_camera_slider(ad, boot_display, x);
        return false;
    }
    if x >= 198 && (38..190).contains(&y) {
        select_camera_parameter(ad, boot_display, x, y);
    }
    false
}

fn camera_exit_tapped(x: u16, y: u16) -> bool {
    (198..=320).contains(&x) && y <= 36
}

fn exit_camera_settings(ad: &mut AppData, click: bool) {
    if click {
        sound::click();
    }
    ad.camera.cam_tune_active = false;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SettingsMenu));
}

fn update_camera_slider(
    ad: &mut AppData,
    boot_display: &mut hw_display::BootDisplay<'_>,
    x: u16,
) {
    let parameter = ad.camera.cam_tune_param as usize;
    ad.camera.cam_tune_vals[parameter] = slider_value(ad.camera.cam_tune_vals[parameter], x);
    ad.camera.cam_tune_dirty = true;
    if x <= 70 || x >= 250 {
        sound::click();
    }
    boot_display.update_cam_tune_slider(ad.camera.cam_tune_param, &ad.camera.cam_tune_vals);
}

fn slider_value(current: u8, x: u16) -> u8 {
    if x <= 70 {
        return current.saturating_sub(4);
    }
    if x >= 250 {
        return current.saturating_add(4);
    }
    let clamped = (i32::from(x) - 70).clamp(0, 180) as u32;
    ((clamped * 255) / 180) as u8
}

fn select_camera_parameter(
    ad: &mut AppData,
    boot_display: &mut hw_display::BootDisplay<'_>,
    x: u16,
    y: u16,
) {
    let Some(row) = camera_parameter_row(y) else {
        return;
    };
    let column = u8::from(x >= 259);
    let index = row * 2 + column;
    if index >= 6 || index == ad.camera.cam_tune_param {
        return;
    }
    ad.camera.cam_tune_param = index;
    sound::click();
    boot_display.draw_cam_tune_overlay(ad.camera.cam_tune_param, &ad.camera.cam_tune_vals);
}

fn camera_parameter_row(y: u16) -> Option<u8> {
    match y {
        38..=82 => Some(0),
        85..=129 => Some(1),
        132..=176 => Some(2),
        _ => None,
    }
}
