// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use embedded_graphics::{
    image::{Image, ImageRawLE},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Line, PrimitiveStyle, Rectangle},
};

use crate::hw::display::BootDisplay;

#[cfg(feature = "production")]
mod attestation;

use super::{
    draw_lato_body, draw_lato_hint, draw_lato_title, draw_oswald_header, measure_body,
    measure_header, measure_hint, measure_title, COLOR_BG, COLOR_DANGER, COLOR_ORANGE,
    COLOR_TEXT, COLOR_TEXT_DIM, KASPA_TEAL,
};

#[derive(Clone, Copy)]
struct BootPresentation {
    board_label: &'static str,
    #[cfg(feature = "production")]
    verification_version_y: i32,
    #[cfg(feature = "production")]
    verification_hash_y: i32,
}

#[cfg(feature = "waveshare")]
const BOOT_PRESENTATION: BootPresentation = BootPresentation {
    board_label: "Waveshare ESP32-S3-Touch-LCD-2",
    #[cfg(feature = "production")]
    verification_version_y: 135,
    #[cfg(feature = "production")]
    verification_hash_y: 165,
};

#[cfg(feature = "m5stack")]
const BOOT_PRESENTATION: BootPresentation = BootPresentation {
    board_label: "M5Stack CoreS3 Lite",
    #[cfg(feature = "production")]
    verification_version_y: 125,
    #[cfg(feature = "production")]
    verification_hash_y: 155,
};

#[cfg(feature = "production")]
fn show_verification_screen<D>(
    display: &mut D,
    version: &str,
    commit: &str,
    image_hash: &str,
    phrase: &str,
    hardware_secure_boot: bool,
    presentation: BootPresentation,
) -> Result<(), &'static str>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

    static KASCOIN_SOFTWARE: &[u8] = include_bytes!("../../../assets/kascoin_90.raw");
    static KASCOIN_HARDWARE: &[u8] = include_bytes!("../../../assets/kascoin_teal_90.raw");
    let coin = if hardware_secure_boot { KASCOIN_HARDWARE } else { KASCOIN_SOFTWARE };
    let raw_coin: ImageRawLE<Rgb565> = ImageRawLE::new(coin, 90);
    Image::new(&raw_coin, Point::new(10, 6)).draw(display).ok();

    attestation::draw_attestation_details(
        display,
        version,
        commit,
        image_hash,
        phrase,
        presentation.verification_version_y,
        presentation.verification_hash_y,
        hardware_secure_boot,
    )
}

fn show_logo_screen<D>(
    display: &mut D,
    presentation: BootPresentation,
) -> Result<(), &'static str>
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(COLOR_BG).map_err(|_| "Clear failed")?;

    static LOGO_DATA: &[u8] = include_bytes!("../../../assets/logo_320x240.raw");
    let raw_image: ImageRawLE<Rgb565> = ImageRawLE::new(LOGO_DATA, 320);
    Image::new(&raw_image, Point::new(0, -20)).draw(display).ok();

    let mut version_buffer = [0u8; 12];
    let version_len = crate::services::fw_update::format_version(
        crate::services::fw_update::CURRENT_VERSION,
        &mut version_buffer[1..],
    );
    version_buffer[0] = b'v';
    let version_text = core::str::from_utf8(&version_buffer[..version_len + 1]).unwrap_or("v?");
    let version_width = measure_title(version_text);
    draw_lato_title(
        display,
        version_text,
        (320 - version_width) / 2,
        122,
        COLOR_TEXT,
    );

    let subtitle = "Secure Hardware Wallet for Kaspa";
    draw_lato_body(
        display,
        subtitle,
        (320 - measure_body(subtitle)) / 2,
        146,
        COLOR_TEXT_DIM,
    );

    let properties = "100% Rust | Air-Gapped | no_std";
    draw_lato_body(
        display,
        properties,
        (320 - measure_body(properties)) / 2,
        166,
        COLOR_TEXT_DIM,
    );

    draw_lato_hint(
        display,
        presentation.board_label,
        (320 - measure_hint(presentation.board_label)) / 2,
        186,
        COLOR_TEXT_DIM,
    );

    let site = "kaspa.org";
    draw_lato_hint(
        display,
        site,
        (320 - measure_hint(site)) / 2,
        206,
        KASPA_TEAL,
    );

    Ok(())
}

fn show_panic_screen<D>(
    display: &mut D,
    message: &str,
) -> Result<(), &'static str>
where
    D: DrawTarget<Color = Rgb565>,
{
    display
        .clear(COLOR_DANGER)
        .map_err(|_| "Clear failed")?;

    let heading = if message.starts_with("ATTESTATION:") {
        "ATTESTATION FAILED"
    } else {
        "!!! PANIC !!!"
    };
    let panic_width = measure_header(heading);
    draw_oswald_header(
        display,
        heading,
        (320 - panic_width) / 2,
        60,
        COLOR_TEXT,
    );

    let truncated = super::truncate_chars(message, 35);
    let message_width = measure_body(truncated);
    draw_lato_body(
        display,
        truncated,
        (320 - message_width) / 2,
        120,
        COLOR_TEXT,
    );

    let no_boot_width = measure_header("NO BOOT");
    draw_oswald_header(
        display,
        "NO BOOT",
        (320 - no_boot_width) / 2,
        180,
        COLOR_TEXT,
    );
    Ok(())
}

fn clear_screen<D>(display: &mut D)
where
    D: DrawTarget<Color = Rgb565>,
{
    display.clear(COLOR_BG).ok();
}

fn draw_frame_counter<D>(display: &mut D, text: &str)
where
    D: DrawTarget<Color = Rgb565>,
{
    let column_center = 278;
    // Keep the frame counter entirely below the shared brightness `+` zone
    // (y=134..164). The previous y=150 origin repainted the lower half of
    // that control during every auto-cycle frame.
    Rectangle::new(Point::new(240, 172), Size::new(80, 64))
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();

    let label = "FRAMES";
    let label_width = measure_hint(label);
    draw_lato_hint(
        display,
        label,
        column_center - label_width / 2,
        184,
        COLOR_TEXT_DIM,
    );

    let text_width = measure_title(text);
    draw_lato_title(
        display,
        text,
        column_center - text_width / 2,
        216,
        KASPA_TEAL,
    );
}

fn draw_sig_status<D>(display: &mut D, present: u32, required: u32)
where
    D: DrawTarget<Color = Rgb565>,
{
    let color = if present >= required {
        KASPA_TEAL
    } else {
        COLOR_ORANGE
    };
    let column_center = 278;
    let label = "SIGNER";
    let label_width = measure_hint(label);
    draw_lato_hint(
        display,
        label,
        column_center - label_width / 2,
        40,
        COLOR_TEXT_DIM,
    );

    let mut signature_count = heapless::String::<24>::new();
    core::fmt::Write::write_fmt(
        &mut signature_count,
        format_args!("{present}/{required}"),
    )
    .ok();
    let count_width = measure_title(signature_count.as_str());
    draw_lato_title(
        display,
        signature_count.as_str(),
        column_center - count_width / 2,
        70,
        color,
    );
}

const SECURITY_BADGE_SIZE: usize = 30;
const SECURITY_BADGE_SOURCE_SIZE: usize = 90;
const SECURITY_BADGE_HOME_X: i32 = 2;
const SECURITY_BADGE_Y: i32 = 2;

pub(crate) fn draw_security_badge<D>(display: &mut D)
where
    D: DrawTarget<Color = Rgb565>,
{
    draw_security_badge_at(display, SECURITY_BADGE_HOME_X);
}

fn draw_security_badge_at<D>(display: &mut D, x_origin: i32)
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(
        Point::new(x_origin, SECURITY_BADGE_Y),
        Size::new(SECURITY_BADGE_SIZE as u32, SECURITY_BADGE_SIZE as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
    .draw(display)
    .ok();

    match crate::services::verify::boot_security::indicator_level() {
        crate::services::verify::boot_security::BootSecurityLevel::HardwareEnforced => {
            static TEAL: &[u8] = include_bytes!("../../../assets/kascoin_teal_90.raw");
            draw_security_coin(display, TEAL, x_origin);
        }
        crate::services::verify::boot_security::BootSecurityLevel::SoftwareVerified => {
            static WHITE: &[u8] = include_bytes!("../../../assets/kascoin_90.raw");
            draw_security_coin(display, WHITE, x_origin);
        }
        crate::services::verify::boot_security::BootSecurityLevel::None => {
            Line::new(Point::new(x_origin + 4, 6), Point::new(x_origin + 26, 28))
                .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 4))
                .draw(display).ok();
            Line::new(Point::new(x_origin + 26, 6), Point::new(x_origin + 4, 28))
                .into_styled(PrimitiveStyle::with_stroke(COLOR_DANGER, 4))
                .draw(display).ok();
        }
    }
}

fn draw_security_coin<D>(display: &mut D, raw: &[u8], x_origin: i32)
where
    D: DrawTarget<Color = Rgb565>,
{
    for y in 0..SECURITY_BADGE_SIZE {
        let source_y = y * SECURITY_BADGE_SOURCE_SIZE / SECURITY_BADGE_SIZE;
        for x in 0..SECURITY_BADGE_SIZE {
            let source_x = x * SECURITY_BADGE_SOURCE_SIZE / SECURITY_BADGE_SIZE;
            let index = (source_y * SECURITY_BADGE_SOURCE_SIZE + source_x) * 2;
            if index + 1 >= raw.len() { return; }
            let value = u16::from(raw[index]) | (u16::from(raw[index + 1]) << 8);
            let color = Rgb565::new(
                ((value >> 11) & 0x1f) as u8,
                ((value >> 5) & 0x3f) as u8,
                (value & 0x1f) as u8,
            );
            Pixel(Point::new(x_origin + x as i32, SECURITY_BADGE_Y + y as i32), color)
                .draw(display).ok();
        }
    }
}

fn draw_back_button<D>(display: &mut D)
where
    D: DrawTarget<Color = Rgb565>,
{
    let back: ImageRawLE<Rgb565> = ImageRawLE::new(
        super::icon_data::ICON_BACK,
        super::icon_data::ICON_BACK_W,
    );
    Image::new(&back, Point::new(0, 0)).draw(display).ok();

}

fn clear_keep_nav<D>(display: &mut D)
where
    D: DrawTarget<Color = Rgb565>,
{
    Rectangle::new(Point::new(34, 0), Size::new(286, 34))
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();
    Rectangle::new(Point::new(0, 34), Size::new(320, 206))
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)
        .ok();
    draw_back_button(display);
}

impl<'a> BootDisplay<'a> {
    #[cfg(feature = "production")]
    pub fn show_verification_screen(
        &mut self,
        version: &str,
        commit: &str,
        image_hash: &str,
        phrase: &str,
        hardware_secure_boot: bool,
    ) -> Result<(), &'static str> {
        show_verification_screen(
            &mut self.display,
            version,
            commit,
            image_hash,
            phrase,
            hardware_secure_boot,
            BOOT_PRESENTATION,
        )
    }

    pub fn show_logo_screen(&mut self) -> Result<(), &'static str> {
        show_logo_screen(&mut self.display, BOOT_PRESENTATION)
    }

    pub fn show_panic_screen(&mut self, message: &str) -> Result<(), &'static str> {
        show_panic_screen(&mut self.display, message)
    }

    pub fn clear_screen(&mut self) {
        clear_screen(&mut self.display);
    }

    pub fn draw_frame_counter(&mut self, text: &str) {
        draw_frame_counter(&mut self.display, text);
    }

    pub fn draw_sig_status(&mut self, present: u32, required: u32) {
        draw_sig_status(&mut self.display, present, required);
    }

    pub fn draw_back_button(&mut self) {
        draw_back_button(&mut self.display);
    }

    pub fn clear_keep_nav(&mut self) {
        clear_keep_nav(&mut self.display);
    }
}
