//! Rendering details for the hardware-attestation boot screen.

use embedded_graphics::{pixelcolor::Rgb565, prelude::DrawTarget};

use crate::ui::display::{
    draw_lato_body, draw_lato_hint, draw_oswald_header, measure_body, measure_hint, COLOR_TEXT,
    COLOR_TEXT_DIM, KASPA_TEAL,
};

pub(super) fn draw_attestation_details<D>(
    display: &mut D,
    version: &str,
    commit: &str,
    image_hash: &str,
    phrase: &str,
    version_y: i32,
    hash_y: i32,
    hardware_secure_boot: bool,
) -> Result<(), &'static str>
where
    D: DrawTarget<Color = Rgb565>,
{
    draw_trust_state(display, hardware_secure_boot);
    draw_phrase(display, phrase);
    draw_identity(display, version, commit, version_y);
    draw_hash(display, image_hash, phrase, hash_y);
    Ok(())
}

fn draw_trust_state<D: DrawTarget<Color = Rgb565>>(display: &mut D, hardware_secure_boot: bool) {
    let (top, bottom, secure_boot) = if hardware_secure_boot {
        ("HARDWARE", "ATTESTED", "Secure Boot v2: ON")
    } else {
        ("SOFTWARE", "VERIFIED", "Secure Boot v2: READY")
    };
    for (text, y) in [(top, 10), (bottom, 32)] {
        draw_oswald_header(display, text, 112, y, KASPA_TEAL);
    }
    draw_lato_hint(display, secure_boot, 112, 61, KASPA_TEAL);
    draw_lato_hint(display, "App signature: VERIFIED", 112, 79, KASPA_TEAL);
}

fn draw_phrase<D: DrawTarget<Color = Rgb565>>(display: &mut D, phrase: &str) {
    draw_lato_hint(
        display,
        phrase,
        (320 - measure_hint(phrase)) / 2,
        105,
        COLOR_TEXT,
    );
}

fn draw_identity<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    version: &str,
    commit: &str,
    version_y: i32,
) {
    let mut version_text = heapless::String::<48>::new();
    core::fmt::Write::write_fmt(&mut version_text, format_args!("Firmware v{version}")).ok();
    draw_lato_body(
        display,
        version_text.as_str(),
        (320 - measure_body(version_text.as_str())) / 2,
        version_y,
        COLOR_TEXT,
    );

    let mut commit_text = heapless::String::<48>::new();
    core::fmt::Write::write_fmt(&mut commit_text, format_args!("Source: {commit}")).ok();
    draw_lato_hint(
        display,
        commit_text.as_str(),
        (320 - measure_hint(commit_text.as_str())) / 2,
        version_y + 17,
        COLOR_TEXT_DIM,
    );
}

fn draw_hash<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    image_hash: &str,
    phrase: &str,
    hash_y: i32,
) {
    let label = if phrase.starts_with("Code phrase:") {
        "SIGNED CODE SHA-256"
    } else {
        "SIGNED IMAGE SHA-256"
    };
    draw_lato_hint(
        display,
        label,
        (320 - measure_hint(label)) / 2,
        hash_y,
        COLOR_TEXT_DIM,
    );
    for (line, delta_y) in [14, 27, 40, 53].into_iter().enumerate() {
        let start = line * 16;
        let end = start + 16;
        let part = image_hash.get(start..end).unwrap_or("????????????????");
        draw_lato_hint(
            display,
            part,
            (320 - measure_hint(part)) / 2,
            hash_y + delta_y,
            COLOR_TEXT,
        );
    }
}
