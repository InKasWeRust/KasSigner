//! Current application-icon gallery diagnostic.

use embedded_graphics::{pixelcolor::Rgb565, prelude::*};

const LABELS: [&str; 20] = [
    "Sign TX", "Sign Mess", "Create Multi", "Import Words", "Import Key",
    "Seed Tools", "Show Seed", "Show as QR", "Backup to", "Watch-Only",
    "Private Key", "Display", "Camera", "Sound", "Settings", "Delete",
    "Help", "Upload", "Download", "kpub",
];

pub(crate) fn draw<D: DrawTarget<Color = Rgb565>>(display: &mut D) {
    use embedded_graphics::geometry::Point;
    let _ = display.clear(crate::ui::display::COLOR_BG);
    for (index, label) in LABELS.iter().enumerate() {
        let x = 18 + (index % 5) as i32 * 60;
        let y = 22 + (index / 5) as i32 * 54;
        crate::ui::display::draw_menu_icon(display, label, Point::new(x, y));
    }
    crate::log!("[icon-browser] rendered {} current application icons", LABELS.len());
}


pub(crate) fn draw_and_halt<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    delay: &mut esp_hal::delay::Delay,
) -> ! {
    draw(display);
    crate::halt_forever(delay)
}
