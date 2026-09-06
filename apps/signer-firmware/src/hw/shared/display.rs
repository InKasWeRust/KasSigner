// KasSigner — shared SPI display transport primitives.

use embedded_graphics::{pixelcolor::{Rgb565, RgbColor}, prelude::*};
use esp_hal::delay::Delay;

pub(crate) fn clear_and_settle<T>(
    display: &mut T,
    delay: &mut Delay,
) -> Result<(), &'static str>
where
    T: DrawTarget<Color = Rgb565>,
{
    display.clear(Rgb565::BLACK).map_err(|_| "Failed to clear display")?;
    delay.delay_millis(100);
    Ok(())
}
