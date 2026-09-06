// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Waveshare ST7789T3 display transport.
//!
//! This module owns the ST7789T3 SPI type, initialization sequence,
//! orientation, and optional screenshot mirroring. Screen presentation lives
//! in `ui::display` and is implemented against the stable `BootDisplay` type.

use esp_hal::{delay::Delay, gpio::Output, spi::master::Spi};
use embedded_hal_bus::spi::ExclusiveDevice;
use mipidsi::{
    interface::SpiInterface,
    models::ST7789,
    options::{Orientation, Rotation},
    Builder,
};
use static_cell::StaticCell;

type DisplayBus<'a> = ExclusiveDevice<
    Spi<'a, esp_hal::Blocking>,
    Output<'a>,
    embedded_hal_bus::spi::NoDelay,
>;
type DisplayInterface<'a> = SpiInterface<'a, DisplayBus<'a>, Output<'a>>;
static SPI_BUFFER: StaticCell<[u8; 512]> = StaticCell::new();

pub type PanelDisplay<'a> = mipidsi::Display<
    DisplayInterface<'a>,
    ST7789,
    Output<'a>,
>;

#[cfg(feature = "screenshot")]
pub type TeeDisplay<'a> = crate::hw::shared::display_support::TeeDisplay<PanelDisplay<'a>>;

#[cfg(feature = "screenshot")]
pub(crate) type BootDisplayTarget<'a> = TeeDisplay<'a>;
#[cfg(not(feature = "screenshot"))]
pub(crate) type BootDisplayTarget<'a> = PanelDisplay<'a>;

pub struct BootDisplay<'a> {
    pub(crate) display: BootDisplayTarget<'a>,
}

impl<'a> BootDisplay<'a> {
    /// Create the Waveshare ST7789T3 display from SPI and direct GPIO pins.
    pub fn new(
        spi: Spi<'a, esp_hal::Blocking>,
        cs_pin: Output<'a>,
        dc_pin: Output<'a>,
        reset_pin: Output<'a>,
        delay: &mut Delay,
    ) -> Result<Self, &'static str> {
        let buffer: &'a mut [u8; 512] = SPI_BUFFER.init([0; 512]);
        let device = ExclusiveDevice::new_no_delay(spi, cs_pin)
            .map_err(|_| "Failed to create SPI device")?;
        let spi_interface = SpiInterface::new(device, dc_pin, buffer);

        let orientation = Orientation::default().rotate(Rotation::Deg90);
        let mut display = Builder::new(ST7789, spi_interface)
            .reset_pin(reset_pin)
            .color_order(mipidsi::options::ColorOrder::Rgb)
            .invert_colors(mipidsi::options::ColorInversion::Inverted)
            .display_size(240, 320)
            .orientation(orientation)
            .init(delay)
            .map_err(|_| "Failed to init ST7789T3")?;

        crate::hw::shared::display::clear_and_settle(&mut display, delay)?;

        #[cfg(feature = "screenshot")]
        let display = {
            let mut tee = TeeDisplay::new(display);
            tee.enable_shadow();
            tee
        };

        Ok(Self { display })
    }
}
