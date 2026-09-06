// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! M5Stack CoreS3 ILI9342C display transport.
//!
//! The LCD is a client of the board's single SPI2 owner. GPIO35 is switched
//! between LCD D/C and SD MISO only at LCD chip-select transaction boundaries.

use esp_hal::{delay::Delay, gpio::Output};
use mipidsi::{
    interface::SpiInterface,
    models::ILI9342CRgb565,
    options::{Orientation, Rotation},
    Builder,
};
use static_cell::StaticCell;

use super::spi_bus::{LcdDataCommand, LcdDevice, lcd_device};

static SPI_BUFFER: StaticCell<[u8; 512]> = StaticCell::new();

type CoreS3Interface<'a> = SpiInterface<'a, LcdDevice<'a>, LcdDataCommand>;

pub type PanelDisplay<'a> = mipidsi::Display<
    CoreS3Interface<'a>,
    ILI9342CRgb565,
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
    pub fn new(
        cs_pin: Output<'a>,
        reset_pin: Output<'a>,
        delay: &mut Delay,
    ) -> Result<Self, &'static str> {
        let device = lcd_device(cs_pin)?;
        build_panel(device, reset_pin, delay)
            .map(|display| Self { display: wrap_panel(display) })
    }
}

fn build_panel<'a>(
    device: LcdDevice<'a>,
    reset_pin: Output<'a>,
    delay: &mut Delay,
) -> Result<PanelDisplay<'a>, &'static str> {
    let buffer: &'a mut [u8; 512] = SPI_BUFFER.init([0; 512]);
    let interface = SpiInterface::new(device, LcdDataCommand, buffer);
    let mut display = Builder::new(ILI9342CRgb565, interface)
        .reset_pin(reset_pin)
        .color_order(mipidsi::options::ColorOrder::Bgr)
        .invert_colors(mipidsi::options::ColorInversion::Inverted)
        .init(delay)
        .map_err(|_| "Failed to init ILI9342C")?;
    display
        .set_orientation(Orientation::default().rotate(Rotation::Deg180))
        .map_err(|_| "Failed to set orientation")?;
    crate::hw::shared::display::clear_and_settle(&mut display, delay)?;
    Ok(display)
}

#[cfg(feature = "screenshot")]
fn wrap_panel<'a>(display: PanelDisplay<'a>) -> BootDisplayTarget<'a> {
    let mut tee = TeeDisplay::new(display);
    tee.enable_shadow();
    tee
}

#[cfg(not(feature = "screenshot"))]
fn wrap_panel<'a>(display: PanelDisplay<'a>) -> BootDisplayTarget<'a> {
    display
}
