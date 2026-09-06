//! LCD client adapter for the CoreS3 shared SPI2 owner.

use core::convert::Infallible;

use embedded_hal::{
    digital::{ErrorType as DigitalErrorType, OutputPin},
    spi::{Error as SpiError, ErrorKind, ErrorType, SpiBus},
};
use embedded_hal_bus::spi::{ExclusiveDevice, NoDelay};
use esp_hal::gpio::Output;

use super::{gpio35, state};

#[derive(Debug)]
pub(crate) enum LcdSpiError {
    Bus,
}

impl SpiError for LcdSpiError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

pub(crate) struct LcdChipSelect<'a> {
    pin: Output<'a>,
}

impl<'a> LcdChipSelect<'a> {
    fn new(pin: Output<'a>) -> Self {
        Self { pin }
    }
}

impl DigitalErrorType for LcdChipSelect<'_> {
    type Error = Infallible;
}

impl OutputPin for LcdChipSelect<'_> {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        gpio35::select_lcd_dc();
        self.pin.set_low();
        Ok(())
    }

    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.pin.set_high();
        gpio35::select_sd_miso();
        Ok(())
    }
}

/// Zero-sized D/C output. Its data latch is set before each LCD SPI transaction;
/// the chip-select wrapper enables GPIO35 output only while the LCD is selected.
pub(crate) struct LcdDataCommand;

impl DigitalErrorType for LcdDataCommand {
    type Error = Infallible;
}

impl OutputPin for LcdDataCommand {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        gpio35::set_dc(false);
        Ok(())
    }

    fn set_high(&mut self) -> Result<(), Self::Error> {
        gpio35::set_dc(true);
        Ok(())
    }
}

pub(crate) struct LcdBus;

impl ErrorType for LcdBus {
    type Error = LcdSpiError;
}

impl SpiBus<u8> for LcdBus {
    fn read(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        state::with_lcd_bus(|spi| embedded_hal::spi::SpiBus::read(spi, words).map_err(|_| "LCD SPI read failed"))
            .map_err(|_| LcdSpiError::Bus)
    }

    fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
        state::with_lcd_bus(|spi| embedded_hal::spi::SpiBus::write(spi, words).map_err(|_| "LCD SPI write failed"))
            .map_err(|_| LcdSpiError::Bus)
    }

    fn transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), Self::Error> {
        state::with_lcd_bus(|spi| {
            embedded_hal::spi::SpiBus::transfer(spi, read, write)
                .map_err(|_| "LCD SPI transfer failed")
        })
        .map_err(|_| LcdSpiError::Bus)
    }

    fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        state::with_lcd_bus(|spi| {
            embedded_hal::spi::SpiBus::transfer_in_place(spi, words)
                .map_err(|_| "LCD SPI in-place transfer failed")
        })
        .map_err(|_| LcdSpiError::Bus)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        state::with_lcd_bus(|spi| embedded_hal::spi::SpiBus::flush(spi).map_err(|_| "LCD SPI flush failed"))
            .map_err(|_| LcdSpiError::Bus)
    }
}

pub(crate) type LcdDevice<'a> = ExclusiveDevice<LcdBus, LcdChipSelect<'a>, NoDelay>;

pub(crate) fn device<'a>(cs_pin: Output<'a>) -> Result<LcdDevice<'a>, &'static str> {
    ExclusiveDevice::new_no_delay(LcdBus, LcdChipSelect::new(cs_pin))
        .map_err(|_| "Failed to create CoreS3 LCD SPI client")
}
