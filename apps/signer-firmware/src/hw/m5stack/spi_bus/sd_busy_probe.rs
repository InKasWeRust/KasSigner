//! Narrow CoreS3 SD chip-select/MISO provenance diagnostics.
//!
//! This is intentionally separate from the shared SPI owner so diagnostics do
//! not expand the normal LCD/SD transaction state machine.

use esp_hal::{Blocking, gpio::Output, spi::master::Spi};

use super::{gpio35, state::complete_sd_transaction};

pub(crate) struct SdBusyProbe<'a> {
    sd_cs: &'a mut Output<'static>,
}

impl SdBusyProbe<'_> {
    /// Sample MISO selected, deselected, then selected again without changing
    /// card power. Card-driven busy should release while CS is high.
    pub(crate) fn sample(
        &mut self,
        spi: &mut Spi<'static, Blocking>,
    ) -> Result<[u8; 3], &'static str> {
        diagnostic_transfer(spi).and_then(|selected_before| {
            flush(spi, "CoreS3 SPI2 busy-probe pre-deselect flush failed").and_then(|_| {
                self.sd_cs.set_high();
                diagnostic_transfer(spi).and_then(|deselected| {
                    flush(spi, "CoreS3 SPI2 busy-probe deselected flush failed").and_then(|_| {
                        self.sd_cs.set_low();
                        diagnostic_transfer(spi)
                            .map(|reselected| [selected_before, deselected, reselected])
                    })
                })
            })
        })
    }
}

pub(super) fn selected_transaction<T>(
    spi: &mut Spi<'static, Blocking>,
    sd_cs: &mut Output<'static>,
    frequency_hz: u32,
    operation: impl FnOnce(
        &mut Spi<'static, Blocking>,
        &mut SdBusyProbe<'_>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    gpio35::select_sd_miso();
    log_bus_state(frequency_hz);
    sd_cs.set_low();
    let mut probe = SdBusyProbe { sd_cs };
    let result = operation(spi, &mut probe);
    let completion = complete_sd_transaction(spi, probe.sd_cs);
    match (result, completion) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn log_bus_state(frequency_hz: u32) {
    let (gpio35_selector, gpio35_output_enabled) = gpio35::diagnostic_state();
    crate::log!(
        "[SD-DIAG] SPI2 mode=0 frequency={}Hz GPIO35_FUNC_OUT_SEL=0x{:08x} GPIO35_output_enabled={}",
        frequency_hz,
        gpio35_selector,
        gpio35_output_enabled,
    );
}

fn diagnostic_transfer(spi: &mut Spi<'static, Blocking>) -> Result<u8, &'static str> {
    let mut byte = [0xFFu8];
    embedded_hal::spi::SpiBus::transfer_in_place(spi, &mut byte)
        .map(|_| byte[0])
        .map_err(|_| "CoreS3 SPI2 busy-probe transfer failed")
}

fn flush(spi: &mut Spi<'static, Blocking>, error: &'static str) -> Result<(), &'static str> {
    embedded_hal::spi::SpiBus::flush(spi).map_err(|_| error)
}
