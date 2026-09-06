//! Lifetime owner and serialized access for the CoreS3 SPI2 bus.
//!
//! The firmware event loop is the only runtime caller. A `RefCell` rejects
//! accidental re-entry, while the pointer only publishes the one `StaticCell`
//! allocation after boot. No interrupt handler is permitted to access SPI2.

use core::{
    cell::{Cell, RefCell, RefMut},
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use esp_hal::{
    Blocking,
    gpio::Output,
    spi::master::Spi,
};
use static_cell::StaticCell;

use super::{config, gpio35};

pub(super) struct SharedBus {
    spi: RefCell<Spi<'static, Blocking>>,
    sd_cs: RefCell<Output<'static>>,
    frequency_hz: Cell<u32>,
}

static SHARED_BUS_STORAGE: StaticCell<SharedBus> = StaticCell::new();
static SHARED_BUS_PTR: AtomicPtr<SharedBus> = AtomicPtr::new(ptr::null_mut());

/// Install the sole HAL owner of CoreS3 SPI2 and the SD chip-select pin.
pub(crate) fn initialize(
    spi: Spi<'static, Blocking>,
    mut sd_cs: Output<'static>,
) -> Result<(), &'static str> {
    if !SHARED_BUS_PTR.load(Ordering::Acquire).is_null() {
        return Err("CoreS3 SPI2 owner already initialized");
    }
    sd_cs.set_high();
    gpio35::select_sd_miso();
    publish_bus(spi, sd_cs);
    Ok(())
}
fn publish_bus(spi: Spi<'static, Blocking>, sd_cs: Output<'static>) {
    let shared = SHARED_BUS_STORAGE.init(SharedBus {
        spi: RefCell::new(spi),
        sd_cs: RefCell::new(sd_cs),
        frequency_hz: Cell::new(config::LCD_HZ),
    });
    SHARED_BUS_PTR.store(shared as *mut SharedBus, Ordering::Release);
}
/// Execute an LCD transfer after restoring the LCD bus configuration.
pub(super) fn with_lcd_bus<T>(
    operation: impl FnOnce(&mut Spi<'static, Blocking>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    with_spi(config::LCD_HZ, operation)
}
/// Execute one complete SD command/data exchange while SD CS remains asserted.
pub(crate) fn with_sd_selected<T>(
    initialization_speed: bool,
    operation: impl FnOnce(&mut Spi<'static, Blocking>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    with_resources(config::sd_frequency(initialization_speed), |spi, sd_cs| {
        selected_sd_transaction(spi, sd_cs, operation)
    })
}

/// Selected SD transaction variant used only by locked-card diagnostics.
pub(crate) fn with_sd_selected_diagnostics<T>(
    initialization_speed: bool,
    operation: impl FnOnce(
        &mut Spi<'static, Blocking>,
        &mut super::sd_busy_probe::SdBusyProbe<'_>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let frequency_hz = config::sd_frequency(initialization_speed);
    with_resources(frequency_hz, |spi, sd_cs| {
        super::sd_busy_probe::selected_transaction(spi, sd_cs, frequency_hz, operation)
    })
}

fn selected_sd_transaction<T>(
    spi: &mut Spi<'static, Blocking>,
    sd_cs: &mut Output<'static>,
    operation: impl FnOnce(&mut Spi<'static, Blocking>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    gpio35::select_sd_miso();
    sd_cs.set_low();
    let result = operation(spi);
    let completion = complete_sd_transaction(spi, sd_cs);
    match (result, completion) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}
pub(super) fn complete_sd_transaction(
    spi: &mut Spi<'static, Blocking>,
    sd_cs: &mut Output<'static>,
) -> Result<(), &'static str> {
    let flush_result = embedded_hal::spi::SpiBus::flush(spi)
        .map_err(|_| "CoreS3 SPI2 SD transaction flush failed");
    sd_cs.set_high();
    flush_result?;
    super::sd_release::release_sd_clock(spi)
}
/// Provide idle clocks with SD deselected, as required during card startup.
pub(crate) fn sd_idle_clocks(
    initialization_speed: bool,
    byte_count: usize,
) -> Result<(), &'static str> {
    with_resources(config::sd_frequency(initialization_speed), |spi, sd_cs| {
        clock_sd_idle(spi, sd_cs, byte_count)
    })
}
fn clock_sd_idle(
    spi: &mut Spi<'static, Blocking>,
    sd_cs: &mut Output<'static>,
    byte_count: usize,
) -> Result<(), &'static str> {
    gpio35::select_sd_miso();
    sd_cs.set_high();
    let clocks = [0xFFu8; 16];
    for start in (0..byte_count).step_by(clocks.len()) {
        let count = (byte_count - start).min(clocks.len());
        embedded_hal::spi::SpiBus::write(spi, &clocks[..count])
            .map_err(|_| "CoreS3 SPI2 idle clock transfer failed")?;
    }
    embedded_hal::spi::SpiBus::flush(spi)
        .map_err(|_| "CoreS3 SPI2 idle clock flush failed")
}
fn with_spi<T>(
    frequency_hz: u32,
    operation: impl FnOnce(&mut Spi<'static, Blocking>) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let shared = shared_bus()?;
    let mut spi = borrow_spi(shared)?;
    config::ensure_frequency(&shared.frequency_hz, &mut spi, frequency_hz)?;
    operation(&mut spi)
}
fn with_resources<T>(
    frequency_hz: u32,
    operation: impl FnOnce(
        &mut Spi<'static, Blocking>,
        &mut Output<'static>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let shared = shared_bus()?;
    let mut spi = borrow_spi(shared)?;
    with_sd_cs(shared, &mut spi, frequency_hz, operation)
}
fn with_sd_cs<T>(
    shared: &'static SharedBus,
    spi: &mut Spi<'static, Blocking>,
    frequency_hz: u32,
    operation: impl FnOnce(
        &mut Spi<'static, Blocking>,
        &mut Output<'static>,
    ) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let mut sd_cs = borrow_sd_cs(shared)?;
    config::ensure_frequency(&shared.frequency_hz, spi, frequency_hz)?;
    operation(spi, &mut sd_cs)
}
pub(super) fn borrow_spi(shared: &'static SharedBus) -> Result<RefMut<'static, Spi<'static, Blocking>>, &'static str> {
    shared.spi.try_borrow_mut().map_err(|_| "CoreS3 SPI2 bus re-entry")
}
pub(super) fn borrow_sd_cs(shared: &'static SharedBus) -> Result<RefMut<'static, Output<'static>>, &'static str> {
    shared.sd_cs.try_borrow_mut().map_err(|_| "CoreS3 SD chip-select re-entry")
}
pub(super) fn shared_bus() -> Result<&'static SharedBus, &'static str> {
    let pointer = SHARED_BUS_PTR.load(Ordering::Acquire);
    if pointer.is_null() {
        return Err("CoreS3 SPI2 owner unavailable");
    }
    Ok(unsafe { &*pointer })
}

