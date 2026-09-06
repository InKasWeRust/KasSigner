//! CoreS3 shared SPI2 ownership boundary.
//!
//! The LCD and microSD are clients of one HAL-owned SPI2 instance. GPIO35 is
//! the board-specific shared SD-MISO/LCD-D-C line and is switched only at the
//! LCD chip-select boundary.

mod config;
mod gpio35;
mod lcd;
mod power_cycle;
mod sd_busy_probe;
mod sd_power_lines;
mod sd_release;
mod state;

pub(crate) use lcd::{device as lcd_device, LcdDataCommand, LcdDevice};
pub(crate) use power_cycle::{quiesce_sd_power_lines, restore_sd_power_lines};
pub(crate) use sd_busy_probe::SdBusyProbe;
pub(crate) use state::{initialize, sd_idle_clocks, with_sd_selected, with_sd_selected_diagnostics};
