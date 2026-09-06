//! CoreS3 microSD transport over the board-owned shared SPI2 bus.

use super::{Delay, SdCardType};

mod block;
mod capacity;
mod card;
mod card_recovery;
mod multi_block;
mod protocol;
mod power;

pub use block::sd_read_block;
pub(crate) use block::sd_write_block;
pub(crate) use card::{probe_boot_card, with_sd_card};
pub(crate) use power::power_cycle_card;
pub(crate) use card_recovery::{force_erase_locked_card_session, unlock_locked_card_session};
#[cfg(all(feature = "workflow-hil-auto", feature = "m5stack"))]
pub(crate) use card_recovery::workflow_force_erase_locked_card;
pub(crate) use multi_block::{fast_read_multi_block, fast_write_multi_block};

pub(crate) use capacity::sd_sector_count;

