//! CoreS3 SD protocol over the board-owned shared SPI2 bus.

mod crc;
mod diagnostics;
mod force_erase_trace;
mod initialization;
mod lock;
mod speed;
mod status;
mod wire;
mod wire_helpers;

pub(super) use initialization::initialize_card;
pub(in crate::hw::m5stack::storage::transport) use lock::card_is_locked;
pub(in crate::hw::m5stack::storage::transport) use lock::{
    ForceEraseAttempt, force_erase_locked_card, unlock_card,
};
pub(super) use status::card_status_r2;
pub(super) use wire::{
    command_data_at, finish_transaction_at, read_exact, require_success, transfer_byte, write_all,
};
pub(in crate::hw::m5stack::storage::transport) use wire::{
    quiesce_for_power_cycle, restore_after_power_on,
};

pub(in crate::hw::m5stack::storage::transport) fn log_read_rejection_status(
    initialization_speed: bool,
) {
    match card_status_r2(initialization_speed) {
        Ok([r1, r2]) => crate::log!("[SD] CMD13 after CMD17 failure: R2=0x{:02x}{:02x}", r1, r2),
        Err(error) => crate::log!("[SD] CMD13 after CMD17 failure unavailable: {}", error),
    }
}

pub(in crate::hw::m5stack::storage::transport) use speed::{
    force_conservative_data_rate, legacy_data_speed,
};
