//! Runtime SD data-rate policy for CoreS3 cards that reject the normal data clock.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hw::m5stack::storage::SdCardType;

static FORCE_CONSERVATIVE_DATA_RATE: AtomicBool = AtomicBool::new(false);

pub(in crate::hw::m5stack::storage::transport) fn legacy_data_speed(card_type: SdCardType) -> bool {
    !matches!(card_type, SdCardType::SdV2Hc)
        || FORCE_CONSERVATIVE_DATA_RATE.load(Ordering::Relaxed)
}

pub(in crate::hw::m5stack::storage::transport) fn force_conservative_data_rate() {
    FORCE_CONSERVATIVE_DATA_RATE.store(true, Ordering::Relaxed);
    crate::log!("[SD] falling back to conservative SPI data rate for this boot");
}
