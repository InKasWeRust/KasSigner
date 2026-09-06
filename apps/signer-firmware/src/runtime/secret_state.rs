//! Internal-SRAM ownership for the long-lived secret-bearing application root.

use super::data::AppData;
use static_cell::StaticCell;

static APP_DATA: StaticCell<AppData> = StaticCell::new();

/// Initialize the application root exactly once in static internal DRAM.
///
/// The root object itself remains in internal DRAM. Bounded bulk transaction
/// storage may be heap-backed in PSRAM, but secret key material and ownership
/// state remain rooted in this static application object.
#[inline(never)]
pub(crate) fn initialize() -> &'static mut AppData {
    match AppData::try_initialize(&APP_DATA) {
        Ok(data) => data.into_mut(),
        Err(()) => {
            crate::log!("FATAL: runtime state allocation failed");
            loop { core::hint::spin_loop(); }
        }
    }
}
