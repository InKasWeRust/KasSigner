//! Stage-2 graph-backed menu reducer.
//!
//! Formal menu controllers emit only an item index. This module resolves the
//! authoritative stage-1 menu row, enforces its declared guard, and resolves
//! the concrete `AppState` payload needed by the pure navigation reducer.

mod catalog;
mod routes;

use crate::runtime::{data::{AppData, OperationKind}, input::AppState};

#[derive(Clone, Copy)]
pub(super) struct MenuResolution {
    pub(super) destination: AppState,
    pub(super) operation: Option<OperationKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolveError {
    MissingItem,
    GuardDenied,
    MissingDestination,
}

pub(super) fn resolve(
    ad: &AppData,
    state: AppState,
    index: u8,
) -> Result<MenuResolution, ResolveError> {
    let item = catalog::item_for(state, index).ok_or(ResolveError::MissingItem)?;
    if !guard_allows(ad, item.guard) {
        crate::log!("   NAV menu guard rejected {} ({})", item.action, item.guard);
        return Err(ResolveError::GuardDenied);
    }
    Ok(MenuResolution {
        destination: routes::destination(state, index).ok_or(ResolveError::MissingDestination)?,
        operation: item.operation,
    })
}

fn guard_allows(ad: &AppData, guard: &str) -> bool {
    match guard {
        "always" | "m5stack" => true,
        "seed_loaded" => ad.wallet.seeds.seed_loaded,
        "mnemonic_wallet" => mnemonic_words(ad).is_some(),
        "mnemonic_12_words" => mnemonic_words(ad) == Some(12),
        #[cfg(feature = "provisioning-ui")]
        "secure_boot_disabled" => super::production::pop_it_available(),
        // Hardware-present guards are kept fail-closed here. Hardware-owning
        // controllers validate those capabilities before emitting a fixed route;
        // Stage 3 will move those facts into typed operation events.
        "review_complete" => ad.navigation.app.review_authorized
            && ad.navigation.app.total_inputs > 0,
        "review_available" => ad.navigation.app.review_pages > 0,
        "camera_available" | "sd_present" | "sd_present_and_seed_loaded"
        | "sd_jpeg_available" | "sd_covenant_available" => false,
        _ => false,
    }
}

fn mnemonic_words(ad: &AppData) -> Option<u8> {
    ad.wallet.seeds.active_source.mnemonic_word_count()
}
