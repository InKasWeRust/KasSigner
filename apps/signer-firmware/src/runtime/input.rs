// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Runtime input facade.
//!
//! Physical input, menus, navigation state, touch routing, and wallet control
//! remain isolated behind one subsystem boundary.


mod button;
mod menu;
mod routing;
mod state;
mod wallet_app;

#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
pub use button::Button;
#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
pub use button::ButtonEvent;
pub use menu::Menu;
pub use routing::HandlerGroup;
pub use state::AppState;
pub(crate) use state::is_scan_state;
pub(crate) use state::CONFIRM_MENU_ITEMS;
#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]
pub use wallet_app::Action;
pub use wallet_app::WalletApp;

#[cfg(any(
    test,
    all(feature = "verbose-boot", not(feature = "skip-tests"))
))]
#[path = "unit_tests/input_tests.rs"]
pub mod unit_tests;
