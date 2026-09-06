//! Authoritative production Home routes.

use crate::runtime::{data::OperationKind, input::AppState};
use super::NavigationOwner;

pub(super) fn root_route(index: usize) -> Option<(AppState, NavigationOwner)> {
    use NavigationOwner::*;
    match index {
        0 => Some((AppState::SeedsMenu, Seeds)),
        1 => Some((AppState::ScanQR, Signing)),
        2 => Some((AppState::SeedsMenu, Seeds)),
        3 => Some((AppState::SettingsMenu, Settings)),
        _ => None,
    }
}

pub(super) fn root_operation(index: usize) -> Option<OperationKind> {
    match index {
        0 => Some(OperationKind::ConnectKasSee),
        _ => None,
    }
}

pub(super) fn main_menu_target(index: usize) -> Option<AppState> {
    root_route(index).map(|(state, _)| state)
}

pub(crate) fn main_menu_target_at(x: u16, y: u16) -> Option<(usize, AppState)> {
    crate::ui::layout::HOME_GRID_ZONES
        .iter()
        .position(|zone| zone.contains(x, y))
        .and_then(|index| main_menu_target(index).map(|state| (index, state)))
}

pub(super) fn transition_allowed(state: AppState) -> bool {
    matches!(state, AppState::ShowAddress | AppState::ScanQR | AppState::SeedsMenu | AppState::SettingsMenu | AppState::ExportKpub)
}
