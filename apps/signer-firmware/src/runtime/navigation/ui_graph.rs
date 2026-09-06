// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Authoritative production M5Stack UI graph.
//!
//! Stage 1 centralized the production state inventory and fixed menu surface.
//! Stage 2 routes formal menu selections through the navigation reducer while
//! labels, stable action IDs, declared destinations, guards, canonical entries,
//! Back metadata, and stage-3 operation effects remain authoritative here for runtime and QA.

#[derive(Clone, Copy)]
pub(crate) struct UiStateSpec {
    pub(crate) state: &'static str,
    pub(crate) owner: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) entry: &'static str,
    pub(crate) back: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) struct UiMenuItemSpec {
    pub(crate) menu: &'static str,
    pub(crate) index: u8,
    pub(crate) label: &'static str,
    pub(crate) action: &'static str,
    pub(crate) destination: &'static str,
    pub(crate) guard: &'static str,
    pub(crate) operation: Option<crate::runtime::data::OperationKind>,
}

pub(crate) struct UiMenuSpec {
    pub(crate) state: &'static str,
    pub(crate) back: &'static str,
    pub(crate) items: &'static [UiMenuItemSpec],
}

macro_rules! ui_state {
    ($state:ident, $owner:ident, $kind:ident, $entry:literal, $back:literal) => {
        UiStateSpec {
            state: stringify!($state),
            owner: stringify!($owner),
            kind: stringify!($kind),
            entry: $entry,
            back: $back,
        }
    };
}

macro_rules! ui_menu {
    ($menu:ident, $index:literal, $label:literal, $action:literal, $destination:ident, $guard:literal) => {
        UiMenuItemSpec {
            menu: stringify!($menu),
            index: $index,
            label: $label,
            action: $action,
            destination: stringify!($destination),
            guard: $guard,
            operation: None,
        }
    };
    ($menu:ident, $index:literal, $label:literal, $action:literal, $destination:ident, $guard:literal, $operation:ident) => {
        UiMenuItemSpec {
            menu: stringify!($menu),
            index: $index,
            label: $label,
            action: $action,
            destination: stringify!($destination),
            guard: $guard,
            operation: Some(crate::runtime::data::OperationKind::$operation),
        }
    };
}

include!("ui_graph/states.rs");
include!("ui_graph/menus.rs");

#[cfg(all(feature = "m5stack", feature = "provisioning-ui"))]
pub(crate) fn advanced_labels(pop_it_available: bool) -> &'static [&'static str] {
    if pop_it_available {
        &ADVANCED_MENU_LABELS
    } else {
        &ADVANCED_MENU_LABELS[..3]
    }
}

/// Cheap debug-time integrity check. The Python gate performs the exhaustive
/// source/AppState comparison and generates the checked-in artifacts.
pub(crate) fn validate_static_graph() -> bool {
    !PRODUCTION_STATES.is_empty()
        && !PRODUCTION_MENUS.is_empty()
        && PRODUCTION_STATES.iter().all(valid_state)
        && PRODUCTION_MENUS.iter().all(valid_menu)
}

fn valid_state(state: &UiStateSpec) -> bool {
    !state.state.is_empty()
        && !state.owner.is_empty()
        && !state.kind.is_empty()
        && !state.entry.is_empty()
        && !state.back.is_empty()
}

fn valid_menu(menu: &UiMenuSpec) -> bool {
    !menu.state.is_empty()
        && !menu.back.is_empty()
        && !menu.items.is_empty()
        && menu.items.iter().enumerate().all(|(expected, item)| {
            item.menu == menu.state
                && usize::from(item.index) == expected
                && !item.label.is_empty()
                && !item.action.is_empty()
                && !item.destination.is_empty()
                && !item.guard.is_empty()
        })
}
