//! Pure menu hit-testing and paging helpers shared by touch controllers.

use crate::{
    hw::touch,
    runtime::input::Menu,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PagedMenuAction {
    None,
    PageChanged,
    Selected(u8),
}

pub(crate) fn selected_visible_item(
    menu: &Menu,
    zones: &[touch::TouchZone; 4],
    x: u16,
    y: u16,
) -> Option<u8> {
    zones.iter().enumerate().find_map(|(slot, zone)| {
        if !zone.contains(x, y) {
            return None;
        }
        let index = menu.visible_to_absolute(slot as u8);
        (index < menu.count).then_some(index)
    })
}

pub(crate) fn handle_paged_menu_touch(
    menu: &mut Menu,
    zones: &[touch::TouchZone; 4],
    page_up: &touch::TouchZone,
    page_down: &touch::TouchZone,
    x: u16,
    y: u16,
) -> PagedMenuAction {
    if page_up.contains(x, y) && menu.page_up() {
        return PagedMenuAction::PageChanged;
    }
    if page_down.contains(x, y) && menu.page_down() {
        return PagedMenuAction::PageChanged;
    }
    selected_visible_item(menu, zones, x, y)
        .map(PagedMenuAction::Selected)
        .unwrap_or(PagedMenuAction::None)
}
