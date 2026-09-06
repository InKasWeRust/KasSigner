use crate::input::{
    button::ButtonEvent,
    navigation::{next_page, previous_page, total_pages, Menu, MAX_MENU_ITEMS},
};

#[test]
fn menu_button_navigation_wraps_and_selects() {
    let mut menu = Menu::from_items(&["one", "two", "three"]);
    assert_eq!(menu.handle(ButtonEvent::ShortPress), None);
    assert_eq!(menu.cursor, 1);
    assert_eq!(menu.handle(ButtonEvent::ShortPress), None);
    assert_eq!(menu.cursor, 2);
    assert_eq!(menu.handle(ButtonEvent::ShortPress), None);
    assert_eq!(menu.cursor, 0);
    assert_eq!(menu.handle(ButtonEvent::LongPress), Some(0));
    assert_eq!(menu.handle(ButtonEvent::None), None);
}

#[test]
fn menu_capacity_and_empty_behavior_are_bounded() {
    let labels = ["item"; MAX_MENU_ITEMS + 2];
    let mut menu = Menu::from_items(&labels);
    assert_eq!(menu.count as usize, MAX_MENU_ITEMS);
    menu.reset();
    assert_eq!((menu.cursor, menu.scroll), (0, 0));

    let mut empty = Menu::new();
    assert_eq!(empty.handle(ButtonEvent::ShortPress), None);
    assert_eq!(empty.handle(ButtonEvent::LongPress), Some(0));
}

#[test]
fn paging_helpers_cover_boundaries_and_partial_pages() {
    assert_eq!(previous_page(0), None);
    assert_eq!(previous_page(4), Some(0));
    assert_eq!(previous_page(6), Some(2));
    assert_eq!(next_page(0, 4), None);
    assert_eq!(next_page(0, 5), Some(4));
    assert_eq!(next_page(4, 5), None);
    assert_eq!(total_pages(0), 1);
    assert_eq!(total_pages(4), 1);
    assert_eq!(total_pages(5), 2);
    assert_eq!(total_pages(16), 4);

    let mut menu = Menu::from_items(&["0", "1", "2", "3", "4", "5", "6", "7", "8"]);
    assert!(!menu.can_page_up());
    assert!(menu.can_page_down());
    assert!(menu.page_down());
    assert_eq!(menu.scroll, 4);
    assert_eq!(menu.current_page(), 1);
    assert_eq!(menu.visible_to_absolute(2), 6);
    assert!(menu.page_down());
    assert_eq!(menu.scroll, 8);
    assert!(!menu.page_down());
    assert!(menu.page_up());
    assert_eq!(menu.scroll, 4);
}

#[test]
fn menu_default_and_instance_total_pages_match_constructor_helpers() {
    let menu = Menu::default();
    assert_eq!((menu.count, menu.cursor, menu.scroll), (0, 0, 0));
    assert_eq!(menu.total_pages(), 1);
    let menu = Menu::from_items(&["0", "1", "2", "3", "4"]);
    assert_eq!(menu.total_pages(), 2);
}
