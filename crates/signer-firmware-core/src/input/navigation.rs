//! Pure fixed-capacity menu navigation and paging state.

use super::button::ButtonEvent;

pub const MAX_MENU_ITEMS: usize = 16;

pub struct Menu {
    pub count: u8,
    pub cursor: u8,
    pub scroll: u8,
    pub items: [&'static str; MAX_MENU_ITEMS],
}

impl Menu {
    pub const MAX_VISIBLE: u8 = 4;

    pub const fn new() -> Self {
        Self {
            count: 0,
            cursor: 0,
            scroll: 0,
            items: [""; MAX_MENU_ITEMS],
        }
    }

    pub fn from_items(labels: &[&'static str]) -> Self {
        let mut menu = Self::new();
        let count = labels.len().min(MAX_MENU_ITEMS);
        menu.items[..count].copy_from_slice(&labels[..count]);
        menu.count = count as u8;
        menu
    }

    pub fn handle(&mut self, event: ButtonEvent) -> Option<u8> {
        match event {
            ButtonEvent::ShortPress => {
                if self.count > 0 {
                    self.cursor = (self.cursor + 1) % self.count;
                }
                None
            }
            ButtonEvent::LongPress => Some(self.cursor),
            ButtonEvent::None => None,
        }
    }

    pub fn reset(&mut self) {
        self.cursor = 0;
        self.scroll = 0;
    }

    pub fn page_up(&mut self) -> bool {
        let Some(previous) = previous_page(self.scroll) else {
            return false;
        };
        self.scroll = previous;
        true
    }

    pub fn page_down(&mut self) -> bool {
        let Some(next) = next_page(self.scroll, self.count) else {
            return false;
        };
        self.scroll = next;
        true
    }

    pub const fn can_page_up(&self) -> bool {
        self.scroll > 0
    }

    pub const fn can_page_down(&self) -> bool {
        next_page(self.scroll, self.count).is_some()
    }

    pub const fn total_pages(&self) -> u8 {
        total_pages(self.count)
    }

    pub const fn current_page(&self) -> u8 {
        self.scroll / Self::MAX_VISIBLE
    }

    pub const fn visible_to_absolute(&self, visible_index: u8) -> u8 {
        self.scroll.saturating_add(visible_index)
    }
}

impl Default for Menu {
    fn default() -> Self {
        Self::new()
    }
}

pub const fn previous_page(scroll: u8) -> Option<u8> {
    if scroll == 0 {
        None
    } else {
        Some(scroll.saturating_sub(Menu::MAX_VISIBLE))
    }
}

pub const fn next_page(scroll: u8, count: u8) -> Option<u8> {
    if count <= Menu::MAX_VISIBLE {
        return None;
    }
    let next = scroll.saturating_add(Menu::MAX_VISIBLE);
    if next < count {
        Some(next)
    } else {
        None
    }
}

pub const fn total_pages(count: u8) -> u8 {
    if count == 0 {
        1
    } else {
        count.saturating_add(Menu::MAX_VISIBLE - 1) / Menu::MAX_VISIBLE
    }
}
