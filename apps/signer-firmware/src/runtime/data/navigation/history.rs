use crate::runtime::input::AppState;

const NAV_HISTORY_CAPACITY: usize = 32;

/// Bounded history of committed production screens.
///
/// Stage 2 replaces scattered menu-specific `*_return` fields with one
/// navigation-owned stack. Thirty-two entries cover the longest supported
/// 24-word and steganography journeys while remaining fixed and allocation-free.
pub(crate) struct NavigationHistory {
    entries: [AppState; NAV_HISTORY_CAPACITY],
    len: u8,
}

impl NavigationHistory {
    pub(crate) const fn new() -> Self {
        Self { entries: [AppState::MainMenu; NAV_HISTORY_CAPACITY], len: 0 }
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn push(&mut self, state: AppState) {
        if self.peek() == Some(state) {
            return;
        }
        let len = usize::from(self.len);
        if len < NAV_HISTORY_CAPACITY {
            self.entries[len] = state;
            self.len = self.len.saturating_add(1);
            return;
        }
        self.entries.copy_within(1..NAV_HISTORY_CAPACITY, 0);
        self.entries[NAV_HISTORY_CAPACITY - 1] = state;
    }

    pub(crate) fn target(&self, candidates: &[AppState]) -> Option<AppState> {
        let mut index = usize::from(self.len);
        while index > 0 {
            index -= 1;
            let state = self.entries[index];
            if candidates.contains(&state) { return Some(state); }
        }
        None
    }

    pub(crate) fn pop_to(&mut self, target: AppState) {
        while let Some(state) = self.pop() {
            if state == target { break; }
        }
    }

    pub(crate) fn pop(&mut self) -> Option<AppState> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.entries[usize::from(self.len)])
    }

    pub(crate) fn peek(&self) -> Option<AppState> {
        self.len.checked_sub(1).map(|index| self.entries[usize::from(index)])
    }

}
