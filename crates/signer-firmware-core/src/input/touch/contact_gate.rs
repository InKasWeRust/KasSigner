//! Pure edge-triggered touch-contact gate for controllers that can miss release samples.
//!
//! The reducer preserves the distinction between PressDown and Contact. It
//! debounces isolated NoTouch samples, suppresses held-finger repeats, and can
//! recover when a clearly new PressDown arrives after a missed LiftUp.

use super::{TouchAction, TouchEventType, TouchPoint, TouchState};

const RELEASE_CONFIRM_SAMPLES: u8 = 2;
const MISSED_RELEASE_DISTANCE: u16 = 24;

pub struct ContactGate {
    is_down: bool,
    release_samples: u8,
    last_x: u16,
    last_y: u16,
    release_required: bool,
    barrier_contact_seen: bool,
    barrier_release_probe: bool,
    inferred_release_guard: bool,
    strict_release: bool,
}

impl ContactGate {
    pub const fn new() -> Self {
        Self {
            is_down: false,
            release_samples: 0,
            last_x: 0,
            last_y: 0,
            release_required: false,
            barrier_contact_seen: false,
            barrier_release_probe: false,
            inferred_release_guard: false,
            strict_release: false,
        }
    }

    pub fn update(&mut self, state: TouchState) -> TouchAction {
        if self.release_required {
            return self.update_release_barrier(state);
        }
        match state {
            TouchState::NoTouch => self.observe_release(),
            TouchState::One(point) => self.observe_point(point),
        }
    }

    /// Start a new screen input epoch. The contact that activated the previous
    /// screen must be physically released before any event can reach the new
    /// screen. This prevents stale FT6336U Contact samples from being mistaken
    /// for—or suppressing—the next screen's first tap.
    pub fn require_release(&mut self) {
        self.begin_release_barrier(false);
    }

    /// Start a security-sensitive input epoch that cannot infer release from a
    /// moved PressDown. PIN/password entry requires an actual LiftUp or confirmed
    /// NoTouch sequence before another key may be accepted.
    pub fn require_strict_release(&mut self) {
        self.begin_release_barrier(true);
    }

    fn begin_release_barrier(&mut self, strict: bool) {
        self.release_required = true;
        self.release_samples = 0;
        self.barrier_contact_seen = false;
        self.barrier_release_probe = false;
        self.strict_release = strict;
    }

    pub const fn release_required(&self) -> bool {
        self.release_required
    }

    fn update_release_barrier(&mut self, state: TouchState) -> TouchAction {
        match state {
            TouchState::NoTouch => self.confirm_barrier_no_touch(),
            TouchState::One(point) if point.event == TouchEventType::LiftUp => {
                self.finish_release_barrier(false)
            }
            TouchState::One(point)
                if !self.strict_release
                    && point.event == TouchEventType::PressDown
                    && (moved_far(self.last_x, point.x) || moved_far(self.last_y, point.y)) =>
            {
                // A clearly moved hardware PressDown is an authoritative new
                // contact edge even if the controller omitted LiftUp/NoTouch
                // between screens. Accept it immediately so destination menus
                // remain responsive; same-position edges stay gated.
                self.finish_release_barrier(false);
                self.remember_contact(point.x, point.y);
                self.is_down = true;
                TouchAction::Tap {
                    x: point.x,
                    y: point.y,
                }
            }
            TouchState::One(_) => {
                self.release_samples = 0;
                self.barrier_contact_seen = true;
                TouchAction::None
            }
        }
    }

    fn confirm_barrier_no_touch(&mut self) -> TouchAction {
        self.release_samples = self.release_samples.saturating_add(1);
        if self.release_samples < RELEASE_CONFIRM_SAMPLES {
            return TouchAction::None;
        }
        if self.barrier_contact_seen && !self.barrier_release_probe {
            self.barrier_release_probe = true;
            self.release_samples = 0;
            return TouchAction::None;
        }
        self.finish_release_barrier(true)
    }

    fn finish_release_barrier(&mut self, inferred_from_no_touch: bool) -> TouchAction {
        self.confirm_release();
        self.release_required = false;
        self.barrier_contact_seen = false;
        self.barrier_release_probe = false;
        self.inferred_release_guard = inferred_from_no_touch;
        self.strict_release = false;
        TouchAction::None
    }

    fn observe_point(&mut self, point: TouchPoint) -> TouchAction {
        match point.event {
            TouchEventType::PressDown => self.observe_press_down(point.x, point.y),
            TouchEventType::Contact => self.observe_contact(point.x, point.y),
            other => self.observe_non_contact(other),
        }
    }

    fn observe_non_contact(&mut self, event: TouchEventType) -> TouchAction {
        if event == TouchEventType::LiftUp {
            self.confirm_release();
        }
        TouchAction::None
    }

    fn observe_release(&mut self) -> TouchAction {
        if self.is_down {
            self.release_samples = self.release_samples.saturating_add(1);
        }
        if self.release_samples >= RELEASE_CONFIRM_SAMPLES {
            self.confirm_release();
        }
        TouchAction::None
    }

    fn confirm_release(&mut self) {
        self.is_down = false;
        self.release_samples = 0;
    }

    fn observe_press_down(&mut self, x: u16, y: u16) -> TouchAction {
        // PressDown is the controller's explicit new-contact edge. Once a
        // release has been confirmed, trust that edge even at the same
        // coordinates so repeated pager/word taps remain responsive. The
        // inferred-release stale guard is reserved for Contact recovery.
        let clearly_new = self.press_is_new(x, y);
        self.remember_contact(x, y);
        if !clearly_new {
            return TouchAction::None;
        }
        self.inferred_release_guard = false;
        self.is_down = true;
        TouchAction::Tap { x, y }
    }

    fn press_is_new(&self, x: u16, y: u16) -> bool {
        // Two NoTouch samples call confirm_release(), which clears is_down before
        // another PressDown can be observed. Therefore a separate
        // release_samples >= 2 arm was unreachable while is_down remained true.
        if !self.is_down {
            return true;
        }
        moved_far(self.last_x, x) || moved_far(self.last_y, y)
    }

    fn observe_contact(&mut self, x: u16, y: u16) -> TouchAction {
        // FT6336U PressDown is edge-like and can be missed between polls. Once
        // the reducer has confirmed that no prior finger is down, the first
        // Contact can recover that missed edge. A redraw barrier cleared only
        // by NoTouch samples retains one spatial guard so transient transport
        // gaps cannot turn the same held finger into a destination-screen tap.
        let starts_new_touch = !self.is_down;
        if starts_new_touch && self.inferred_edge_is_stale(x, y) {
            self.remember_contact(x, y);
            self.is_down = true;
            return TouchAction::None;
        }
        self.remember_contact(x, y);
        self.is_down = true;
        if starts_new_touch {
            self.inferred_release_guard = false;
            TouchAction::Tap { x, y }
        } else {
            TouchAction::None
        }
    }

    fn inferred_edge_is_stale(&self, x: u16, y: u16) -> bool {
        self.inferred_release_guard && !moved_far(self.last_x, x) && !moved_far(self.last_y, y)
    }

    fn remember_contact(&mut self, x: u16, y: u16) {
        self.release_samples = 0;
        self.last_x = x;
        self.last_y = y;
    }
}

impl Default for ContactGate {
    fn default() -> Self {
        Self::new()
    }
}

fn moved_far(previous: u16, current: u16) -> bool {
    current.abs_diff(previous) >= MISSED_RELEASE_DISTANCE
}
