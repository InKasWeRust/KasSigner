//! Pure debounced-button state transitions.

pub const BOOT_DEBOUNCE_MS: u32 = 50;
pub const BOOT_LONG_PRESS_MS: u32 = 800;
pub const PIR_DEBOUNCE_MS: u32 = 500;
pub const PIR_LONG_PRESS_MS: u32 = 2_000;
pub const PIR_COOLDOWN_MS: u32 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ButtonEvent {
    ShortPress,
    LongPress,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ButtonConfig {
    pub debounce_ms: u32,
    pub long_press_ms: u32,
    pub cooldown_ms: u32,
}

impl ButtonConfig {
    pub const fn boot() -> Self {
        Self {
            debounce_ms: BOOT_DEBOUNCE_MS,
            long_press_ms: BOOT_LONG_PRESS_MS,
            cooldown_ms: 0,
        }
    }

    pub const fn pir() -> Self {
        Self {
            debounce_ms: PIR_DEBOUNCE_MS,
            long_press_ms: PIR_LONG_PRESS_MS,
            cooldown_ms: PIR_COOLDOWN_MS,
        }
    }
}

/// Debounced button state machine with hold detection and optional cooldown.
pub struct Button {
    was_pressed: bool,
    press_start: u32,
    last_event: Option<u32>,
    time_ms: u32,
    pending_press: bool,
    config: ButtonConfig,
}

impl Button {
    pub const fn new() -> Self {
        Self::with_config(ButtonConfig::boot())
    }

    pub const fn new_pir() -> Self {
        Self::with_config(ButtonConfig::pir())
    }

    pub const fn with_config(config: ButtonConfig) -> Self {
        Self {
            was_pressed: false,
            press_start: 0,
            last_event: None,
            time_ms: 0,
            pending_press: false,
            config,
        }
    }

    /// Advance the state machine and return an edge-triggered event.
    pub fn update(&mut self, active: bool, elapsed_ms: u32) -> ButtonEvent {
        self.time_ms = self.time_ms.wrapping_add(elapsed_ms);

        if self.cooldown_active() {
            self.was_pressed = active;
            self.pending_press = false;
            return ButtonEvent::None;
        }

        if active && !self.was_pressed {
            self.begin_press();
            return ButtonEvent::None;
        }
        if !active && self.was_pressed {
            return self.finish_press();
        }
        ButtonEvent::None
    }

    fn cooldown_active(&self) -> bool {
        if self.config.cooldown_ms == 0 {
            return false;
        }
        match self.last_event {
            Some(last) => self.time_ms.wrapping_sub(last) < self.config.cooldown_ms,
            None => false,
        }
    }

    fn begin_press(&mut self) {
        self.press_start = self.time_ms;
        self.pending_press = true;
        self.was_pressed = true;
    }

    fn finish_press(&mut self) -> ButtonEvent {
        self.was_pressed = false;
        if !core::mem::take(&mut self.pending_press) {
            return ButtonEvent::None;
        }
        let duration = self.time_ms.wrapping_sub(self.press_start);
        let event = classify_duration(duration, self.config);
        if event != ButtonEvent::None {
            self.last_event = Some(self.time_ms);
        }
        event
    }
}

impl Default for Button {
    fn default() -> Self {
        Self::new()
    }
}

pub const fn classify_duration(duration_ms: u32, config: ButtonConfig) -> ButtonEvent {
    if duration_ms >= config.long_press_ms {
        ButtonEvent::LongPress
    } else if duration_ms >= config.debounce_ms {
        ButtonEvent::ShortPress
    } else {
        ButtonEvent::None
    }
}
