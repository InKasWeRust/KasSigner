use crate::input::button::{
    classify_duration, Button, ButtonConfig, ButtonEvent, BOOT_DEBOUNCE_MS, BOOT_LONG_PRESS_MS,
    PIR_COOLDOWN_MS,
};

#[test]
fn duration_classification_covers_debounce_and_long_press_boundaries() {
    let config = ButtonConfig::boot();
    assert_eq!(
        classify_duration(BOOT_DEBOUNCE_MS - 1, config),
        ButtonEvent::None
    );
    assert_eq!(
        classify_duration(BOOT_DEBOUNCE_MS, config),
        ButtonEvent::ShortPress
    );
    assert_eq!(
        classify_duration(BOOT_LONG_PRESS_MS - 1, config),
        ButtonEvent::ShortPress
    );
    assert_eq!(
        classify_duration(BOOT_LONG_PRESS_MS, config),
        ButtonEvent::LongPress
    );
}

#[test]
fn button_state_machine_emits_edge_events_and_ignores_bounce() {
    let mut button = Button::new();
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(
        button.update(false, BOOT_DEBOUNCE_MS - 2),
        ButtonEvent::None
    );
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(true, BOOT_DEBOUNCE_MS), ButtonEvent::None);
    assert_eq!(button.update(false, 0), ButtonEvent::ShortPress);

    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(
        button.update(false, BOOT_LONG_PRESS_MS),
        ButtonEvent::LongPress
    );
}

#[test]
fn pir_cooldown_suppresses_complete_presses_until_elapsed() {
    let mut button = Button::new_pir();
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(false, 500), ButtonEvent::ShortPress);
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(false, 500), ButtonEvent::None);
    assert_eq!(button.update(false, PIR_COOLDOWN_MS), ButtonEvent::None);
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(false, 500), ButtonEvent::ShortPress);
}

#[test]
fn wrapping_clock_preserves_press_duration() {
    let config = ButtonConfig {
        debounce_ms: 5,
        long_press_ms: 10,
        cooldown_ms: 0,
    };
    let mut button = Button::with_config(config);
    assert_eq!(button.update(false, u32::MAX - 2), ButtonEvent::None);
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(false, 10), ButtonEvent::LongPress);
}

#[test]
fn button_default_matches_boot_constructor() {
    let mut button = Button::default();
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(
        button.update(false, BOOT_DEBOUNCE_MS),
        ButtonEvent::ShortPress
    );
}

#[test]
fn cooldown_suppressed_hold_releases_without_pending_press() {
    let mut button = Button::new_pir();

    // Establish a real event so the PIR cooldown becomes active.
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(false, 500), ButtonEvent::ShortPress);

    // Press during cooldown. The state machine deliberately remembers the
    // physical level but clears pending_press so this press cannot become an
    // event after the cooldown expires.
    assert_eq!(button.update(true, 1), ButtonEvent::None);
    assert_eq!(button.update(true, PIR_COOLDOWN_MS), ButtonEvent::None);

    // Releasing after cooldown reaches finish_press() with pending_press=false.
    // This is a real recovery branch, not an impossible path: it must return
    // None rather than manufacturing a delayed PIR event.
    assert_eq!(button.update(false, 0), ButtonEvent::None);
}
