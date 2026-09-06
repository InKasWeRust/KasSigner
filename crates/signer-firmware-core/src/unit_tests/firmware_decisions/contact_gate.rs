use crate::input::touch::{
    contact_gate::ContactGate, TouchAction, TouchEventType, TouchPoint, TouchState,
};

fn point(x: u16, y: u16, event: TouchEventType) -> TouchState {
    TouchState::One(TouchPoint { x, y, event })
}

#[test]
fn missed_release_recovers_on_distinct_press() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(160, 190, TouchEventType::PressDown)),
        TouchAction::Tap { x: 160, y: 190 }
    );
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::PressDown)),
        TouchAction::Tap { x: 238, y: 188 }
    );
}

#[test]
fn held_press_is_suppressed_but_two_release_samples_rearm_same_location() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::PressDown)),
        TouchAction::Tap { x: 238, y: 188 }
    );
    assert_eq!(
        gate.update(point(240, 190, TouchEventType::PressDown)),
        TouchAction::None
    );
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::PressDown)),
        TouchAction::Tap { x: 238, y: 188 }
    );
}

#[test]
fn first_contact_after_confirmed_release_recovers_missed_press_down() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(160, 190, TouchEventType::PressDown)),
        TouchAction::Tap { x: 160, y: 190 }
    );
    assert_eq!(
        gate.update(point(160, 190, TouchEventType::LiftUp)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::Contact)),
        TouchAction::Tap { x: 238, y: 188 }
    );
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::Contact)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(238, 188, TouchEventType::LiftUp)),
        TouchAction::None
    );
}

#[test]
fn screen_transition_requires_release_before_next_screen_contact() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::PressDown)),
        TouchAction::Tap { x: 226, y: 190 }
    );
    gate.require_release();
    assert!(gate.release_required());
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::Contact)),
        TouchAction::None
    );
    assert!(gate.release_required());
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert!(gate.release_required());
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert!(gate.release_required());
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::Contact)),
        TouchAction::None
    );
    assert!(gate.release_required());
    for _ in 0..2 {
        assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    }
    assert!(!gate.release_required());
    assert_eq!(
        gate.update(point(160, 67, TouchEventType::Contact)),
        TouchAction::Tap { x: 160, y: 67 }
    );
    assert_eq!(
        gate.update(point(160, 67, TouchEventType::Contact)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(160, 67, TouchEventType::LiftUp)),
        TouchAction::None
    );
}

#[test]
fn clean_screen_transition_rearms_after_two_no_touch_samples() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::PressDown)),
        TouchAction::Tap { x: 226, y: 190 }
    );
    gate.require_release();
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert!(gate.release_required());
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert!(!gate.release_required());
    assert_eq!(
        gate.update(point(160, 67, TouchEventType::PressDown)),
        TouchAction::Tap { x: 160, y: 67 }
    );
}

#[test]
fn screen_transition_liftup_rearms_without_click_through() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::PressDown)),
        TouchAction::Tap { x: 226, y: 190 }
    );
    gate.require_release();
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::PressDown)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(226, 190, TouchEventType::LiftUp)),
        TouchAction::None
    );
    assert!(!gate.release_required());
    assert_eq!(
        gate.update(point(160, 67, TouchEventType::PressDown)),
        TouchAction::Tap { x: 160, y: 67 }
    );
}

#[test]
fn redraw_barrier_accepts_clearly_moved_explicit_press_without_waiting() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(220, 168, TouchEventType::PressDown)),
        TouchAction::Tap { x: 220, y: 168 }
    );
    gate.require_release();
    assert_eq!(
        gate.update(point(220, 168, TouchEventType::PressDown)),
        TouchAction::None
    );
    assert!(gate.release_required());
    assert_eq!(
        gate.update(point(180, 68, TouchEventType::PressDown)),
        TouchAction::Tap { x: 180, y: 68 }
    );
    assert!(!gate.release_required());
}

#[test]
fn idle_no_touch_noevent_and_y_only_motion_cover_remaining_contact_edges() {
    let mut gate = ContactGate::default();
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(
        gate.update(point(100, 100, TouchEventType::NoEvent)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(100, 100, TouchEventType::PressDown)),
        TouchAction::Tap { x: 100, y: 100 }
    );
    assert_eq!(
        gate.update(point(100, 140, TouchEventType::PressDown)),
        TouchAction::Tap { x: 100, y: 140 }
    );
}

#[test]
fn inferred_release_guard_rejects_same_contact_but_accepts_y_only_motion() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(120, 120, TouchEventType::PressDown)),
        TouchAction::Tap { x: 120, y: 120 }
    );
    gate.require_release();
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert!(!gate.release_required());

    // NoTouch-only barrier completion carries one stale-edge guard.
    assert_eq!(
        gate.update(point(120, 120, TouchEventType::Contact)),
        TouchAction::None
    );
    assert_eq!(
        gate.update(point(120, 120, TouchEventType::LiftUp)),
        TouchAction::None
    );

    gate.require_release();
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(gate.update(TouchState::NoTouch), TouchAction::None);
    assert_eq!(
        gate.update(point(120, 160, TouchEventType::Contact)),
        TouchAction::Tap { x: 120, y: 160 }
    );
}

#[test]
fn strict_release_barrier_rejects_moved_press_until_physical_release() {
    let mut gate = ContactGate::new();
    assert_eq!(
        gate.update(point(70, 90, TouchEventType::PressDown)),
        TouchAction::Tap { x: 70, y: 90 }
    );
    gate.require_strict_release();
    assert!(gate.release_required());
    assert_eq!(
        gate.update(point(180, 90, TouchEventType::PressDown)),
        TouchAction::None
    );
    assert!(gate.release_required());
    assert_eq!(
        gate.update(point(180, 90, TouchEventType::LiftUp)),
        TouchAction::None
    );
    assert!(!gate.release_required());
    assert_eq!(
        gate.update(point(180, 90, TouchEventType::PressDown)),
        TouchAction::Tap { x: 180, y: 90 }
    );
}
