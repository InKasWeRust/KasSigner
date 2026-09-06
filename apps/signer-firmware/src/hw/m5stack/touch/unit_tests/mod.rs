use super::*;
use signer_firmware_core::input::touch::{TouchEventType, TouchPoint};

// Self-tests
// ═══════════════════════════════════════════════════════════════

/// Run touch subsystem tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let mut total = 6u32;

    // Test 1: TouchZone hit-test
    {
        let zone = TouchZone::new(100, 50, 120, 60); // x=100-219, y=50-109
        let ok = zone.contains(150, 70)     // inside
            && !zone.contains(50, 70)       // left of zone
            && !zone.contains(150, 120)     // below zone
            && zone.contains(100, 50)       // top-left corner (inclusive)
            && !zone.contains(220, 50);     // just outside right edge
        if ok { passed += 1; }
    }

    // Test 2: TouchTracker tap detection (tap on finger-down, instant)
    {
        let mut tracker = TouchTracker::new();
        let a1 = tracker.update(TouchState::NoTouch);
        // Finger down → tap fires immediately
        let a2 = tracker.update(TouchState::One(TouchPoint { x: 100, y: 100, event: TouchEventType::PressDown }));
        // Held → no repeat
        let a3 = tracker.update(TouchState::One(TouchPoint { x: 100, y: 100, event: TouchEventType::Contact }));
        // Release → nothing
        let a4 = tracker.update(TouchState::NoTouch);

        let ok = a1 == TouchAction::None
            && matches!(a2, TouchAction::Tap { x: 100, y: 100 })
            && a3 == TouchAction::None
            && a4 == TouchAction::None;
        if ok { passed += 1; }
    }

    // Test 3: No repeat while held, new tap after release+retouch
    {
        let mut tracker = TouchTracker::new();
        tracker.update(TouchState::NoTouch);
        // First tap
        let a1 = tracker.update(TouchState::One(TouchPoint { x: 100, y: 100, event: TouchEventType::PressDown }));
        // Held — no repeat
        let a2 = tracker.update(TouchState::One(TouchPoint { x: 150, y: 120, event: TouchEventType::Contact }));
        // Confirmed release (two consecutive no-touch samples).
        tracker.update(TouchState::NoTouch);
        tracker.update(TouchState::NoTouch);
        // New tap at different position
        let a3 = tracker.update(TouchState::One(TouchPoint { x: 200, y: 50, event: TouchEventType::PressDown }));

        let ok = matches!(a1, TouchAction::Tap { x: 100, y: 100 })
            && a2 == TouchAction::None
            && matches!(a3, TouchAction::Tap { x: 200, y: 50 });
        if ok { passed += 1; }
    }

    // Test 4: repeated PressDown samples while held must never retrigger.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 40, y: 50, event: TouchEventType::PressDown }));
        let repeat1 = tracker.update(TouchState::One(TouchPoint { x: 40, y: 50, event: TouchEventType::PressDown }));
        let repeat2 = tracker.update(TouchState::One(TouchPoint { x: 41, y: 50, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 40, y: 50 })
            && repeat1 == TouchAction::None
            && repeat2 == TouchAction::None;
        if ok { passed += 1; }
    }

    // Test 5: isolated NoTouch/I2C-miss samples do not re-arm a held finger.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 70, y: 80, event: TouchEventType::PressDown }));
        let gap = tracker.update(TouchState::NoTouch);
        let still_held = tracker.update(TouchState::One(TouchPoint { x: 70, y: 80, event: TouchEventType::PressDown }));
        tracker.update(TouchState::NoTouch);
        tracker.update(TouchState::NoTouch);
        let retouch = tracker.update(TouchState::One(TouchPoint { x: 90, y: 100, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 70, y: 80 })
            && gap == TouchAction::None
            && still_held == TouchAction::None
            && matches!(retouch, TouchAction::Tap { x: 90, y: 100 });
        if ok { passed += 1; }
    }

    // Test 6: the controller's explicit LiftUp event immediately re-arms navigation.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 120, y: 120, event: TouchEventType::PressDown }));
        let lifted = tracker.update(TouchState::One(TouchPoint { x: 120, y: 120, event: TouchEventType::LiftUp }));
        let next = tracker.update(TouchState::One(TouchPoint { x: 20, y: 20, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 120, y: 120 })
            && lifted == TouchAction::None
            && matches!(next, TouchAction::Tap { x: 20, y: 20 });
        if ok { passed += 1; }
    }

    // Test 7: a clearly new PressDown recovers after a missed release.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 160, y: 190, event: TouchEventType::PressDown }));
        let settings = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 160, y: 190 })
            && matches!(settings, TouchAction::Tap { x: 238, y: 188 });
        if ok { passed += 1; }
        total += 1;
    }

    // Test 8: repeated PressDown samples near a held finger remain suppressed.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 200, y: 180, event: TouchEventType::PressDown }));
        let repeat = tracker.update(TouchState::One(TouchPoint { x: 205, y: 184, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 200, y: 180 }) && repeat == TouchAction::None;
        if ok { passed += 1; }
        total += 1;
    }

    // Test 9: two release samples are enough to recover a clearly new press
    // at the same coordinates when the controller missed the final release.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::PressDown }));
        tracker.update(TouchState::NoTouch);
        tracker.update(TouchState::NoTouch);
        let retouch = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::PressDown }));
        let ok = matches!(first, TouchAction::Tap { x: 238, y: 188 })
            && matches!(retouch, TouchAction::Tap { x: 238, y: 188 });
        if ok { passed += 1; }
        total += 1;
    }

    // Test 10: a new FT6336U PressDown is authoritative even if the prior
    // screen transition happened without observing LiftUp.
    {
        let mut tracker = TouchTracker::new();
        let ack = tracker.update(TouchState::One(TouchPoint { x: 160, y: 190, event: TouchEventType::PressDown }));
        let settings = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::PressDown }));
        let ok = matches!(ack, TouchAction::Tap { x: 160, y: 190 })
            && matches!(settings, TouchAction::Tap { x: 238, y: 188 });
        if ok { passed += 1; }
        total += 1;
    }

    // Test 11: held-contact samples never synthesize duplicate taps.
    {
        let mut tracker = TouchTracker::new();
        let first = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::PressDown }));
        let held = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::Contact }));
        let idle_event = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::NoEvent }));
        let ok = matches!(first, TouchAction::Tap { x: 238, y: 188 })
            && held == TouchAction::None && idle_event == TouchAction::None;
        if ok { passed += 1; }
        total += 1;
    }

    // Test 12: first Contact after a clean release recovers a missed PressDown; held Contact never repeats.
    {
        let mut tracker = TouchTracker::new();
        let ack = tracker.update(TouchState::One(TouchPoint { x: 160, y: 190, event: TouchEventType::PressDown }));
        tracker.update(TouchState::One(TouchPoint { x: 160, y: 190, event: TouchEventType::LiftUp }));
        let contact = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::Contact }));
        let held = tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::Contact }));
        tracker.update(TouchState::One(TouchPoint { x: 238, y: 188, event: TouchEventType::LiftUp }));
        let ok = matches!(ack, TouchAction::Tap { x: 160, y: 190 })
            && matches!(contact, TouchAction::Tap { x: 238, y: 188 })
            && held == TouchAction::None;
        if ok { passed += 1; }
        total += 1;
    }


    // Test 13: every redrawn screen requires two consecutive NoTouch samples
    // (or an explicit LiftUp) before a new PressDown can activate the screen.
    {
        let mut tracker = TouchTracker::new();
        let home = tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::PressDown }));
        tracker.require_release();
        let held = tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::Contact }));
        let release1 = tracker.update(TouchState::NoTouch);
        let false_edge = tracker.update(TouchState::One(TouchPoint { x: 200, y: 115, event: TouchEventType::PressDown }));
        for _ in 0..2 { tracker.update(TouchState::NoTouch); }
        let settings = tracker.update(TouchState::One(TouchPoint { x: 160, y: 67, event: TouchEventType::PressDown }));
        let ok = matches!(home, TouchAction::Tap { x: 226, y: 190 })
            && held == TouchAction::None && release1 == TouchAction::None
            && false_edge == TouchAction::None
            && matches!(settings, TouchAction::Tap { x: 160, y: 67 });
        if ok { passed += 1; }
        total += 1;
    }

    // Test 14: a held finger cannot click through a redraw barrier.
    {
        let mut tracker = TouchTracker::new();
        tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::PressDown }));
        tracker.require_release();
        let repeat = tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::PressDown }));
        tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::LiftUp }));
        let next = tracker.update(TouchState::One(TouchPoint { x: 160, y: 67, event: TouchEventType::PressDown }));
        let ok = repeat == TouchAction::None && matches!(next, TouchAction::Tap { x: 160, y: 67 });
        if ok { passed += 1; }
        total += 1;
    }

    (passed, total)
}

#[test]
fn all_vectors_pass() {
    let (passed, total) = run_tests();
    assert_eq!(passed, total);
}

#[test]
fn redraw_no_touch_release_does_not_reactivate_same_position() {
    let mut tracker = TouchTracker::new();
    let first = tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::PressDown }));
    assert!(matches!(first, TouchAction::Tap { .. }));
    tracker.require_release();
    for _ in 0..2 { tracker.update(TouchState::NoTouch); }
    assert!(!tracker.release_required());
    let stale = tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::Contact }));
    assert_eq!(stale, TouchAction::None);
}

#[test]
fn redraw_inferred_release_allows_clearly_moved_contact_recovery() {
    let mut tracker = TouchTracker::new();
    tracker.update(TouchState::One(TouchPoint { x: 226, y: 190, event: TouchEventType::PressDown }));
    tracker.require_release();
    for _ in 0..2 { tracker.update(TouchState::NoTouch); }
    let next = tracker.update(TouchState::One(TouchPoint { x: 120, y: 80, event: TouchEventType::Contact }));
    assert_eq!(next, TouchAction::Tap { x: 120, y: 80 });
}
