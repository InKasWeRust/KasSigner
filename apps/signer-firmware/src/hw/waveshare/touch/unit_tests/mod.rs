use super::*;

pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    let zone = TouchZone::new(100, 50, 120, 60);
    if zone.contains(150, 70)
        && !zone.contains(50, 70)
        && !zone.contains(150, 120)
        && zone.contains(100, 50)
        && !zone.contains(220, 50)
    {
        passed += 1;
    }

    let mut tracker = TouchTracker::new();
    let press = TouchPoint { x: 150, y: 100, event: TouchEventType::PressDown };
    let contact = TouchPoint { x: 150, y: 100, event: TouchEventType::Contact };
    let lift = TouchPoint { x: 150, y: 100, event: TouchEventType::LiftUp };
    if tracker.update(TouchState::One(press), HwGesture::None) == TouchAction::None
        && tracker.update(TouchState::One(contact), HwGesture::None) == TouchAction::None
        && tracker.update(TouchState::One(lift), HwGesture::None)
            == (TouchAction::Tap { x: 150, y: 100 })
    {
        passed += 1;
    }

    let mut tracker = TouchTracker::new();
    if tracker.update(TouchState::One(contact), HwGesture::None) == TouchAction::None
        && tracker.update(TouchState::NoTouch, HwGesture::None)
            == (TouchAction::Tap { x: 150, y: 100 })
    {
        passed += 1;
    }

    let mut tracker = TouchTracker::new();
    tracker.update(TouchState::One(press), HwGesture::None);
    let drag = TouchPoint { x: 155, y: 96, event: TouchEventType::Contact };
    if tracker.update(TouchState::One(drag), HwGesture::None)
        == (TouchAction::Drag { x: 155, y: 96, dx: 5, dy: -4 })
    {
        passed += 1;
    }

    let mut tracker = TouchTracker::new();
    if tracker.update(TouchState::One(contact), HwGesture::SwipeLeft) == TouchAction::SwipeUp
        && tracker.update(TouchState::One(contact), HwGesture::SwipeLeft) == TouchAction::None
    {
        passed += 1;
    }

    (passed, total)
}

#[test]
fn all_vectors_pass() {
    let (passed, total) = run_tests();
    assert_eq!(passed, total);
}
