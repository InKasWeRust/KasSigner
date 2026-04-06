// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


// hw/touch.rs — FT6336U capacitive touch driver + TouchTracker
// 100% Rust, no-std, no-alloc
//
// The FT6336U is on the same internal I2C bus as AXP2101 and AW9523B
// (GPIO12=SDA, GPIO11=SCL). We borrow the I2C bus, not own it.
//
// Register map (FT6x36 family):
//   0x02: TD_STATUS  — [3:0] number of touch points (0, 1, or 2)
//   0x03: P1_XH      — [7:6] event flag, [3:0] X position high nibble
//   0x04: P1_XL      — [7:0] X position low byte
//   0x05: P1_YH      — [7:4] touch ID, [3:0] Y position high nibble
//   0x06: P1_YL      — [7:0] Y position low byte
//
// Event flags (bits [7:6] of P1_XH):
//   0b00 = Press Down
//   0b01 = Lift Up
//   0b10 = Contact
//   0b11 = No Event
//
// CoreS3 display is 320×240. Touch coordinates match display pixels
// when properly calibrated (x: 0-319, y: 0-239).
//
// With Rotation::Deg180, touch coords need to be flipped:
//   display_x = 319 - raw_x
//   display_y = 239 - raw_y

use esp_hal::i2c::master::I2c;

/// FT6336U I2C address (fixed, not configurable)
const FT6336U_ADDR: u8 = 0x38;

/// Touch status register — number of active touch points
const REG_TD_STATUS: u8 = 0x02;

// ═══════════════════════════════════════════════════════════════
// Touch Event Types
// ═══════════════════════════════════════════════════════════════

/// Raw touch event from the FT6336U
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchEventType {
    /// Finger just touched the screen
    PressDown,
    /// Finger just lifted off
    LiftUp,
    /// Finger is held on screen (continuous contact)
    Contact,
    /// No touch detected
    NoEvent,
}

/// A single touch point with coordinates and event type
#[derive(Debug, Clone, Copy)]
pub struct TouchPoint {
    /// X coordinate (0-319 after rotation correction)
    pub x: u16,
    /// Y coordinate (0-239 after rotation correction)
    pub y: u16,
    /// Type of touch event
    pub event: TouchEventType,
}

/// Result of polling the touch controller
#[derive(Debug, Clone, Copy)]
pub enum TouchState {
    /// No finger on screen
    NoTouch,
    /// One touch point detected
    One(TouchPoint),
    /// Two touch points detected (for future use)
    Two(TouchPoint, TouchPoint),
}

// ═══════════════════════════════════════════════════════════════
// High-level touch input for UI
// ═══════════════════════════════════════════════════════════════

/// Processed touch action for the app state machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchAction {
    /// No touch input
    None,
    /// Tap detected at (x, y) — finger down then up
    Tap { x: u16, y: u16 },
    /// Finger currently held down at (x, y)
    Hold { x: u16, y: u16 },
    /// Swipe up detected
    SwipeUp,
    /// Swipe down detected
    SwipeDown,
}

/// Touch state tracker — clean tap detection, no swipe
pub struct TouchTracker {
    /// Was finger down in previous poll?
    was_down: bool,
    /// Coordinates where finger first touched
    down_x: u16,
    down_y: u16,
}

impl TouchTracker {
    pub fn new() -> Self {
        Self {
            was_down: false,
            down_x: 0,
            down_y: 0,
        }
    }

    /// Process a TouchState into a TouchAction.
    /// Uses the FT6336U hardware PressDown event flag for reliable tap detection.
    /// The controller latches PressDown until read, so short taps are never lost
    /// even if we poll infrequently (e.g. during camera DMA blocking).
    pub fn update(&mut self, state: TouchState) -> TouchAction {
        match state {
            TouchState::NoTouch => {
                self.was_down = false;
                TouchAction::None
            }
            TouchState::One(pt) => {
                // Fire tap on PressDown event OR on first contact if not already down
                let is_new = match pt.event {
                    TouchEventType::PressDown => true,
                    _ => !self.was_down,
                };
                self.was_down = true;
                if is_new {
                    self.down_x = pt.x;
                    self.down_y = pt.y;
                    TouchAction::Tap { x: pt.x, y: pt.y }
                } else {
                    TouchAction::None
                }
            }
            TouchState::Two(_, _) => {
                TouchAction::None
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Raw I2C communication
// ═══════════════════════════════════════════════════════════════

/// Read touch data from FT6336U.
/// Borrows I2C mutably but does not own it.
/// Applies 180° rotation correction for CoreS3 display orientation.
pub fn read_touch(i2c: &mut I2c<'_, esp_hal::Blocking>) -> TouchState {
    // Read 5 bytes starting from register 0x02
    // [0] = TD_STATUS (num points)
    // [1] = P1_XH (event + X high)
    // [2] = P1_XL (X low)
    // [3] = P1_YH (ID + Y high)
    // [4] = P1_YL (Y low)
    let mut buf = [0u8; 5];

    if i2c.write_read(FT6336U_ADDR, &[REG_TD_STATUS], &mut buf).is_err() {
        return TouchState::NoTouch;
    }

    let num_points = buf[0] & 0x0F;

    if num_points == 0 {
        return TouchState::NoTouch;
    }

    // Parse first touch point
    let event_flag = (buf[1] >> 6) & 0x03;
    let raw_x = ((buf[1] as u16 & 0x0F) << 8) | buf[2] as u16;
    let raw_y = ((buf[3] as u16 & 0x0F) << 8) | buf[4] as u16;

    let event = match event_flag {
        0 => TouchEventType::PressDown,
        1 => TouchEventType::LiftUp,
        2 => TouchEventType::Contact,
        _ => TouchEventType::NoEvent,
    };

    // Apply 180° rotation correction
    // Display is 320×240, rotated 180°
    let x = 319u16.saturating_sub(raw_x);
    let y = 239u16.saturating_sub(raw_y);

    let p1 = TouchPoint { x, y, event };

    if num_points >= 2 {
        // Read second point (registers 0x09-0x0C)
        let mut buf2 = [0u8; 4];
        if i2c.write_read(FT6336U_ADDR, &[0x09], &mut buf2).is_ok() {
            let raw_x2 = ((buf2[0] as u16 & 0x0F) << 8) | buf2[1] as u16;
            let raw_y2 = ((buf2[2] as u16 & 0x0F) << 8) | buf2[3] as u16;
            let event2_flag = (buf2[0] >> 6) & 0x03;
            let event2 = match event2_flag {
                0 => TouchEventType::PressDown,
                1 => TouchEventType::LiftUp,
                2 => TouchEventType::Contact,
                _ => TouchEventType::NoEvent,
            };
            let x2 = 319u16.saturating_sub(raw_x2);
            let y2 = 239u16.saturating_sub(raw_y2);
            let p2 = TouchPoint { x: x2, y: y2, event: event2 };
            return TouchState::Two(p1, p2);
        }
    }

    TouchState::One(p1)
}

// ═══════════════════════════════════════════════════════════════
// Button Hit-Test Helpers
// ═══════════════════════════════════════════════════════════════

/// A rectangular touch zone on screen
#[derive(Debug, Clone, Copy)]
pub struct TouchZone {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl TouchZone {
        /// Define a rectangular touch zone at (x, y) with size (w, h).
pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    /// Check if a point falls within this zone
    pub fn contains(&self, px: u16, py: u16) -> bool {
        px >= self.x && px < self.x + self.w &&
        py >= self.y && py < self.y + self.h
    }
}

// ═══════════════════════════════════════════════════════════════
// Self-tests
// ═══════════════════════════════════════════════════════════════

/// Run touch subsystem tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 3u32;

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
        // Release
        tracker.update(TouchState::NoTouch);
        // New tap at different position
        let a3 = tracker.update(TouchState::One(TouchPoint { x: 200, y: 50, event: TouchEventType::PressDown }));

        let ok = matches!(a1, TouchAction::Tap { x: 100, y: 100 })
            && a2 == TouchAction::None
            && matches!(a3, TouchAction::Tap { x: 200, y: 50 });
        if ok { passed += 1; }
    }

    (passed, total)
}
