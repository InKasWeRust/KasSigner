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

// hw/touch.rs — CST816D driver for Waveshare ESP32-S3-Touch-LCD-2
//
// STATELESS DESIGN: each I2C read is independent.
//   - GestureID is a swipe → return Swipe (once per gesture)
//   - Event is PressDown, no gesture → return Tap
//   - Everything else → None
//
// CST816D gesture rotation (portrait → Deg90 landscape):
//   CST816D SwipeUp(0x01)    = finger moves right on screen
//   CST816D SwipeDown(0x02)  = finger moves left on screen

use esp_hal::i2c::master::I2c;

const CST816D_ADDR: u8 = 0x15;
const REG_GESTURE_ID: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchEventType { PressDown, LiftUp, Contact, NoEvent }

#[derive(Debug, Clone, Copy)]
pub struct TouchPoint { pub x: u16, pub y: u16, pub event: TouchEventType }

#[derive(Debug, Clone, Copy)]
pub enum TouchState { NoTouch, One(TouchPoint), Two(TouchPoint, TouchPoint) }

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HwGesture {
    None, SwipeUp, SwipeDown, SwipeLeft, SwipeRight,
    SingleTap, DoubleTap, LongPress, Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TouchAction {
    None,
    Tap { x: u16, y: u16 },
    Hold { x: u16, y: u16 },
    Drag { x: u16, y: u16, dx: i16, dy: i16 },
    DragEnd { x: u16, y: u16 },
    SwipeUp, SwipeDown, SwipeLeft, SwipeRight,
}

// ═══════════════════════════════════════════════════════════════

pub struct TouchTracker {
    last_gesture: HwGesture,
    last_x: u16,
    last_y: u16,
    is_down: bool,
    configured: bool,
    pending_tap: bool,
    pending_x: u16,
    pending_y: u16,
    got_contact: bool,
    contact_count: u8,
}

impl TouchTracker {
    pub fn new() -> Self {
        Self {
            last_gesture: HwGesture::None,
            last_x: 0, last_y: 0,
            is_down: false, configured: false,
            pending_tap: false, pending_x: 0, pending_y: 0,
            got_contact: false, contact_count: 0,
        }
    }
    pub fn update(&mut self, state: TouchState, gesture: HwGesture) -> TouchAction {
        match state {
            TouchState::NoTouch => {
                // Fire pending tap if we saw Contact (got_contact=true).
                // With the implicit-PressDown-from-Contact fix, this covers
                // the common case where PressDown is missed during 33ms polling.
                if self.pending_tap && self.got_contact {
                    self.pending_tap = false;
                    self.is_down = false;
                    self.got_contact = false;
                    return TouchAction::Tap { x: self.pending_x, y: self.pending_y };
                }
                self.pending_tap = false;
                self.is_down = false;
                self.got_contact = false;
                TouchAction::None
            }
            TouchState::One(pt) => {
                let x = pt.x;
                let y = pt.y;

                // Swipe: fire ONCE per touch (last_gesture blocks repeats)
                if gesture != HwGesture::None && gesture != self.last_gesture {
                    self.last_gesture = gesture;
                    self.pending_tap = false;
                    match gesture {
                        HwGesture::SwipeUp    => { self.is_down = false; return TouchAction::SwipeRight; }
                        HwGesture::SwipeDown  => { self.is_down = false; return TouchAction::SwipeLeft; }
                        HwGesture::SwipeLeft  => { self.is_down = false; return TouchAction::SwipeUp; }
                        HwGesture::SwipeRight => { self.is_down = false; return TouchAction::SwipeDown; }
                        HwGesture::LongPress  => return TouchAction::Hold { x, y },
                        HwGesture::SingleTap | HwGesture::DoubleTap => {
                            // CST816D confirmed it's a tap — fire immediately
                            self.is_down = false;
                            self.got_contact = false;
                            return TouchAction::Tap { x, y };
                        }
                        _ => {}
                    }
                }

                match pt.event {
                    TouchEventType::PressDown => {
                        self.last_gesture = HwGesture::None;
                        self.is_down = true;
                        self.last_x = x;
                        self.last_y = y;
                        self.pending_tap = true;
                        self.pending_x = x;
                        self.pending_y = y;
                        self.got_contact = false;
                        self.contact_count = 0;
                        TouchAction::None
                    }
                    TouchEventType::Contact => {
                        self.got_contact = true;

                        // If gesture arrived, cancel pending tap (swipe handled above)
                        if gesture != HwGesture::None {
                            self.pending_tap = false;
                        }

                        if !self.is_down {
                            // First Contact without PressDown — PressDown was missed
                            // during 33ms polling gap. Treat as implicit PressDown.
                            self.is_down = true;
                            self.last_x = x;
                            self.last_y = y;
                            self.pending_tap = true;
                            self.pending_x = x;
                            self.pending_y = y;
                            self.last_gesture = HwGesture::None;
                            return TouchAction::None;
                        }
                        let dx = x as i16 - self.last_x as i16;
                        let dy = y as i16 - self.last_y as i16;
                        self.last_x = x;
                        self.last_y = y;
                        if dx.abs() > 2 || dy.abs() > 2 {
                            TouchAction::Drag { x, y, dx, dy }
                        } else {
                            TouchAction::None
                        }
                    }
                    TouchEventType::LiftUp => {
                        self.is_down = false;
                        self.last_gesture = HwGesture::None;
                        // Fire pending tap on explicit LiftUp (faster than NoTouch)
                        if self.pending_tap && self.got_contact {
                            self.pending_tap = false;
                            self.got_contact = false;
                            return TouchAction::Tap { x: self.pending_x, y: self.pending_y };
                        }
                        TouchAction::None
                    }
                    TouchEventType::NoEvent => TouchAction::None,
                }
            }
            TouchState::Two(_, _) => TouchAction::None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// I2C read
// ═══════════════════════════════════════════════════════════════

pub fn read_touch_full(
    i2c: &mut I2c<'_, esp_hal::Blocking>,
    configured: &mut bool,
) -> (TouchState, HwGesture) {
    let mut buf = [0u8; 6];
    if i2c.write_read(CST816D_ADDR, &[REG_GESTURE_ID], &mut buf).is_err() {
        return (TouchState::NoTouch, HwGesture::None);
    }

    if !*configured {
        *configured = true;
        // Reduce touch sensitivity to avoid phantom wake from light/EMI.
        // Register 0x05: sensitivity threshold — higher = less sensitive (default ~1-2)
        // Register 0x06: low-power scan range — lower = less sensitive (default varies)
        let _ = i2c.write(CST816D_ADDR, &[0x05, 0x28]); // sensitivity threshold = 40
        let _ = i2c.write(CST816D_ADDR, &[0x06, 0x10]); // low-power scan range = 16
        #[cfg(not(feature = "silent"))]
        crate::log!("[CST816D] Factory defaults OK, sensitivity reduced");
    }

    let gesture = match buf[0] {
        0x01 => HwGesture::SwipeUp,   0x02 => HwGesture::SwipeDown,
        0x03 => HwGesture::SwipeLeft,  0x04 => HwGesture::SwipeRight,
        0x05 => HwGesture::SingleTap,  0x0B => HwGesture::DoubleTap,
        0x0C => HwGesture::LongPress,  0x00 => HwGesture::None,
        other => HwGesture::Unknown(other),
    };

    let num_fingers = buf[1] & 0x0F;
    if num_fingers == 0 {
        // CST816D retains gesture register value after auto-sleep/wake.
        // NoTouch + gesture is stale — clear it to prevent phantom activity.
        return (TouchState::NoTouch, HwGesture::None);
    }

    let event_flag = (buf[2] >> 6) & 0x03;
    let raw_x = ((buf[2] as u16 & 0x0F) << 8) | buf[3] as u16;
    let raw_y = ((buf[4] as u16 & 0x0F) << 8) | buf[5] as u16;

    let event = match event_flag {
        0 => TouchEventType::PressDown, 1 => TouchEventType::LiftUp,
        2 => TouchEventType::Contact, _ => TouchEventType::NoEvent,
    };

    let x = raw_y.min(319);
    let y = 239u16.saturating_sub(raw_x);

    (TouchState::One(TouchPoint { x, y, event }), gesture)
}

pub fn read_touch(i2c: &mut I2c<'_, esp_hal::Blocking>) -> TouchState {
    let mut dummy = true;
    let (state, _) = read_touch_full(i2c, &mut dummy);
    state
}

pub fn read_touch_with_gesture(i2c: &mut I2c<'_, esp_hal::Blocking>) -> (TouchState, HwGesture) {
    let mut dummy = true;
    read_touch_full(i2c, &mut dummy)
}

// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
pub struct TouchZone { pub x: u16, pub y: u16, pub w: u16, pub h: u16 }

impl TouchZone {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self { Self { x, y, w, h } }
    pub fn contains(&self, px: u16, py: u16) -> bool {
        px >= self.x && px < self.x + self.w && py >= self.y && py < self.y + self.h
    }
}

// ═══════════════════════════════════════════════════════════════

pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 2u32;

    {
        let zone = TouchZone::new(100, 50, 120, 60);
        let ok = zone.contains(150, 70) && !zone.contains(50, 70)
            && !zone.contains(150, 120) && zone.contains(100, 50) && !zone.contains(220, 50);
        if ok { passed += 1; }
    }

    {
        let mut t = TouchTracker::new();
        let pt = TouchPoint { x: 150, y: 100, event: TouchEventType::PressDown };
        let a = t.update(TouchState::One(pt), HwGesture::None);
        if matches!(a, TouchAction::Tap { x: 150, y: 100 }) { passed += 1; }
    }

    (passed, total)
}
