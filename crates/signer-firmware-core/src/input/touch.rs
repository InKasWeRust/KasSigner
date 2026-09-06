//! Board-neutral touch contracts and the Waveshare gesture state machine.

pub mod contact_gate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEventType {
    PressDown,
    LiftUp,
    Contact,
    NoEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchPoint {
    pub x: u16,
    pub y: u16,
    pub event: TouchEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchState {
    NoTouch,
    One(TouchPoint),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchZone {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl TouchZone {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    pub fn contains(&self, px: u16, py: u16) -> bool {
        axis_contains(self.x, self.w, px) && axis_contains(self.y, self.h, py)
    }
}

fn axis_contains(origin: u16, length: u16, point: u16) -> bool {
    let point = u32::from(point);
    let origin = u32::from(origin);
    point >= origin && point < origin + u32::from(length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwGesture {
    None,
    SwipeUp,
    SwipeDown,
    SwipeLeft,
    SwipeRight,
    SingleTap,
    DoubleTap,
    LongPress,
    Unknown(u8),
}

pub const fn decode_touch_event_flag(flag: u8) -> TouchEventType {
    match flag {
        0 => TouchEventType::PressDown,
        1 => TouchEventType::LiftUp,
        2 => TouchEventType::Contact,
        _ => TouchEventType::NoEvent,
    }
}

pub const fn decode_gesture_byte(value: u8) -> HwGesture {
    match value {
        0x01 => HwGesture::SwipeUp,
        0x02 => HwGesture::SwipeDown,
        0x03 => HwGesture::SwipeLeft,
        0x04 => HwGesture::SwipeRight,
        0x05 => HwGesture::SingleTap,
        0x0B => HwGesture::DoubleTap,
        0x0C => HwGesture::LongPress,
        0x00 => HwGesture::None,
        other => HwGesture::Unknown(other),
    }
}

/// Decode one FT6336U register sample and apply a 180-degree display rotation.
pub fn decode_rotated_single_touch(
    registers: [u8; 5],
    maximum_x: u16,
    maximum_y: u16,
) -> TouchState {
    let points = registers[0] & 0x0F;
    if points != 1 {
        return TouchState::NoTouch;
    }
    let raw_x = ((registers[1] as u16 & 0x0F) << 8) | registers[2] as u16;
    let raw_y = ((registers[3] as u16 & 0x0F) << 8) | registers[4] as u16;
    TouchState::One(TouchPoint {
        x: maximum_x.saturating_sub(raw_x),
        y: maximum_y.saturating_sub(raw_y),
        event: decode_touch_event_flag((registers[1] >> 6) & 0x03),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchAction {
    None,
    Tap { x: u16, y: u16 },
    Hold { x: u16, y: u16 },
    Drag { x: u16, y: u16, dx: i16, dy: i16 },
    SwipeUp,
    SwipeDown,
    SwipeLeft,
    SwipeRight,
}

/// Immediate tap tracker used by controllers that report a tap on first contact.
pub struct ImmediateTouchTracker {
    was_down: bool,
}

impl ImmediateTouchTracker {
    pub const fn new() -> Self {
        Self { was_down: false }
    }

    pub fn update(&mut self, state: TouchState) -> TouchAction {
        match state {
            TouchState::NoTouch => {
                self.was_down = false;
                TouchAction::None
            }
            TouchState::One(point) => {
                let is_new = point.event == TouchEventType::PressDown || !self.was_down;
                self.was_down = true;
                if is_new {
                    TouchAction::Tap {
                        x: point.x,
                        y: point.y,
                    }
                } else {
                    TouchAction::None
                }
            }
        }
    }
}

impl Default for ImmediateTouchTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TouchTracker {
    last_gesture: HwGesture,
    last_x: u16,
    last_y: u16,
    is_down: bool,
    pending_tap: bool,
    pending_x: u16,
    pending_y: u16,
    got_contact: bool,
}

impl TouchTracker {
    pub const fn new() -> Self {
        Self {
            last_gesture: HwGesture::None,
            last_x: 0,
            last_y: 0,
            is_down: false,
            pending_tap: false,
            pending_x: 0,
            pending_y: 0,
            got_contact: false,
        }
    }

    pub fn update(&mut self, state: TouchState, gesture: HwGesture) -> TouchAction {
        match state {
            TouchState::NoTouch => self.release_without_point(),
            TouchState::One(point) => self.update_point(point, gesture),
        }
    }

    fn release_without_point(&mut self) -> TouchAction {
        let action = self.pending_tap_action();
        self.pending_tap = false;
        self.is_down = false;
        self.got_contact = false;
        action
    }

    fn update_point(&mut self, point: TouchPoint, gesture: HwGesture) -> TouchAction {
        if let Some(action) = self.new_gesture_action(point, gesture) {
            return action;
        }
        match point.event {
            TouchEventType::PressDown => self.press(point),
            TouchEventType::Contact => self.contact(point, gesture),
            TouchEventType::LiftUp => self.lift(),
            TouchEventType::NoEvent => TouchAction::None,
        }
    }

    fn mapped_swipe_action(&mut self, gesture: HwGesture) -> Option<TouchAction> {
        match gesture {
            HwGesture::SwipeUp => Some(self.finish_swipe(TouchAction::SwipeRight)),
            HwGesture::SwipeDown => Some(self.finish_swipe(TouchAction::SwipeLeft)),
            HwGesture::SwipeLeft => Some(self.finish_swipe(TouchAction::SwipeUp)),
            HwGesture::SwipeRight => Some(self.finish_swipe(TouchAction::SwipeDown)),
            _ => None,
        }
    }

    fn new_gesture_action(&mut self, point: TouchPoint, gesture: HwGesture) -> Option<TouchAction> {
        if gesture == HwGesture::None || gesture == self.last_gesture {
            return None;
        }
        self.last_gesture = gesture;
        self.pending_tap = false;
        if let Some(action) = self.mapped_swipe_action(gesture) {
            return Some(action);
        }
        match gesture {
            HwGesture::LongPress => Some(TouchAction::Hold {
                x: point.x,
                y: point.y,
            }),
            HwGesture::SingleTap | HwGesture::DoubleTap => self.confirm_hardware_tap(point),
            HwGesture::None | HwGesture::Unknown(_) => None,
            _ => None,
        }
    }

    fn finish_swipe(&mut self, action: TouchAction) -> TouchAction {
        self.is_down = false;
        action
    }

    fn confirm_hardware_tap(&mut self, point: TouchPoint) -> Option<TouchAction> {
        if !self.is_down && !self.got_contact {
            return Some(TouchAction::None);
        }
        self.is_down = false;
        self.got_contact = false;
        Some(TouchAction::Tap {
            x: point.x,
            y: point.y,
        })
    }

    fn press(&mut self, point: TouchPoint) -> TouchAction {
        self.last_gesture = HwGesture::None;
        self.is_down = true;
        self.last_x = point.x;
        self.last_y = point.y;
        self.pending_tap = true;
        self.pending_x = point.x;
        self.pending_y = point.y;
        self.got_contact = false;
        TouchAction::None
    }

    fn contact(&mut self, point: TouchPoint, gesture: HwGesture) -> TouchAction {
        self.got_contact = true;
        if gesture != HwGesture::None {
            self.pending_tap = false;
        }
        if !self.is_down {
            return self.implicit_press(point);
        }
        self.drag_action(point)
    }

    fn implicit_press(&mut self, point: TouchPoint) -> TouchAction {
        self.is_down = true;
        self.last_x = point.x;
        self.last_y = point.y;
        self.pending_tap = true;
        self.pending_x = point.x;
        self.pending_y = point.y;
        self.last_gesture = HwGesture::None;
        TouchAction::None
    }

    fn drag_action(&mut self, point: TouchPoint) -> TouchAction {
        let dx = point.x as i16 - self.last_x as i16;
        let dy = point.y as i16 - self.last_y as i16;
        self.last_x = point.x;
        self.last_y = point.y;
        if dx.abs() > 2 || dy.abs() > 2 {
            TouchAction::Drag {
                x: point.x,
                y: point.y,
                dx,
                dy,
            }
        } else {
            TouchAction::None
        }
    }

    fn lift(&mut self) -> TouchAction {
        self.is_down = false;
        self.last_gesture = HwGesture::None;
        let action = self.pending_tap_action();
        self.pending_tap = false;
        self.got_contact = false;
        action
    }

    fn pending_tap_action(&self) -> TouchAction {
        if self.pending_tap && self.got_contact {
            TouchAction::Tap {
                x: self.pending_x,
                y: self.pending_y,
            }
        } else {
            TouchAction::None
        }
    }
}

impl Default for TouchTracker {
    fn default() -> Self {
        Self::new()
    }
}
