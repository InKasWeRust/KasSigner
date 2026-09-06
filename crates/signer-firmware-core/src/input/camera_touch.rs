//! Pure immediate camera-screen touch classification.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraTouchEvent {
    PressDown,
    Contact,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CameraTouchInput {
    pub x: u16,
    pub y: u16,
    pub event: CameraTouchEvent,
    pub tap_pending: bool,
    pub tune_active: bool,
    pub selected_parameter: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraTouchEffect {
    Ignore,
    Back,
    ExitTuning,
    SelectParameter(Option<u8>),
    PassThrough,
}

fn is_back(input: CameraTouchInput) -> bool {
    input.x <= 48 && input.y <= 48
}

fn is_tuning_exit(input: CameraTouchInput) -> bool {
    input.x >= 198 && input.y <= 36
}

fn is_parameter_press(input: CameraTouchInput) -> bool {
    input.event == CameraTouchEvent::PressDown && input.x >= 198 && input.y > 36 && input.y < 190
}

pub fn classify_immediate_touch(input: CameraTouchInput) -> CameraTouchEffect {
    if input.tap_pending || input.event == CameraTouchEvent::Other {
        return CameraTouchEffect::Ignore;
    }
    if is_back(input) {
        return CameraTouchEffect::Back;
    }
    if !input.tune_active {
        return CameraTouchEffect::Ignore;
    }
    if is_tuning_exit(input) {
        return CameraTouchEffect::ExitTuning;
    }
    if is_parameter_press(input) {
        return CameraTouchEffect::SelectParameter(parameter_at(
            input.x,
            input.y,
            input.selected_parameter,
        ));
    }
    CameraTouchEffect::PassThrough
}

fn parameter_at(x: u16, y: u16, current: u8) -> Option<u8> {
    let row = if (38..=82).contains(&y) {
        0
    } else if (85..=129).contains(&y) {
        1
    } else if (132..=176).contains(&y) {
        2
    } else {
        return None;
    };
    let column = u8::from(x >= 259);
    let index = row * 2 + column;
    (index < 6 && index != current).then_some(index)
}
