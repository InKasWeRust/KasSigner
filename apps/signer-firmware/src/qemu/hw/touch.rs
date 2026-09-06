// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Deterministic input source for QEMU smoke testing.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TouchEvent {
    Tap { x: u16, y: u16 },
    Back,
}

const STARTUP_EVENTS: [TouchEvent; 3] = [
    TouchEvent::Tap { x: 160, y: 120 },
    TouchEvent::Tap { x: 280, y: 24 },
    TouchEvent::Back,
];

pub(crate) struct ScriptedTouch {
    next_index: usize,
}

impl ScriptedTouch {
    pub(crate) const fn new() -> Self {
        Self { next_index: 0 }
    }

    #[cfg(feature = "qemu-tests")]
    pub(crate) const fn consumed(&self) -> usize {
        self.next_index
    }

    pub(crate) fn next_event(&mut self) -> Option<TouchEvent> {
        let event = STARTUP_EVENTS.get(self.next_index).copied();
        if event.is_some() {
            self.next_index += 1;
        }
        event
    }
}
