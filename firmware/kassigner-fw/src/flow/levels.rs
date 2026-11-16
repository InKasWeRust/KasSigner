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

//! Settings' Display, Audio and camera tuning screens, and the page of
//! Settings each goes back to.

use super::*;

impl<'b, const N: usize> Flow<'b, N> {
    /// Display or Audio: minus and plus move the level a step, a tap on the
    /// bar sets it there, and the board is told. The backlight stays at or
    /// above [`BACKLIGHT_FLOOR`].
    pub(super) fn on_level(&mut self, event: Event<'_>, which: Setting) -> Option<Command> {
        let Event::Tap { x, y } = event else {
            return None;
        };
        let now = match which {
            Setting::Audio => self.volume,
            _ => self.backlight,
        };
        let next = match settings::target(self.scale, x, y)? {
            settings::Target::Nav(Nav::Home) => {
                self.state = State::Home;
                return None;
            }
            settings::Target::Nav(_) => {
                self.state = self.settings_at(which);
                return None;
            }
            settings::Target::Minus => now.saturating_sub(settings::STEP),
            settings::Target::Plus => now.saturating_add(settings::STEP),
            settings::Target::Bar => settings::level_at(self.scale, x),
        };
        match which {
            Setting::Audio if next != now => {
                self.volume = next;
                Some(Command::Volume(next))
            }
            Setting::Audio => None,
            _ => {
                let next = next.max(BACKLIGHT_FLOOR);
                if next == now {
                    return None;
                }
                self.backlight = next;
                Some(Command::Backlight(next))
            }
        }
    }

    /// The tuning screen. A lift answers every button; a finger down on or
    /// dragged along the track sets the knob there. The screen shows the
    /// sensor's reading, reported after every change.
    pub(super) fn on_camera_tune(&mut self, event: Event<'_>, knob: usize) -> Option<Command> {
        let n = self.knobs.len();
        let (x, y, lift) = match event {
            Event::Tuned { values, auto } => {
                for (v, s) in self.tune.iter_mut().zip(values.iter().take(n)) {
                    *v = *s;
                }
                if let Some(on) = auto {
                    self.auto = on;
                }
                return None;
            }
            Event::Tap { x, y } => (x, y, true),
            Event::Press { x, y } | Event::Drag { x, y } => (x, y, false),
            Event::CameraLost => {
                self.refuse(Refusal::NoCamera);
                return Some(Command::TuneOff);
            }
            _ => return None,
        };
        let target = camtune::target(self.scale, n, self.has_auto, x, y)?;
        if !lift && target != camtune::Target::Track {
            return None;
        }
        let k = self.knobs.get(knob)?;
        let now = self.tune[knob];
        let next = match target {
            camtune::Target::Exit => {
                self.state = self.settings_at(Setting::Camera);
                return Some(Command::TuneOff);
            }
            camtune::Target::Auto => return Some(Command::TuneAuto(!self.auto)),
            camtune::Target::Knob(i) => {
                self.state = State::CameraTune { knob: i };
                return None;
            }
            camtune::Target::Minus => k.down(now),
            camtune::Target::Plus => k.up(now),
            camtune::Target::Track => k.snap(camtune::value_at(self.scale, k.max, x)),
        };
        if next == now {
            return None;
        }
        self.tune[knob] = next;
        Some(Command::Tune { knob, value: next })
    }

    /// Settings at the page `setting`'s row is on, where its screen goes
    /// back to.
    pub(super) fn settings_at(&self, setting: Setting) -> State {
        State::Menu {
            menu: MenuId::Settings,
            page: menu::page_of(self.settings, setting),
        }
    }

    /// The camera settings the tuning screen moves.
    pub fn knobs(&self) -> &'static [Knob] {
        self.knobs
    }
}
