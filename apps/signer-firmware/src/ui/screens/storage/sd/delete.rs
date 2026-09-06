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


use super::super::super::BootDisplay;

impl<'a> BootDisplay<'a> {
    /// Draw SD backup delete confirmation screen.
    /// Mirrors the seed delete confirmation layout: CANCEL left, DELETE right.
    pub fn draw_sd_delete_confirm(&mut self, filename: &[u8; 11]) {
        let mut display_name = [0u8; 13];
        let length = crate::hw::sdcard::format_83_display(filename, &mut display_name);
        let subject = core::str::from_utf8(&display_name[..length]).unwrap_or("SD backup");
        self.draw_destructive_confirmation(
            "DELETE BACKUP?",
            subject,
            [
                "This action is irreversible.",
                "The backup file will be",
                "permanently deleted from SD.",
            ],
        );
    }
}
