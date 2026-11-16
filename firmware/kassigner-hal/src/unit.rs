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

//! What a board's bring-up returns when it fails: one shape for every
//! board, so the binary handles them alike, each board naming its own
//! errors.

/// A bring-up that failed: why, in the board's own `E`, and the panel if
/// it came up, lit, so the binary can say why on it rather than halt on a
/// black screen. `None` is a failure before the panel.
pub struct Failed<E, L> {
    /// What failed.
    pub error: E,
    /// The panel, when the failure came after it.
    pub panel: Option<L>,
}

/// A failure before the panel: the `?`s before it.
impl<E, L> From<E> for Failed<E, L> {
    fn from(error: E) -> Self {
        Self { error, panel: None }
    }
}

/// The error, and whether the panel came back: a panel is not `Debug`.
impl<E: core::fmt::Debug, L> core::fmt::Debug for Failed<E, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failed")
            .field("error", &self.error)
            .field("panel", &self.panel.is_some())
            .finish()
    }
}

/// `$result`'s value, or the bring-up returns a [`Failed`] with `$panel`
/// handed back. A macro, not a closure: a closure would take the panel even
/// when the result is fine.
#[macro_export]
macro_rules! or_fail {
    ($result:expr, $panel:ident) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                return Err($crate::unit::Failed {
                    error,
                    panel: Some($panel),
                })
            }
        }
    };
}
