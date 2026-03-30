// KasSigner — Air-gapped hardware wallet for Kaspa
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
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

// ui/pin_ui.rs — PIN entry keypad interface

// KasSigner — PIN Entry UI
// 100% Rust, no-std, no-alloc
//
// Touch-based numeric keypad for PIN entry on 320×240 screen.
//
// Layout (320×240):
//   Row 0 (y=0..40):   Title bar ("Enter PIN" / "Confirm PIN")
//   Row 1 (y=44..84):  PIN dots display (masked)
//   Row 2 (y=90..140):  [1] [2] [3]
//   Row 3 (y=144..194): [4] [5] [6]
//   Row 4 (y=198..238): [7] [8] [9]
//   Row 5 (y=198..238): [⌫] [0] [OK]
//
//   Wait... 5 rows don't fit in 240 with title + dots.
//   Better layout — 4 rows of keys:
//
//   y=0..35:    Title
//   y=38..60:   PIN dots (up to 12)
//   y=65..105:  [1] [2] [3]
//   y=110..150: [4] [5] [6]
//   y=155..195: [7] [8] [9]
//   y=200..240: [⌫] [0] [✓]
//
//   Each key: ~100w × 40h with 5px gaps

/// Maximum PIN length
pub const MAX_PIN_LEN: usize = 12;

/// Minimum PIN length for confirmation
pub const MIN_PIN_LEN: usize = 6;

/// PIN entry state
pub struct PinEntry {
    /// Current PIN digits
    pub digits: [u8; MAX_PIN_LEN],
    /// Current number of digits entered
    pub len: usize,
    /// Whether PIN entry is complete (user pressed OK)
    pub confirmed: bool,
    /// Whether user cancelled
    pub cancelled: bool,
    /// Title to show (e.g., "Enter PIN", "Confirm PIN")
    pub title: &'static str,
    /// Show error message
    pub error: bool,
}

impl PinEntry {
        /// Create a new PIN entry with the given screen title.
pub fn new(title: &'static str) -> Self {
        Self {
            digits: [0; MAX_PIN_LEN],
            len: 0,
            confirmed: false,
            cancelled: false,
            title,
            error: false,
        }
    }

    /// Reset for retry
    pub fn reset(&mut self) {
        self.digits = [0; MAX_PIN_LEN];
        self.len = 0;
        self.confirmed = false;
        self.cancelled = false;
        self.error = false;
    }

    /// Add a digit (0-9)
    pub fn push_digit(&mut self, d: u8) {
        if self.len < MAX_PIN_LEN {
            self.digits[self.len] = d;
            self.len += 1;
            self.error = false;
        }
    }

    /// Delete last digit
    pub fn backspace(&mut self) {
        if self.len > 0 {
            self.len -= 1;
            self.digits[self.len] = 0;
            self.error = false;
        }
    }

    /// Attempt to confirm — only if >= MIN_PIN_LEN
    pub fn try_confirm(&mut self) -> bool {
        if self.len >= MIN_PIN_LEN {
            self.confirmed = true;
            true
        } else {
            self.error = true;
            false
        }
    }
    /// Compare with another PIN entry
    pub fn matches(&self, other: &PinEntry) -> bool {
        if self.len != other.len {
            return false;
        }
        // Constant-time compare
        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.digits[i] ^ other.digits[i];
        }
        diff == 0
    }

    /// Zeroize PIN from memory
    pub fn zeroize(&mut self) {
        for b in self.digits.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        self.len = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for PinEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─── Touch Zones for Keypad ─────────────────────────────────────────

/// Key positions on the 320×240 screen
/// 3 columns: x = 10..105, 110..205, 210..305 (95px wide each, 5px gap)
/// 4 rows:    y = 65..105, 110..150, 155..195, 200..240 (40px high, 5px gap)
const KEY_W: i32 = 95;
const KEY_H: i32 = 38;
const KEY_X: [i32; 3] = [10, 110, 210];
const KEY_Y: [i32; 4] = [65, 108, 151, 194];

/// Result of checking a tap against the keypad
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeypadAction {
    /// A digit was pressed (0-9)
    Digit(u8),
    /// Backspace
    Backspace,
    /// OK/Confirm
    Confirm,
    /// No key hit
    None,
}

/// Check which key was tapped given (x, y) coordinates
pub fn check_keypad_tap(x: i32, y: i32) -> KeypadAction {
    // Find column
    let col = if x >= KEY_X[0] && x < KEY_X[0] + KEY_W { Some(0) }
        else if x >= KEY_X[1] && x < KEY_X[1] + KEY_W { Some(1) }
        else if x >= KEY_X[2] && x < KEY_X[2] + KEY_W { Some(2) }
        else { None };

    // Find row
    let row = if y >= KEY_Y[0] && y < KEY_Y[0] + KEY_H { Some(0) }
        else if y >= KEY_Y[1] && y < KEY_Y[1] + KEY_H { Some(1) }
        else if y >= KEY_Y[2] && y < KEY_Y[2] + KEY_H { Some(2) }
        else if y >= KEY_Y[3] && y < KEY_Y[3] + KEY_H { Some(3) }
        else { None };

    match (row, col) {
        // Row 0: 1 2 3
        (Some(0), Some(0)) => KeypadAction::Digit(1),
        (Some(0), Some(1)) => KeypadAction::Digit(2),
        (Some(0), Some(2)) => KeypadAction::Digit(3),
        // Row 1: 4 5 6
        (Some(1), Some(0)) => KeypadAction::Digit(4),
        (Some(1), Some(1)) => KeypadAction::Digit(5),
        (Some(1), Some(2)) => KeypadAction::Digit(6),
        // Row 2: 7 8 9
        (Some(2), Some(0)) => KeypadAction::Digit(7),
        (Some(2), Some(1)) => KeypadAction::Digit(8),
        (Some(2), Some(2)) => KeypadAction::Digit(9),
        // Row 3: ⌫ 0 ✓
        (Some(3), Some(0)) => KeypadAction::Backspace,
        (Some(3), Some(1)) => KeypadAction::Digit(0),
        (Some(3), Some(2)) => KeypadAction::Confirm,
        _ => KeypadAction::None,
    }
}

// ─── Keypad layout constants (exported for display) ─────────────────

/// Key labels for rendering
pub const KEY_LABELS: [[&str; 3]; 4] = [
    ["1", "2", "3"],
    ["4", "5", "6"],
    ["7", "8", "9"],
    ["<", "0", "OK"],
];

/// Get key rectangle position for rendering
pub fn key_rect(row: usize, col: usize) -> (i32, i32, u32, u32) {
    (KEY_X[col], KEY_Y[row], KEY_W as u32, KEY_H as u32)
}

/// Number of key rows
pub const KEY_ROWS: usize = 4;
/// Number of key columns
pub const KEY_COLS: usize = 3;

/// PIN dots Y position
pub const DOTS_Y: i32 = 45;

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: basic PIN digit entry.
pub fn test_pin_entry_basic() -> bool {
    let mut pin = PinEntry::new("Test");
    pin.push_digit(1);
    pin.push_digit(2);
    pin.push_digit(3);
    pin.push_digit(4);
    pin.push_digit(5);
    pin.push_digit(6);

    pin.len == 6 && pin.try_confirm()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: PIN too short is rejected.
pub fn test_pin_too_short() -> bool {
    let mut pin = PinEntry::new("Test");
    pin.push_digit(1);
    pin.push_digit(2);
    pin.push_digit(3);

    !pin.try_confirm() && pin.error
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: backspace removes last digit.
pub fn test_pin_backspace() -> bool {
    let mut pin = PinEntry::new("Test");
    pin.push_digit(1);
    pin.push_digit(2);
    pin.push_digit(3);
    pin.backspace();

    pin.len == 2 && pin.digits[0] == 1 && pin.digits[1] == 2
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: PIN comparison logic.
pub fn test_pin_match() -> bool {
    let mut a = PinEntry::new("A");
    let mut b = PinEntry::new("B");

    for d in [1, 2, 3, 4, 5, 6] {
        a.push_digit(d);
        b.push_digit(d);
    }

    let same = a.matches(&b);

    b.backspace();
    b.push_digit(9);

    let diff = !a.matches(&b);

    same && diff
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: keypad touch zone hit detection.
pub fn test_keypad_zones() -> bool {
    // Center of digit "5" key: col 1 (x=157), row 1 (y=129)
    let five = check_keypad_tap(157, 129);
    // Center of "0" key: col 1 (x=157), row 3 (y=213)
    let zero = check_keypad_tap(157, 213);
    // Center of backspace: col 0 (x=57), row 3 (y=213)
    let bksp = check_keypad_tap(57, 213);
    // Center of OK: col 2 (x=257), row 3 (y=213)
    let ok = check_keypad_tap(257, 213);
    // Outside all keys
    let none = check_keypad_tap(0, 0);

    five == KeypadAction::Digit(5)
        && zero == KeypadAction::Digit(0)
        && bksp == KeypadAction::Backspace
        && ok == KeypadAction::Confirm
        && none == KeypadAction::None
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all PIN entry tests.
pub fn run_pin_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_pin_entry_basic() { passed += 1; }
    if test_pin_too_short() { passed += 1; }
    if test_pin_backspace() { passed += 1; }
    if test_pin_match() { passed += 1; }
    if test_keypad_zones() { passed += 1; }

    (passed, total)
}
