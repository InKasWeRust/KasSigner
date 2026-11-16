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

//! Text typed on the keyboard.

use kassigner_fw::text::{printable, Typed};

/// **Characters go in at the cursor, Delete takes the one before it, and
/// the arrows move it within the text.**
#[test]
fn typing_edits_at_the_cursor() {
    let mut t: Typed<8> = Typed::new();
    for &c in b"acd" {
        assert!(t.insert(c));
    }
    t.left();
    t.left();
    assert!(t.insert(b'b'));
    assert_eq!((t.as_str(), t.cursor()), ("abcd", 2));
    t.backspace();
    assert_eq!((t.as_str(), t.cursor()), ("acd", 1));
    t.left();
    t.left();
    t.backspace();
    assert_eq!((t.as_str(), t.cursor()), ("acd", 0), "nothing before it");
    for _ in 0..9 {
        t.right();
    }
    assert_eq!(t.cursor(), 3, "no further than the end");
    t.backspace();
    assert_eq!((t.as_str(), t.len()), ("ac", 2));
}

/// **Printable ASCII only, and no more than the room.**
#[test]
fn only_printable_and_only_what_fits() {
    let mut t: Typed<3> = Typed::new();
    assert!(!t.insert(b'\n'), "a control character");
    assert!(!t.insert(0x7F));
    assert!(!t.insert(0xC3), "not ASCII");
    assert!(t.insert(b' ') && t.insert(b'~') && t.insert(b'A'));
    assert!(!t.insert(b'B'), "full");
    assert_eq!(t.as_str(), " ~A");
    assert!(printable(b' ') && printable(b'~') && !printable(0x1F));
}

/// **Cleared is wiped: empty, the cursor home.** A screen's field says it
/// changed without saying what.
#[test]
fn cleared_is_empty_and_the_field_says_nothing() {
    let mut t: Typed<8> = Typed::new();
    let before = t.field();
    t.insert(b's');
    assert_ne!(t.field(), before, "an edit is a new field");
    assert_eq!(format!("{:?}", t.field()), "Field(..)");
    t.clear();
    assert!(t.is_empty());
    assert_eq!((t.as_str(), t.cursor()), ("", 0));
    assert_eq!(t.field(), before);
}

/// **A carriage return is allowed only before a line break.** `\r\n` is a
/// line break, as `\n` is. One anywhere else is refused: the screen cannot
/// show it, so it would be signed unseen.
#[test]
fn a_carriage_return_only_before_a_line_break() {
    use kassigner_fw::text::is_message;
    assert!(is_message(b"one\ntwo"));
    assert!(is_message(b"one\r\ntwo\r\n"));
    assert!(!is_message(b"one\rtwo"), "alone, mid-line");
    assert!(!is_message(b"one\r"), "alone, at the end");
    assert!(!is_message(b"one\r\r\ntwo"), "two before a break");
    assert!(!is_message(b"\r"));
    assert!(!is_message(b""), "nothing");
    assert!(!is_message(b"tab\there"), "and still no other control");
}
