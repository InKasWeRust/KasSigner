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

//! The container password policy: what seals and what does not.

use kassigner_crypto::password::{check, Strength, Weakness, MIN_CLASSES, MIN_DISTINCT, MIN_LEN};

/// The thresholds are the policy, pinned so a change is deliberate.
#[test]
fn the_thresholds_are_pinned() {
    assert_eq!(MIN_LEN, 12);
    assert_eq!(MIN_CLASSES, 3);
    assert_eq!(MIN_DISTINCT, 6);
}

/// Short is refused first, whatever else the password has.
#[test]
fn short_passwords_are_refused() {
    for pw in [&b""[..], b"pw", b"abc", b"Aa1!Aa1!Aa1", b"correct hors"] {
        let r = check(pw);
        if pw.len() < MIN_LEN {
            assert_eq!(
                r,
                Err(Weakness::TooShort {
                    have: pw.len(),
                    min: MIN_LEN
                }),
                "{pw:?}"
            );
        } else {
            assert_ne!(
                r,
                Err(Weakness::TooShort {
                    have: pw.len(),
                    min: MIN_LEN
                })
            );
        }
    }
}

/// Long enough but from too few classes is refused, with the count seen.
#[test]
fn one_or_two_classes_are_refused() {
    assert_eq!(
        check(b"correcthorsebattery"),
        Err(Weakness::TooFewClasses {
            have: 1,
            min: MIN_CLASSES
        })
    );
    assert_eq!(
        check(b"correct horse battery staple"),
        Err(Weakness::TooFewClasses {
            have: 2,
            min: MIN_CLASSES
        }),
        "lower and space: two classes"
    );
    assert_eq!(
        check(b"1234567890123456"),
        Err(Weakness::TooFewClasses {
            have: 1,
            min: MIN_CLASSES
        })
    );
    assert_eq!(
        check(b"CorrectHorseBattery"),
        Err(Weakness::TooFewClasses {
            have: 2,
            min: MIN_CLASSES
        })
    );
}

/// Three classes over a handful of characters is still a handful of
/// characters.
#[test]
fn repetitive_passwords_are_refused() {
    assert_eq!(
        check(b"aaaaaaaaaaaA1"),
        Err(Weakness::TooFewDistinct {
            have: 3,
            min: MIN_DISTINCT
        })
    );
    assert!(
        check(b"abAB12abAB12").is_ok(),
        "six distinct is the floor, and passes"
    );
    assert_eq!(
        check(b"abAB1abAB1ab"),
        Err(Weakness::TooFewDistinct {
            have: 5,
            min: MIN_DISTINCT
        })
    );
}

/// Accepted passwords are rated by estimated bits, rising with length and
/// classes. The shortest accepted rates `Fair` whatever it is made of: the
/// meter pushes past the minimum.
#[test]
fn accepted_passwords_are_rated() {
    // 12 bytes over lower, upper, digit: pool 62, 6.0 bits each, 72.
    assert_eq!(check(b"Ab1Cd2Ef3Gh4"), Ok(Strength::Fair));
    // 12 bytes over all four: pool 95, 6.6 bits each, 79.
    assert_eq!(check(b"Ab1!Cd2@Ef3#"), Ok(Strength::Fair));
    // 14 bytes over three: 84.
    assert_eq!(check(b"Ab1Cd2Ef3Gh4Ij"), Ok(Strength::Good));
    // 15 bytes over all four: 99.
    assert_eq!(check(b"Piggy-Bank-2026"), Ok(Strength::Good));
    // 16 bytes over all four: 105.
    assert_eq!(check(b"Piggy-Bank-2026!"), Ok(Strength::Strong));
    // 20 bytes over three: 120.
    assert_eq!(check(b"Ab1Cd2Ef3Gh4Ij5Kl6Mn"), Ok(Strength::Strong));
    assert!(Strength::Fair < Strength::Good && Strength::Good < Strength::Strong);
}

/// The password `tests/slot.rs` seals cards under passes, so a card it
/// writes is one a unit would write.
#[test]
fn the_test_suites_card_password_passes() {
    assert!(check(b"Piggy-Bank-2026").is_ok());
}
