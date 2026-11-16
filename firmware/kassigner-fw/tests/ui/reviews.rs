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

//! The review pages and the savings card: their targets, amounts,
//! addresses and lock times.

use super::*;

/// The review's targets count where drawn and apart on both panels: page
/// arrows in the side columns as a list's, CONFIRM SEND?'s answers as a
/// dialog's, nothing between the columns.
#[test]
fn the_review_targets_are_apart() {
    for size in SIZES {
        let scale = Scale::for_panel(size);
        for confirm in [false, true] {
            let zones: Vec<_> = [
                review::Target::Nav(Nav::Back),
                review::Target::Nav(Nav::Home),
                review::Target::Previous,
                review::Target::Next,
                review::Target::Cancel,
                review::Target::Confirm,
            ]
            .into_iter()
            .filter_map(|t| review::zone(scale, confirm, t).map(|z| (t, z)))
            .collect();
            assert_eq!(zones.len(), if confirm { 5 } else { 4 }, "{size:?}");
            check(
                size,
                &zones,
                |x, y| review::target(scale, confirm, x, y),
                |_, _| false,
            );
        }
        // The arrows' columns are a list's page strips, across.
        let list = chrome::List { top: 60, rows: 3 };
        for (t, nav) in [
            (review::Target::Previous, Nav::PageUp),
            (review::Target::Next, Nav::PageDown),
        ] {
            let (ours, theirs) = (review::zone(scale, false, t).unwrap(), list.nav(scale, nav));
            assert_eq!(
                (ours.x, ours.width),
                (theirs.x, theirs.width),
                "{t:?} at {size:?}"
            );
        }
        // Between the columns nothing counts: the address is not a page.
        for x in [
            scale.x(SIDE_COLUMN),
            scale.x(160),
            scale.x(RIGHT_COLUMN) - 1,
        ] {
            for y in [scale.y(70), scale.y(120), scale.y(170)] {
                for confirm in [false, true] {
                    assert_eq!(
                        review::target(scale, confirm, x as u16, y as u16),
                        None,
                        "({x}, {y}) at {size:?}, confirm {confirm}"
                    );
                }
            }
        }
        // Nothing that turns a page is where CONFIRM is: a second tap where
        // the last page was turned does not sign.
        let confirm = review::zone(scale, true, review::Target::Confirm).unwrap();
        for t in [review::Target::Previous, review::Target::Next] {
            let z = review::zone(scale, false, t).unwrap();
            assert!(!overlap(&z, &confirm), "{t:?} over CONFIRM at {size:?}");
        }
        // CONFIRM SEND?'s answers are a dialog's, where every other
        // question puts them.
        for (ours, theirs) in [
            (review::Target::Cancel, dialog::Target::Cancel),
            (review::Target::Confirm, dialog::Target::Accept),
        ] {
            assert_eq!(
                review::zone(scale, true, ours),
                dialog::zone(scale, theirs),
                "{size:?}"
            );
        }
    }
}

/// SAVINGS CARD's targets count where drawn and apart on every page and
/// both panels, its arrows where the review's are and its answers where a
/// dialog's are, and what it draws fits the card.
#[test]
fn the_savings_card_targets_are_apart_and_fit() {
    use savings::Target;
    for size in SIZES {
        let (scale, kit) = (Scale::for_panel(size), kit(size));
        for file in [false, true] {
            for page in 0..3 {
                let zones: Vec<_> = [
                    Target::Nav(Nav::Back),
                    Target::Nav(Nav::Home),
                    Target::Previous,
                    Target::Next,
                    Target::Address,
                    Target::Save,
                    Target::Show,
                    Target::Search,
                ]
                .into_iter()
                .filter_map(|t| savings::zone(scale, (page, file), t).map(|z| (t, z)))
                .collect();
                let address = usize::from(page == 0);
                let search = usize::from(page > 0);
                let answers = if file { 1 } else { 2 };
                assert_eq!(
                    zones.len(),
                    4 + address + search + answers,
                    "{size:?} {page} {file}"
                );
                check(
                    size,
                    &zones,
                    |x, y| savings::target(scale, (page, file), x, y),
                    |_, _| false,
                );
                for (ours, theirs) in [
                    (Target::Previous, review::Target::Previous),
                    (Target::Next, review::Target::Next),
                ] {
                    assert_eq!(
                        savings::zone(scale, (page, file), ours),
                        review::zone(scale, false, theirs),
                        "{size:?}"
                    );
                }
                let save = savings::zone(scale, (page, file), Target::Save);
                let show = savings::zone(scale, (page, file), Target::Show);
                if !file {
                    assert_eq!(save, dialog::zone(scale, dialog::Target::Cancel));
                    assert_eq!(show, dialog::zone(scale, dialog::Target::Accept));
                }
            }
        }
        let room = scale.len(260 - 2 * 8);
        for address in [CARD, CARD_OWNER, CARD_RECOVERY] {
            let per = kassigner_fw::ui::address::address_per_line(scale, kit, address);
            for line in address.as_bytes().chunks(per) {
                let line = core::str::from_utf8(line).unwrap();
                assert!(kit.title.width(line) <= room, "{line:?} at {size:?}");
            }
        }
        let clock = (0..24 * 60)
            .map(|m| kit.body.width(&format!("{:02}:{:02} UTC", m / 60, m % 60)))
            .max()
            .unwrap();
        for date in ["31/12/2026", "16/02/10136"] {
            let day = kit.icons.side as i32 + scale.len(12) + kit.title.width(date) + clock;
            assert!(day <= room, "{date} at {size:?}");
        }
        for pill in ["THIS SEED #999", "NOT IN THIS SEED"] {
            assert!(
                kit.hint.width(pill) + scale.len(14) <= room,
                "{pill} at {size:?}"
            );
        }
        // The search's button: its words inside it on both panels, and it
        // inside its touch, which stays between the arrows' columns.
        let button = savings::search_area(scale);
        let touch = savings::zone(scale, (1, false), savings::Target::Search).unwrap();
        for words in ["SEARCH PAST #998", "SEARCHING #999..."] {
            assert!(
                kit.body.width(words) + scale.len(12) <= i32::from(button.width),
                "{words} at {size:?}"
            );
        }
        assert!(
            touch.x <= button.x
                && touch.y <= button.y
                && button.x + button.width <= touch.x + touch.width
                && button.y + button.height <= touch.y + touch.height,
            "{size:?}"
        );
    }
}

/// Amounts are written in KAS, eight decimals, grouped in thousands.
#[test]
fn review_amounts_are_kas_with_eight_decimals() {
    let mut buf = [0u8; review::AMOUNT_MAX];
    for (sompi, text) in [
        (0, "0.00000000"),
        (1, "0.00000001"),
        (100_000_000, "1.00000000"),
        (499_000_000, "4.99000000"),
        (99_999_999_999, "999.99999999"),
        (100_000_000_000, "1,000.00000000"),
        (123_456_789_012_345_678, "1,234,567,890.12345678"),
        (u64::MAX, "184,467,440,737.09551615"),
    ] {
        assert_eq!(review::kas(sompi, &mut buf), text);
    }
}

/// An address's ends are teal: the five characters after the colon and the
/// last five, nothing else.
#[test]
fn review_addresses_light_their_ends() {
    let a = REVIEW_ADDRESS;
    let lit: Vec<usize> = (0..a.len()).filter(|&i| review::lit(a, i)).collect();
    let n = a.len();
    assert_eq!(lit, [6, 7, 8, 9, 10, n - 5, n - 4, n - 3, n - 2, n - 1]);
    assert_eq!(&a[6..11], "qz20g");
    assert_eq!(&a[n - 5..], "8hfkl");
}

/// A lock time is said as consensus reads it: below rusty-kaspa's threshold
/// a DAA score, grouped in thousands; at or above it a time in
/// milliseconds, day first in UTC, its milliseconds only when it has some.
#[test]
fn review_lock_times_are_said_day_first() {
    use kassigner_kaspa::constants::LOCK_TIME_THRESHOLD;
    let mut buf = [0u8; review::LOCK_TIME_MAX];
    for (value, text) in [
        (1, "DAA score 1"),
        (999, "DAA score 999"),
        (1_000, "DAA score 1,000"),
        (412_345_678, "DAA score 412,345,678"),
        (LOCK_TIME_THRESHOLD - 1, "DAA score 499,999,999,999"),
        (LOCK_TIME_THRESHOLD, "05/11/1985 00:53:20 UTC"),
        (1_798_761_599_000, "31/12/2026 23:59:59 UTC"),
        (1_798_761_599_250, "31/12/2026 23:59:59.250 UTC"),
        (1_835_438_400_007, "29/02/2028 12:00:00.007 UTC"),
        (4_107_542_401_000, "01/03/2100 00:00:01 UTC"),
        (u64::MAX, "03/04/584556019 14:25:51.615 UTC"),
    ] {
        assert_eq!(review::lock_time(value, &mut buf), text);
    }
    assert_eq!(review::lock_time(0, &mut buf), "None");
}

/// LOCK TIME fits between its arrows on both panels for any DAA score and
/// any time to the year 9999; the farthest a `u64` reaches fits the panel.
#[test]
fn the_lock_time_fits() {
    let mut buf = [0u8; review::LOCK_TIME_MAX];
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let room = scale.x(298) - scale.x(22);
        for value in [499_999_999_999, 253_402_300_799_999] {
            let w = kit.title.width(review::lock_time(value, &mut buf));
            assert!(w <= room, "{value}: {w} in {room} at {size:?}");
        }
        let w = kit.title.width(review::lock_time(u64::MAX, &mut buf));
        assert!(w <= scale.len(320), "u64::MAX: {w} at {size:?}");
        for line in [
            "Valid only after",
            "Until then no block can take it",
            "Set to",
            "Ignored: every input is final",
        ] {
            let w = kit.body.width(line);
            assert!(w <= room, "{line}: {w} in {room} at {size:?}");
        }
        assert!(kit.header.width("LOCK TIME") <= room);
    }
}

/// The review fits on both panels: the longest titles, the totals from an
/// ordinary amount to past Kaspa's supply (never a number over its label or
/// KAS over an arrow), and an output's amount and address lines.
#[test]
fn the_review_fits() {
    use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};
    for size in SIZES {
        let scale = Scale::for_panel(size);
        let kit = kit(size);
        let back = kassigner_fw::ui::chrome::corner(scale, Nav::Back);
        let home = kassigner_fw::ui::chrome::corner(scale, Nav::Home);
        let between = i32::from(home.x) - i32::from(back.x + back.width);
        for title in ["TX REVIEW", "CONFIRM SEND?", "OUTPUT 8 (CHANGE)"] {
            let w = kit.header.width(title);
            assert!(w <= between, "{title} is {w} in {between} at {size:?}");
        }

        let label_w = ["Out", "In", "Fee"]
            .iter()
            .map(|l| kit.body.width(l))
            .max()
            .unwrap();
        let mut buf = [0u8; review::AMOUNT_MAX];
        for (sompi, dx, agreed) in [
            (499_000_000, 0, true),
            (499_000_000, 14, true),
            (99_999_999_999, 0, true),
            (2_900_000_000_000_000_000, 0, false),
            (u64::MAX, 0, false),
            (u64::MAX, 14, false),
        ] {
            let t = review::Totals {
                out: sompi,
                spent: sompi,
                fee: sompi,
            };
            let c = review::columns(scale, kit, &t, dx);
            assert_eq!(c.label == scale.x(48 + dx), agreed, "{sompi} at {size:?}");
            // As drawn: its characters spaced.
            let w = c
                .number
                .width_spaced(review::kas(sompi, &mut buf), c.spacing);
            assert!(
                c.label + label_w + scale.len(review::GAP) <= c.right - w,
                "{sompi}: the number over its label at {size:?}"
            );
            assert!(c.right < c.kas, "{sompi} at {size:?}");
            assert!(c.label >= scale.x(22), "{sompi} at {size:?}");
            assert!(
                c.kas + kit.body.width("KAS") <= scale.x(298),
                "{sompi}: KAS over the arrow at {size:?}"
            );
        }

        let room = scale.len(300);
        let amount = review::amount_width(scale, kit.title, review::kas(u64::MAX, &mut buf))
            + kit.body.width(" ")
            + kit.body.width("KAS");
        assert!(amount <= room, "an output's amount at {size:?}");

        // Addresses of many payloads, each version: every line within the
        // panel less its margins.
        let mut widest = 0;
        for seed in 0..512u32 {
            let mut payload = [0u8; 33];
            for (i, b) in payload.iter_mut().enumerate() {
                *b = (seed.wrapping_mul(2_654_435_761).rotate_left(i as u32 % 32) >> 7) as u8
                    ^ (i as u8).wrapping_mul(97);
            }
            for (version, len) in [
                (Version::PubKey, 32),
                (Version::PubKeyEcdsa, 33),
                (Version::ScriptHash, 32),
            ] {
                let mut out = [0u8; MAX_ADDRESS_LEN];
                let n = encode(Prefix::Mainnet, version, &payload[..len], &mut out).unwrap();
                let text = core::str::from_utf8(&out[..n]).unwrap();
                for line in text.as_bytes().chunks(n.div_ceil(3)) {
                    let w = kit.title.width(core::str::from_utf8(line).unwrap());
                    widest = widest.max(w);
                }
            }
        }
        assert!(
            widest <= room,
            "an address line {widest} in {room} at {size:?}"
        );
    }
}
