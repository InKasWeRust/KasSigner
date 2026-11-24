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

//! The band renderer and the brand screens, drawn into a buffer.
//!
//! ```text
//! UI_PREVIEW=/some/dir cargo +esp195 test -p kassigner-fw --test ui
//! ```
//!
//! also writes every brand screen at both panel sizes as PPM pictures in
//! that directory: what a unit shows, pixel for pixel, without flashing it.

use kassigner_fw::card::{self, Job, Kind, Outcome};
use kassigner_fw::touch::Zone;
use kassigner_fw::ui::band::{render, Band};
use kassigner_fw::ui::brand;
use kassigner_fw::ui::chrome::{self, Nav, RIGHT_COLUMN, SIDE_COLUMN};
use kassigner_fw::ui::color::{blend, rgb565, ACCENT, BACKGROUND, TEXT};
use kassigner_fw::ui::menu::{self, Menu};
use kassigner_fw::ui::savings::{self, Seen};
use kassigner_fw::ui::scale::{Kit, Scale, LARGE, SMALL};
use kassigner_fw::ui::seeds::{self, Seed};
use kassigner_fw::ui::words as word_ui;
use kassigner_fw::ui::{
    backup, camera, camtune, dialog, keyboard, loading, refusal, review, sd_card, settings,
};
use kassigner_hal::display::{Backlight, Display, Error, Rect, Size};
use kassigner_hal::provisioning::{Holes, Verdict};
use kassigner_hal::tune::Knob;

// The tests, by what they hold: texts that must fit, drawing, touch targets
// kept apart, the review pages, and the other screens. What they share is
// here: the panel, the samples, every screen, and the zone checks.
mod drawing;
mod fits;
mod other_screens;
mod reviews;
mod targets;

/// A panel that is a buffer, and counts how often each pixel was written.
struct Panel {
    size: Size,
    px: Vec<u16>,
    writes: Vec<u32>,
}

impl Panel {
    fn new(width: u16, height: u16) -> Self {
        let n = usize::from(width) * usize::from(height);
        Self {
            size: Size::new(width, height),
            px: vec![0x1234; n],
            writes: vec![0; n],
        }
    }

    fn at(&self, x: u16, y: u16) -> u16 {
        self.px[usize::from(y) * usize::from(self.size.width) + usize::from(x)]
    }
}

impl Display for Panel {
    fn size(&self) -> Size {
        self.size
    }

    fn blit(&mut self, rect: Rect, pixels: &[u16]) -> Result<(), Error> {
        self.check(rect, Some(pixels))?;
        let w = usize::from(self.size.width);
        for (i, &p) in pixels.iter().enumerate() {
            let x = usize::from(rect.x) + i % usize::from(rect.width);
            let y = usize::from(rect.y) + i / usize::from(rect.width);
            self.px[y * w + x] = p;
            self.writes[y * w + x] += 1;
        }
        Ok(())
    }

    fn fill(&mut self, rect: Rect, color: u16) -> Result<(), Error> {
        let n = rect.pixels();
        self.blit(rect, &vec![color; n])
    }

    fn set_backlight(&mut self, _level: Backlight) -> Result<(), Error> {
        Ok(())
    }
}

/// A whole panel.
fn whole(panel: &Panel) -> Rect {
    Rect::new(0, 0, panel.size.width, panel.size.height)
}

/// Something that draws a whole screen into a band.
type Painter = Box<dyn Fn(&mut Band<'_>)>;

/// Seven settings with a switch, as the M5 names them, and six without, as
/// the Waveshare does.
static SEVEN: [Knob; 7] = [
    Knob::new("AEC-Y", 0xFF, 8),
    Knob::new("EXPO-H", 0x0F, 1),
    Knob::new("EXPO-L", 0xFF, 8),
    Knob::new("GAIN", 0x3F, 2),
    Knob::new("PREGN", 0xFF, 8),
    Knob::new("CONTR", 0xFF, 8),
    Knob::new("SHARP", 0xFF, 8),
];
/// The most settings a board can name: [`SEVEN`] and one more.
static EIGHT: [Knob; 8] = [
    Knob::new("AEC-Y", 0xFF, 8),
    Knob::new("EXPO-H", 0x0F, 1),
    Knob::new("EXPO-L", 0xFF, 8),
    Knob::new("GAIN", 0x3F, 2),
    Knob::new("PREGN", 0xFF, 8),
    Knob::new("CONTR", 0xFF, 8),
    Knob::new("SHARP", 0xFF, 8),
    Knob::new("BRITE", 0xFF, 8),
];
static SIX: [Knob; 6] = [
    Knob::new("AEC-H", 0xFF, 4),
    Knob::new("AEC-L", 0xFF, 4),
    Knob::new("Contr", 0xFF, 4),
    Knob::new("Brite", 0xFF, 4),
    Knob::new("AGC", 0xFF, 4),
    Knob::new("Sharp", 0xFF, 4),
];

/// The sample rows, and the slots they assume.
const SEEDS: [Seed; 5] = seeds::SAMPLE;

/// Words for CHECK's previews: four of the list, the longest among them.
const CHECK_SAMPLE: [&str; 4] = ["abandon", "umbrella", "zoo", "midnight"];

/// The sample seeds, the one in use and one other without a backup.
fn unbacked_seeds() -> [Seed; 5] {
    let mut s = SEEDS;
    s[0].backed = false;
    s[4].backed = false;
    s
}

/// What the ERROR screen can say: each refusal's words, and the review's
/// and the reply's with each reason.
const REFUSALS: [(&str, refusal::Words); 78] = [
    (
        "refused_card_early",
        (refusal::CARD_LOCKED, refusal::CARD_EARLY),
    ),
    (
        "refused_card_final",
        (refusal::CARD_LOCKED, refusal::CARD_FINAL),
    ),
    ("refused_not_recognised", refusal::NOT_RECOGNISED),
    ("refused_not_a_request", refusal::NOT_A_REQUEST),
    ("refused_not_a_transaction", refusal::NOT_A_TRANSACTION),
    ("refused_not_reviewable", (refusal::NOT_REVIEWABLE, "")),
    (
        "refused_too_many_pages",
        (refusal::NOT_REVIEWABLE, refusal::TOO_MANY_PAGES),
    ),
    (
        "refused_value_overflow",
        (refusal::NOT_REVIEWABLE, refusal::VALUE_OVERFLOW),
    ),
    (
        "refused_not_native",
        (refusal::NOT_REVIEWABLE, refusal::NOT_NATIVE),
    ),
    ("refused_gas", (refusal::NOT_REVIEWABLE, refusal::GAS)),
    (
        "refused_storage_mass",
        (refusal::NOT_REVIEWABLE, refusal::STORAGE_MASS),
    ),
    (
        "refused_consensus",
        (refusal::NOT_REVIEWABLE, refusal::CONSENSUS),
    ),
    ("refused_not_signed", (refusal::NOT_SIGNED, "")),
    (
        "refused_nothing_signed",
        (refusal::NOT_SIGNED, refusal::NOTHING_SIGNED),
    ),
    (
        "refused_not_every_input",
        (refusal::NOT_SIGNED, refusal::NOT_EVERY_INPUT),
    ),
    (
        "refused_input_unsigned",
        (refusal::NOT_SIGNED, refusal::INPUT_UNSIGNED),
    ),
    (
        "refused_not_the_groups",
        (refusal::NOT_SIGNED, refusal::NOT_THE_GROUPS),
    ),
    (
        "refused_too_large",
        (refusal::NOT_SIGNED, refusal::TOO_LARGE),
    ),
    (
        "refused_not_one_transaction",
        (refusal::NOT_SIGNED, refusal::NOT_ONE_TRANSACTION),
    ),
    (
        "refused_sighash_not_all",
        (refusal::NOT_SIGNED, refusal::SIGHASH_NOT_ALL),
    ),
    (
        "refused_already_signed",
        (refusal::NOT_SIGNED, refusal::ALREADY_SIGNED),
    ),
    (
        "refused_bad_signature",
        (refusal::NOT_SIGNED, refusal::BAD_SIGNATURE),
    ),
    (
        "refused_multisig_too_many_keys",
        (refusal::NOT_SIGNED, refusal::MULTISIG_TOO_MANY_KEYS),
    ),
    (
        "refused_multisig_no_threshold",
        (refusal::NOT_SIGNED, refusal::MULTISIG_NO_THRESHOLD),
    ),
    (
        "refused_multisig_repeated_key",
        (refusal::NOT_SIGNED, refusal::MULTISIG_REPEATED_KEY),
    ),
    (
        "refused_multisig_op_count",
        (refusal::NOT_SIGNED, refusal::MULTISIG_OP_COUNT),
    ),
    ("refused_op_count", (refusal::NOT_SIGNED, refusal::OP_COUNT)),
    (
        "refused_redeem_mismatch",
        (refusal::NOT_SIGNED, refusal::REDEEM_MISMATCH),
    ),
    (
        "refused_no_redeem_script",
        (refusal::NOT_SIGNED, refusal::NO_REDEEM_SCRIPT),
    ),
    (
        "refused_signing_not_derived",
        (refusal::NOT_SIGNED, refusal::NOT_DERIVED.0),
    ),
    (
        "refused_tx_version",
        (refusal::NOT_REVIEWABLE, refusal::TX_VERSION),
    ),
    (
        "refused_covenant_input",
        (refusal::NOT_REVIEWABLE, refusal::COVENANT_INPUT),
    ),
    (
        "refused_script_version",
        (refusal::NOT_REVIEWABLE, refusal::SCRIPT_VERSION),
    ),
    (
        "refused_non_standard_output",
        (refusal::NOT_REVIEWABLE, refusal::NON_STANDARD_OUTPUT),
    ),
    (
        "refused_signing_no_entropy",
        (refusal::NOT_SIGNED, refusal::NO_ENTROPY.0),
    ),
    (
        "refused_above_supply",
        (refusal::NOT_REVIEWABLE, refusal::ABOVE_SUPPLY),
    ),
    (
        "refused_zero_output",
        (refusal::NOT_REVIEWABLE, refusal::ZERO_OUTPUT),
    ),
    (
        "refused_no_outputs",
        (refusal::NOT_REVIEWABLE, refusal::NO_OUTPUTS),
    ),
    (
        "refused_duplicate_input",
        (refusal::NOT_REVIEWABLE, refusal::DUPLICATE_INPUT),
    ),
    (
        "refused_payload_unshown",
        (refusal::NOT_REVIEWABLE, refusal::PAYLOAD_UNSHOWN),
    ),
    (
        "refused_script_unshown",
        (refusal::NOT_REVIEWABLE, refusal::SCRIPT_UNSHOWN),
    ),
    (
        "refused_relative_unshown",
        (refusal::NOT_REVIEWABLE, refusal::RELATIVE_UNSHOWN),
    ),
    ("refused_not_verified", refusal::NOT_VERIFIED),
    ("refused_request_changed", refusal::REQUEST_CHANGED),
    ("refused_not_a_seed", refusal::NOT_A_SEED),
    ("refused_not_a_kpub", refusal::NOT_A_KPUB),
    ("refused_key_added", refusal::KEY_ADDED),
    ("refused_group_not_made", refusal::GROUP_NOT_MADE),
    ("refused_not_a_descriptor", refusal::NOT_A_DESCRIPTOR),
    (
        "refused_card_backup_not_one",
        (refusal::CARD_BACKUP, refusal::BACKUP_NOT_ONE),
    ),
    (
        "refused_card_backup_malformed",
        (refusal::CARD_BACKUP, refusal::BACKUP_MALFORMED),
    ),
    (
        "refused_card_backup_bad_key",
        (refusal::CARD_BACKUP, refusal::BACKUP_BAD_KEY),
    ),
    (
        "refused_card_backup_bad_date",
        (refusal::CARD_BACKUP, refusal::BACKUP_BAD_DATE),
    ),
    (
        "refused_card_backup_bad_address",
        (refusal::CARD_BACKUP, refusal::BACKUP_BAD_ADDRESS),
    ),
    (
        "refused_card_backup_not_the_card",
        (refusal::CARD_BACKUP, refusal::BACKUP_NOT_THE_CARD),
    ),
    (
        "refused_card_backup_not_canonical",
        (refusal::CARD_BACKUP, refusal::BACKUP_NOT_CANONICAL),
    ),
    ("refused_no_cosigner_key", refusal::NO_COSIGNER_KEY),
    ("refused_no_kcc3_key", refusal::NO_KCC3_KEY),
    ("refused_not_a_key", refusal::NOT_A_KEY),
    ("refused_not_text", refusal::NOT_TEXT),
    ("refused_trailing_whitespace", refusal::TRAILING_WHITESPACE),
    ("refused_not_mainnet", refusal::NOT_MAINNET),
    ("refused_seed_not_message", refusal::SEED_NOT_MESSAGE),
    ("refused_plain_text", refusal::PLAIN_TEXT),
    ("refused_no_phrase", refusal::NO_PHRASE),
    ("refused_no_wallet", refusal::NO_WALLET),
    ("refused_not_backed_up", refusal::NOT_BACKED_UP),
    ("check_wrong_word", refusal::WRONG_WORD),
    ("check_not_this_seed", refusal::NOT_THIS_SEED),
    ("refused_not_opened", refusal::NOT_OPENED),
    ("refused_slots_full", refusal::SLOTS_FULL),
    ("refused_no_entropy", refusal::NO_ENTROPY),
    ("refused_declined", refusal::DECLINED),
    ("refused_no_camera", refusal::NO_CAMERA),
    ("refused_not_saved", refusal::NOT_SAVED),
    ("refused_not_derived", refusal::NOT_DERIVED),
    ("refused_too_long", refusal::TOO_LONG),
    ("refused_message_not_signed", refusal::MESSAGE_NOT_SIGNED),
];
const CAPACITY: usize = seeds::SAMPLE_CAPACITY;

/// Addresses for the review's pages: a key's, the seed's change, a
/// script's.
const REVIEW_ADDRESS: &str = "kaspa:qz20g2ugrrm629fnnvmfjpsjlx9zu2f2zj828wwpv9gvxcnajl0qs36s8hfkl";
const REVIEW_CHANGE: &str = "kaspa:qqnkyg4hha30lnjystpugz42yh3paurdylxfrsshk3jfstgy95elu2a8l3jcs";
const REVIEW_P2SH: &str = "kaspa:prmr0h7fcx5z8n9aqjt4lrx0f4tmy92u0ftck3spqtqka9833jepjqzv0u403";

/// A Time-Locked Savings card, its owner's key and its recovery wallet's,
/// as the backup line's test vector has them.
const CARD: &str = "kaspa:ppx4y2gfned75sa9w64fw7rjumtng5yyzs4s4vmrv6appfgut0jcv5q4pg9pg";
const CARD_OWNER: &str = "kaspa:qqdcf32k0vfxgsyet5ldt246q4jaw8scx3sysx0lnstlt6w4m5rc72kqpk9q3";
const CARD_RECOVERY: &str = "kaspa:qpx5kmx3xcgr9j5m62htnkgq4fx5tk02mq9vjs3nwnz9rfe9f5rkvz0673pmd";

/// A covenant's id, for the gallery's covenant pages.
const COVENANT_ID: [u8; 32] = [
    0xa3, 0xf9, 0x1c, 0x07, 0xd2, 0xb8, 0x4e, 0x6f, 0x5a, 0x10, 0x90, 0xc7, 0xe3, 0xd4, 0xb2, 0xa1,
    0x8f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x19, 0x08, 0x7f, 0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0x7e, 0x41,
];

/// What the flow says on a card job's result screen, for the gallery.
const SAID: sd_card::Said = sd_card::Said {
    saved: "!! Backup Saved !!",
    failed: sd_card::BACKUP_FAILED,
    empty: ("NO BACKUPS", "No backups on the card"),
};

/// A battery gauge for Home.
fn gauge(percent: u8, charging: bool) -> brand::Gauge {
    brand::Gauge::Level { percent, charging }
}

/// The kit for a panel.
fn kit(size: Size) -> &'static Kit {
    if size.height > 240 {
        &LARGE
    } else {
        &SMALL
    }
}

/// A real Waveshare app image's SHA-256, `a654a85f...e941b4cb`, for the
/// verification screen's previews.
const SAMPLE_SHA256: [u8; 32] = [
    0xa6, 0x54, 0xa8, 0x5f, 0x3f, 0x5a, 0x4e, 0x67, 0x52, 0x65, 0x3e, 0x1e, 0x68, 0xe2, 0x06, 0xb4,
    0xa3, 0xe8, 0xf5, 0xee, 0x76, 0x78, 0xbf, 0x94, 0x28, 0xe7, 0x14, 0x5d, 0xb9, 0x41, 0xb4, 0xcb,
];

/// The verification screen, at boot or as About, for a preview.
fn verified(
    scale: Scale,
    kit: &'static Kit,
    read: bool,
    verdict: Verdict,
    unit: Option<&'static str>,
) -> Painter {
    Box::new(move |b: &mut Band<'_>| {
        let kept = brand::shown(&SAMPLE_SHA256);
        let hash = read.then_some(&kept);
        brand::verification(b, scale, kit, "1.1.0", hash, verdict, unit)
    })
}

/// Only download mode open.
const DOWNLOAD_OPEN: Holes = Holes {
    key_slot: false,
    jtag: false,
    download: true,
};

/// Every hole open, for the longest line.
const ALL_OPEN: Holes = Holes {
    key_slot: true,
    jtag: true,
    download: true,
};

/// Every screen, each as a painter over a panel of its size.
fn screens(size: Size) -> Vec<(&'static str, Painter)> {
    let scale = Scale::for_panel(size);
    let kit = kit(size);
    let mut out: Vec<(&'static str, Painter)> = vec![
        (
            "logo",
            Box::new(move |b: &mut Band<'_>| {
                brand::logo(b, scale, kit, "v1.1.0", "M5Stack CoreS3")
            }),
        ),
        (
            "verification_blank",
            verified(scale, kit, true, Verdict::Blank, None),
        ),
        (
            "verification_provisioned",
            verified(scale, kit, true, Verdict::Provisioned, None),
        ),
        (
            "verification_holes",
            verified(scale, kit, true, Verdict::Holes(DOWNLOAD_OPEN), None),
        ),
        (
            "verification_holes_all",
            verified(scale, kit, true, Verdict::Holes(ALL_OPEN), None),
        ),
        (
            "verification_unread",
            verified(scale, kit, false, Verdict::Provisioned, None),
        ),
        (
            "about",
            verified(
                scale,
                kit,
                true,
                Verdict::Provisioned,
                Some("M5Stack CoreS3"),
            ),
        ),
        (
            "home",
            Box::new(move |b: &mut Band<'_>| brand::home(b, scale, kit, None, None)),
        ),
        (
            "home_pressed",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, Some(brand::Target::Card(1)), None)
            }),
        ),
        (
            "home_battery",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, None, Some(gauge(72, false)))
            }),
        ),
        (
            "home_battery_low",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, None, Some(gauge(22, false)))
            }),
        ),
        (
            "home_battery_empty",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, None, Some(gauge(8, false)))
            }),
        ),
        (
            "home_battery_charging",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, None, Some(gauge(100, true)))
            }),
        ),
        (
            "home_battery_none",
            Box::new(move |b: &mut Band<'_>| {
                brand::home(b, scale, kit, None, Some(brand::Gauge::Empty))
            }),
        ),
        (
            "seeds",
            Box::new(move |b: &mut Band<'_>| seeds::draw(b, scale, kit, &SEEDS, CAPACITY, 0, None)),
        ),
        (
            "seeds_page2",
            Box::new(move |b: &mut Band<'_>| {
                let lit = Some(seeds::Target::Delete(0));
                seeds::draw(b, scale, kit, &SEEDS, CAPACITY, 1, lit)
            }),
        ),
        (
            "seeds_empty",
            Box::new(move |b: &mut Band<'_>| seeds::draw(b, scale, kit, &[], CAPACITY, 0, None)),
        ),
    ];
    // The review's pages; CONFIRM SEND? repeats TX REVIEW's counts.
    const SINGLE: review::Counted = review::Counted {
        inputs: 1,
        outputs: 2,
        group: None,
        unchecked: false,
    };
    const GROUP: review::Counted = review::Counted {
        inputs: 2,
        outputs: 2,
        group: Some((2, 3)),
        unchecked: false,
    };
    // No group held: the warning, with the M of N the inputs share.
    const UNCHECKED: review::Counted = review::Counted {
        unchecked: true,
        ..GROUP
    };
    // Inputs that share no M of N, a single key's beside a multisig's: the
    // warning all the same.
    const MIXED: review::Counted = review::Counted {
        inputs: 3,
        outputs: 2,
        group: None,
        unchecked: true,
    };
    // The most a request is let through with, and the largest group.
    const WIDEST: review::Counted = review::Counted {
        inputs: kassigner_fw::limits::MAX_INPUTS,
        outputs: kassigner_fw::limits::MAX_OUTPUTS,
        group: Some((
            kassigner_fw::limits::MAX_MULTISIG_KEYS,
            kassigner_fw::limits::MAX_MULTISIG_KEYS,
        )),
        unchecked: false,
    };
    let totals = review::Totals {
        out: 499_000_000,
        spent: 500_000_000,
        fee: 1_000_000,
    };
    let pages: [(&'static str, review::Shown<'static>, usize); 19] = [
        // A covenant an input's UTXO is bound to, continued in an output.
        (
            "review_covenant_continued",
            review::Shown::Covenant {
                id: COVENANT_ID,
                spent: 1,
                outputs: 0b1,
                from: None,
            },
            2,
        ),
        // The same, ending here: no output continues it.
        (
            "review_covenant_ended",
            review::Shown::Covenant {
                id: COVENANT_ID,
                spent: 1,
                outputs: 0,
                from: None,
            },
            2,
        ),
        // One that starts here, in output 2, authorized by input 1.
        (
            "review_covenant_new",
            review::Shown::Covenant {
                id: COVENANT_ID,
                spent: 0,
                outputs: 0b10,
                from: Some(0),
            },
            2,
        ),
        // The widest a unit says: every input and every output it takes.
        (
            "review_covenant_widest",
            review::Shown::Covenant {
                id: COVENANT_ID,
                spent: 32,
                outputs: 0xFF,
                from: None,
            },
            2,
        ),
        (
            "review_card_claim",
            review::Shown::Card {
                address: CARD,
                unlock: 1_798_761_600_000,
                utxos: 3,
                recover: false,
                other: Some(CARD_RECOVERY),
            },
            1,
        ),
        (
            "review_card_claim_none",
            review::Shown::Card {
                address: CARD,
                unlock: 1_798_761_600_000,
                utxos: 1,
                recover: false,
                other: None,
            },
            1,
        ),
        (
            "review_card_recover",
            review::Shown::Card {
                address: CARD,
                unlock: 1_798_761_600_000,
                utxos: 3,
                recover: true,
                other: Some(CARD_OWNER),
            },
            1,
        ),
        (
            "review_summary",
            review::Shown::Summary {
                totals,
                inputs: 1,
                outputs: 2,
                group: None,
                unchecked: false,
            },
            0,
        ),
        // A group's spend: its M of N, in the group's orange.
        (
            "review_summary_group",
            review::Shown::Summary {
                totals,
                inputs: 2,
                outputs: 2,
                group: Some((2, 3)),
                unchecked: false,
            },
            0,
        ),
        // The same with no group held: one line, in the warning's colour.
        (
            "review_summary_unchecked",
            review::Shown::Summary {
                totals,
                inputs: 2,
                outputs: 2,
                group: Some((2, 3)),
                unchecked: true,
            },
            0,
        ),
        // Inputs that share no M of N, no group held: the warning alone.
        (
            "review_summary_mixed",
            review::Shown::Summary {
                totals,
                inputs: 3,
                outputs: 2,
                group: None,
                unchecked: true,
            },
            0,
        ),
        // The group's own change: a script's address, and CHANGE.
        (
            "review_output_group_change",
            review::Shown::Output {
                number: 2,
                value: 399_000_000,
                address: REVIEW_P2SH,
                script: true,
                change: review::Change::At(4),
            },
            2,
        ),
        // LOCK TIME: a DAA score, a time with its milliseconds, and one
        // consensus ignores.
        (
            "review_lock_daa",
            review::Shown::LockTime {
                value: 412_345_678,
                ignored: false,
            },
            2,
        ),
        (
            "review_lock_time",
            review::Shown::LockTime {
                value: 1_798_761_599_250,
                ignored: false,
            },
            2,
        ),
        (
            "review_lock_ignored",
            review::Shown::LockTime {
                value: 412_345_678,
                ignored: true,
            },
            2,
        ),
        (
            "review_output",
            review::Shown::Output {
                number: 1,
                value: 100_000_000,
                address: REVIEW_ADDRESS,
                script: false,
                change: review::Change::No,
            },
            1,
        ),
        (
            "review_output_change",
            review::Shown::Output {
                number: 2,
                value: 399_000_000,
                address: REVIEW_CHANGE,
                script: false,
                change: review::Change::At(560),
            },
            2,
        ),
        // A payment to one of the seed's own receive addresses: YOURS.
        (
            "review_output_yours",
            review::Shown::Output {
                number: 1,
                value: 100_000_000,
                address: REVIEW_CHANGE,
                script: false,
                change: review::Change::Yours(3),
            },
            1,
        ),
        (
            "review_output_p2sh",
            review::Shown::Output {
                number: 1,
                value: 1_234_567_800_000_000,
                address: REVIEW_P2SH,
                script: true,
                change: review::Change::No,
            },
            1,
        ),
    ];
    for (name, shown, index) in pages {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| review::draw(b, scale, kit, &shown, (index, 3))),
        ));
    }
    out.push((
        "wiped",
        Box::new(move |b: &mut Band<'_>| brand::wiped(b, scale, kit)),
    ));
    out.push((
        "review_confirm",
        Box::new(move |b: &mut Band<'_>| review::draw_confirm(b, scale, kit, &totals, &SINGLE)),
    ));
    out.push((
        "review_confirm_group",
        Box::new(move |b: &mut Band<'_>| review::draw_confirm(b, scale, kit, &totals, &GROUP)),
    ));
    out.push((
        "review_confirm_unchecked",
        Box::new(move |b: &mut Band<'_>| review::draw_confirm(b, scale, kit, &totals, &UNCHECKED)),
    ));
    out.push((
        "review_confirm_mixed",
        Box::new(move |b: &mut Band<'_>| review::draw_confirm(b, scale, kit, &totals, &MIXED)),
    ));
    out.push((
        "signing",
        Box::new(move |b: &mut Band<'_>| loading::draw(b, scale, kit, loading::SIGNING, 1, 2)),
    ));
    out.push((
        "checking",
        Box::new(move |b: &mut Band<'_>| loading::draw(b, scale, kit, loading::CHECKING, 1, 2)),
    ));
    out.push((
        "signing_message",
        Box::new(move |b: &mut Band<'_>| {
            loading::draw(b, scale, kit, loading::SIGNING_MESSAGE, 1, 2)
        }),
    ));
    let whale = review::Totals {
        out: 1_234_567_000_000_000,
        spent: 1_234_567_100_000_000,
        fee: 100_000_000,
    };
    out.push((
        "review_confirm_whale",
        Box::new(move |b: &mut Band<'_>| review::draw_confirm(b, scale, kit, &whale, &WIDEST)),
    ));
    out.push((
        "load",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(
                b,
                scale,
                kit,
                &dialog::load(12),
                Some(dialog::Target::Accept),
            )
        }),
    ));
    out.push((
        "message",
        Box::new(move |b: &mut Band<'_>| {
            let t = "I, the holder of this address, confirm the payment of 12 KAS for invoice 2026-118 was sent by me.\nSigned on the unit.";
            let pages = kassigner_fw::ui::address::message_pages(t);
            kassigner_fw::ui::address::draw_message(b, scale, kit, t, (0, pages), (false, false))
        }),
    ));
    out.push((
        "message_read",
        Box::new(move |b: &mut Band<'_>| {
            let t = "I, the holder of this address, confirm the payment of 12 KAS for invoice 2026-118 was sent by me.\nSigned on the unit.";
            let pages = kassigner_fw::ui::address::message_pages(t);
            kassigner_fw::ui::address::draw_message(b, scale, kit, t, (pages - 1, pages), (false, true))
        }),
    ));
    out.push((
        "sign_with",
        Box::new(move |b: &mut Band<'_>| {
            let a = "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs";
            kassigner_fw::ui::address::draw_sign_with(b, scale, kit, a, false, 3)
        }),
    ));
    for (name, page) in [("signed_0", 0u8), ("signed_1", 1)] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let s = "3c1a9f2b7d4e8a6c0f5b2e9d7a4c1b8e6f3a0d9c7b5e2a8f4d1c6b9e3a7f0d5c2b8e4a1f6d9c3b7e0a5f2d8c4b1e9a6f3d0c7b5e2a8f4d1c6b9e3a7f0d5c2b8e";
                let a = "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs";
                kassigner_fw::ui::address::draw_signed(b, scale, kit, page, s, a)
            }),
        ));
    }
    for (name, valid) in [
        ("message_valid", Some(true)),
        ("message_invalid", Some(false)),
        ("message_unchecked", None),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::address::draw_ask(
                    b,
                    scale,
                    kit,
                    &dialog::checked(valid),
                    "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs",
                )
            }),
        ));
    }
    out.push((
        "signed_message",
        Box::new(move |b: &mut Band<'_>| {
            let t = "I own this address.";
            kassigner_fw::ui::address::draw_message(b, scale, kit, t, (0, 1), (true, true))
        }),
    ));
    out.push((
        "message_format",
        Box::new(move |b: &mut Band<'_>| {
            let mut buf = [0u8; 24];
            let hint = kassigner_fw::ui::kpub::codes_hint("Text", 7, &mut buf);
            kassigner_fw::ui::kpub::format(
                b,
                scale,
                kit,
                kassigner_fw::ui::kpub::MESSAGE_TITLE,
                ("Text, 1 QR", hint),
            )
        }),
    ));
    // Past the 64 frames a unit reassembles: KasSigner dimmed, saying why.
    out.push((
        "message_format_too_long",
        Box::new(move |b: &mut Band<'_>| {
            let mut buf = [0u8; 24];
            let hint = kassigner_fw::ui::kpub::codes_hint("Text", 15, &mut buf);
            kassigner_fw::ui::kpub::format_live(
                b,
                scale,
                kit,
                kassigner_fw::ui::kpub::MESSAGE_TITLE,
                (hint, refusal::TOO_LARGE),
                (true, false),
            )
        }),
    ));
    out.push((
        "reply_format",
        Box::new(move |b: &mut Band<'_>| {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let wallet = kassigner_fw::ui::kpub::codes_hint("PSKB", 9, &mut one);
            let unit = kassigner_fw::ui::kpub::codes_hint("PSKB", 41, &mut two);
            kassigner_fw::ui::kpub::format(
                b,
                scale,
                kit,
                kassigner_fw::ui::kpub::REPLY_TITLE,
                (wallet, unit),
            )
        }),
    ));
    // A single-key request of a wallet built on v1.0.7: Wallet shows the
    // reply in that release's form.
    out.push((
        "reply_format_v107",
        Box::new(move |b: &mut Band<'_>| {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let wallet =
                kassigner_fw::ui::kpub::codes_hint(kassigner_fw::ui::kpub::REPLY_V107, 2, &mut one);
            let unit = kassigner_fw::ui::kpub::codes_hint("KSPT", 8, &mut two);
            kassigner_fw::ui::kpub::format(
                b,
                scale,
                kit,
                kassigner_fw::ui::kpub::REPLY_TITLE,
                (wallet, unit),
            )
        }),
    ));
    out.push((
        "sign_message_ask",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::address::draw_ask(
                b,
                scale,
                kit,
                &dialog::sign_with(),
                "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs",
            )
        }),
    ));
    out.push((
        "import_key",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::address::draw_ask(
                b,
                scale,
                kit,
                &dialog::import_key(),
                "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs",
            )
        }),
    ));
    out.push((
        "delete",
        Box::new(move |b: &mut Band<'_>| {
            let mut line = [0u8; 40];
            let d = dialog::delete(SEEDS[1].describe(&mut line), Some(60));
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "scan",
        Box::new(move |b: &mut Band<'_>| {
            let mut buf = [0u8; 16];
            let count = camera::scan_counter(1, 3, &mut buf);
            camera::chrome(b, scale, kit, camera::SCAN, count, None)
        }),
    ));
    // The scan's dots beside its square: `total` frames, `received` as
    // bits.
    for (name, total, received) in [
        ("scan_dots_3", 3usize, 0b101u64),
        ("scan_dots_12", 12, 0b1011_1110_1111),
        ("scan_dots_21", 21, 0x0F_7BEF),
        ("scan_dots_32", 32, 0xFFFF_7FFF),
        ("scan_dots_46", 46, 0x2DFF_FFFF_FFEF),
        ("scan_dots_64", 64, 0xFFFF_FFFF_FFFF_FFF3),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let mut buf = [0u8; 16];
                let have = received.count_ones() as usize;
                let count = camera::scan_counter(have, total, &mut buf);
                camera::chrome(b, scale, kit, camera::SCAN, count, None);
                camera::scan_side(b, scale, kit, None, (total, received));
            }),
        ));
    }
    out.push((
        "scan_line",
        Box::new(move |b: &mut Band<'_>| {
            camera::chrome(b, scale, kit, camera::SCAN, "", None);
            camera::scan_side(b, scale, kit, Some(camera::SEED_HINT), (0, 0));
        }),
    ));
    out.push((
        "new_seed",
        Box::new(move |b: &mut Band<'_>| {
            let mut buf = [0u8; 16];
            let count = camera::seed_counter(181, &mut buf);
            let hint = camera::seed_hint(Some(kassigner_fw::seed::Source::Touch));
            camera::chrome(b, scale, kit, camera::NEW_SEED, count, Some(hint))
        }),
    ));
    out.push((
        "loading",
        Box::new(move |b: &mut Band<'_>| {
            let text = kassigner_fw::ui::loading::OPENING;
            kassigner_fw::ui::loading::draw(b, scale, kit, text, 9, 26)
        }),
    ));
    out.push((
        "seed_tools_page2",
        Box::new(move |b: &mut Band<'_>| menu::draw(b, scale, kit, &menu::SEED_TOOLS, 1, None)),
    ));
    out.push((
        "display",
        Box::new(move |b: &mut Band<'_>| {
            let lit = Some(settings::Target::Plus);
            settings::level(b, scale, kit, settings::DISPLAY, 153, lit)
        }),
    ));
    out.push((
        "audio",
        Box::new(move |b: &mut Band<'_>| settings::level(b, scale, kit, settings::AUDIO, 18, None)),
    ));
    out.push((
        "camtune_m5",
        Box::new(move |b: &mut Band<'_>| {
            let t = camtune::Tuning {
                knobs: &SEVEN,
                picked: 1,
                value: 0x05,
                auto: Some(false),
            };
            camtune::draw(b, scale, kit, &t, Some(camtune::Target::Plus))
        }),
    ));
    out.push((
        "camtune_ws",
        Box::new(move |b: &mut Band<'_>| {
            let t = camtune::Tuning {
                knobs: &SIX,
                picked: 0,
                value: 0x60,
                auto: None,
            };
            camtune::draw(b, scale, kit, &t, None)
        }),
    ));
    let present = card::Status::Present(Kind::SdV2High);
    out.push((
        "sd_card",
        Box::new(move |b: &mut Band<'_>| {
            sd_card::draw(b, scale, kit, present, Some(sd_card::Target::Test))
        }),
    ));
    out.push((
        "sd_card_absent",
        Box::new(move |b: &mut Band<'_>| sd_card::draw(b, scale, kit, card::Status::Absent, None)),
    ));
    out.push((
        "sd_card_checking",
        Box::new(move |b: &mut Band<'_>| {
            sd_card::draw(b, scale, kit, card::Status::Checking, None)
        }),
    ));
    out.push((
        "sd_format",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::format(Some(40)), None)
        }),
    ));
    // A seed's backup with no password: the warning, its SAVE half held.
    out.push((
        "backup_no_password",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::no_password(None), None)
        }),
    ));
    out.push((
        "backup_no_password_held",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::no_password(Some(50)), None)
        }),
    ));
    out.push((
        "sd_busy",
        Box::new(move |b: &mut Band<'_>| sd_card::busy(b, scale, kit, Job::Format)),
    ));
    out.push((
        "sd_tested",
        Box::new(move |b: &mut Band<'_>| {
            let o = Outcome::Tested {
                bytes: 34,
                files: 3,
            };
            sd_card::done(b, scale, kit, (Job::Test, o), SAID)
        }),
    ));
    out.push((
        "sd_formatted",
        Box::new(move |b: &mut Band<'_>| {
            sd_card::done(b, scale, kit, (Job::Format, Outcome::Formatted), SAID)
        }),
    ));
    out.push((
        "sd_test_failed",
        Box::new(move |b: &mut Band<'_>| {
            let o = Outcome::Failed(card::Error::Data);
            sd_card::done(b, scale, kit, (Job::Test, o), SAID)
        }),
    ));
    out.push((
        "sd_save_failed_no_card",
        Box::new(move |b: &mut Band<'_>| {
            let said = sd_card::Said {
                failed: sd_card::TX_SAVE_FAILED,
                ..SAID
            };
            sd_card::done(b, scale, kit, (Job::NextName, Outcome::Absent), said)
        }),
    ));
    out.push((
        "sd_format_failed",
        Box::new(move |b: &mut Band<'_>| {
            let o = Outcome::Failed(card::Error::Filesystem("Card too small for FAT32"));
            sd_card::done(b, scale, kit, (Job::Format, o), SAID)
        }),
    ));
    for page in 0..keyboard::PAGES {
        let name: &'static str =
            ["keyboard_0", "keyboard_1", "keyboard_2", "keyboard_3"][page as usize];
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let text = "Correct horse battery staple, 42 times!";
                let line = keyboard::Line {
                    text,
                    cursor: 30,
                    note: None,
                    mode: keyboard::Mode::Text { full: false },
                    word: None,
                };
                keyboard::draw(b, scale, kit, "PASSPHRASE", page, line)
            }),
        ));
    }
    out.push((
        "keyboard_empty",
        Box::new(move |b: &mut Band<'_>| {
            let line = keyboard::Line {
                text: "",
                cursor: 0,
                note: None,
                mode: keyboard::Mode::Text { full: false },
                word: None,
            };
            keyboard::draw(b, scale, kit, "PASSPHRASE", 0, line)
        }),
    ));
    // At its limit: the count in the limit's colour, the keys that type dim.
    out.push((
        "keyboard_full",
        Box::new(move |b: &mut Band<'_>| {
            let text = "Correct horse battery staple, and then some more of the same, 64";
            let line = keyboard::Line {
                text,
                cursor: text.len(),
                note: Some(keyboard::Note::Count { used: 64, of: 64 }),
                mode: keyboard::Mode::Text { full: true },
                word: None,
            };
            keyboard::draw(b, scale, kit, "PASSPHRASE", 0, line)
        }),
    ));
    for (name, typed) in [
        ("keyboard_hex", "24cd8d2875e8e17e4f88fbc5"),
        (
            "keyboard_hex_full",
            "24cd8d2875e8e17e4f88fbc554834a89b7b3e0c6f9d84fae36883604359ba440",
        ),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let line = keyboard::Line {
                    text: typed,
                    cursor: typed.len(),
                    note: Some(keyboard::Note::Count {
                        used: typed.len() as u8,
                        of: 64,
                    }),
                    mode: keyboard::Mode::Hex {
                        full: typed.len() >= 64,
                    },
                    word: None,
                };
                keyboard::draw(b, scale, kit, "IMPORT KEY", keyboard::HEX_PAGE, line)
            }),
        ));
    }
    out.push((
        "keyboard_password",
        Box::new(move |b: &mut Band<'_>| {
            let text = "Correct-Horse-Battery-Staple-9";
            let line = keyboard::Line {
                text,
                cursor: text.len(),
                note: Some(keyboard::Note::Good),
                mode: keyboard::Mode::Text { full: false },
                word: None,
            };
            keyboard::draw(b, scale, kit, "PASSWORD", 1, line)
        }),
    ));
    out.push((
        "restore_list",
        Box::new(move |b: &mut Band<'_>| {
            let names: Vec<[u8; 11]> = (1..=6)
                .map(|i| kassigner_fw::card::name83(format!("SD000{i}").as_bytes(), b"KAS"))
                .collect();
            backup::list(b, scale, kit, "SELECT BACKUP", (0, &names), 3)
        }),
    ));
    out.push((
        "keyboard_delete",
        Box::new(move |b: &mut Band<'_>| {
            let line = keyboard::Line {
                text: "",
                cursor: 0,
                note: None,
                mode: keyboard::Mode::Text { full: false },
                word: None,
            };
            let title = kassigner_fw::flow::Typing::DeletePassword.title();
            keyboard::draw(b, scale, kit, title, 0, line)
        }),
    ));
    out.push((
        "keyboard_overwrite",
        Box::new(move |b: &mut Band<'_>| {
            let line = keyboard::Line {
                text: "",
                cursor: 0,
                note: None,
                mode: keyboard::Mode::Text { full: false },
                word: None,
            };
            let title = kassigner_fw::flow::Typing::OverwritePassword.title();
            keyboard::draw(b, scale, kit, title, 0, line)
        }),
    ));
    for (name, typed, invalid) in [
        ("words_chips", "ab", false),
        ("words_one", "aba", false),
        ("words_invalid", "zoo", true),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let found = kassigner_fw::words::lookup(typed);
                let word = |i: u16| kassigner_crypto::bip39::index_to_word(i).unwrap_or("");
                let mut chips = [""; kassigner_fw::words::SHOWN];
                for (c, &i) in chips.iter_mut().zip(&found.first[..found.shown]) {
                    *c = word(i);
                }
                let line = keyboard::Line {
                    text: typed,
                    cursor: typed.len(),
                    note: None,
                    mode: keyboard::Mode::Word {
                        back: true,
                        on: false,
                        take: found.taken().is_some(),
                        chips: if found.count > 1 {
                            found.shown as u8
                        } else {
                            0
                        },
                    },
                    word: Some(keyboard::WordLine {
                        completes: found.taken().map(word).filter(|&w| w != typed),
                        chips,
                        shown: if found.count > 1 { found.shown } else { 0 },
                        status: invalid
                            .then_some(("Invalid seed phrase", kassigner_fw::ui::color::DANGER)),
                    }),
                };
                let mut t = [0u8; 24];
                let title = kassigner_fw::ui::words::title(&mut t, "IMPORT", 4, 12);
                keyboard::draw(b, scale, kit, title, 0, line)
            }),
        ));
    }
    out.push((
        "address",
        Box::new(move |b: &mut Band<'_>| {
            let a = "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs";
            kassigner_fw::ui::address::draw(b, scale, kit, a, false, 0, false)
        }),
    ));
    out.push((
        "kcc3_address",
        Box::new(move |b: &mut Band<'_>| {
            let a = "kaspa:pq02dzckvs0g6hhl9s9c484fv0wsd93sltwct9symfad4yw062w5y4v4mtlxa";
            kassigner_fw::ui::address::draw_kcc3(b, scale, kit, a, false, 0)
        }),
    ));
    out.push((
        "address_single",
        Box::new(move |b: &mut Band<'_>| {
            let a = "kaspa:qypr7ayn2rx5vstkxs9uf2kl0n3lnsvnmu2fm34ghsyspra0dkt2yqcmwhv3kqs";
            kassigner_fw::ui::address::draw(b, scale, kit, a, false, 0, true)
        }),
    ));
    out.push((
        "private_key",
        Box::new(move |b: &mut Band<'_>| {
            let k = "24cd8d2875e8e17e4f88fbc554834a89b7b3e0c6f9d84fae36883604359ba440";
            kassigner_fw::ui::address::draw_key(b, scale, kit, k, true, 70_000, false)
        }),
    ));
    out.push((
        "private_key_single",
        Box::new(move |b: &mut Band<'_>| {
            let k = "24cd8d2875e8e17e4f88fbc554834a89b7b3e0c6f9d84fae36883604359ba440";
            kassigner_fw::ui::address::draw_key(b, scale, kit, k, false, 0, true)
        }),
    ));
    for (name, title, text) in [
        (
            "kprv_master",
            kassigner_fw::ui::address::KPRV_MASTER,
            "kprv5y2qurMHCsXYqi1QoHPHz5JDcJ1FBjYgerR5Dehe7q5Co3TDm7n9q2T4dPDBwYwNYDvMR9XNAkaghw94L49vqPzvWxipwqSxRzD9jWrgb29",
        ),
        (
            "kprv_account",
            kassigner_fw::ui::address::KPRV_ACCOUNT,
            "kprv65YUEJDB9cdBQreWqeparu9zQnQJGCVqtp69WS23QZPiwP5XdmB94bydJsK37ehzbYWXYroSZupcW5zKAjyJbeqojEKVTBXJdJN5tdBtM6k",
        ),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::address::draw_text(b, scale, kit, title, text)
            }),
        ));
    }
    out.push((
        "address_index",
        Box::new(move |b: &mut Band<'_>| {
            use kassigner_fw::ui::keypad;
            keypad::draw(b, scale, kit, keypad::ADDRESS_TITLE, "25", keypad::HINT)
        }),
    ));
    out.push((
        "seedqr_grid",
        Box::new(move |b: &mut Band<'_>| {
            let code = kassigner_qr::encode::encode_numeric(
                b"123456789012345678901234567890123456789012345678",
            )
            .unwrap();
            kassigner_fw::ui::seedqr::draw(b, scale, kit, &code, (3, 0))
        }),
    ));
    out.push((
        "seedqr_grid_bottom",
        Box::new(move |b: &mut Band<'_>| {
            // A 24-word Standard SeedQR's 29 rows, at the bottom: W to Z,
            // then a', b' and c'.
            let code = kassigner_qr::encode::encode_numeric(&[b'7'; 96]).unwrap();
            assert_eq!(code.size, 29);
            kassigner_fw::ui::seedqr::draw(b, scale, kit, &code, (0, 22))
        }),
    ));
    out.push((
        "kpub_format",
        Box::new(move |b: &mut Band<'_>| {
            use kassigner_fw::ui::kpub;
            kpub::format(b, scale, kit, kpub::KPUB_TITLE, kpub::KPUB_HINTS)
        }),
    ));
    out.push((
        "kpub_mode",
        Box::new(move |b: &mut Band<'_>| dialog::draw(b, scale, kit, &dialog::qr_mode(), None)),
    ));
    out.push((
        "kpub_exported",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::kpub_exported(), None)
        }),
    ));
    out.push((
        "signed_tx",
        Box::new(move |b: &mut Band<'_>| dialog::draw(b, scale, kit, &dialog::signed_tx(), None)),
    ));
    out.push((
        "message_exported",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::message_exported(), None)
        }),
    ));
    out.push((
        "address_exported",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::address_exported(), None)
        }),
    ));
    out.push((
        "seed_exported",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::seed_exported(), None)
        }),
    ));
    out.push((
        "encrypt_file",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::encrypt_file(), None)
        }),
    ));
    out.push((
        "kpub_counter",
        Box::new(move |b: &mut Band<'_>| {
            let panel = (scale.x(320) as u16, scale.y(240) as u16);
            kassigner_fw::ui::kpub::counter(b, scale, kit, panel, (0, 2))
        }),
    ));
    out.push((
        "reply_signer",
        Box::new(move |b: &mut Band<'_>| {
            let panel = (scale.x(320) as u16, scale.y(240) as u16);
            kassigner_fw::ui::kpub::signer(b, scale, kit, panel, (1, 2));
            kassigner_fw::ui::kpub::counter(b, scale, kit, panel, (2, 3))
        }),
    ));
    out.push((
        "dice",
        Box::new(move |b: &mut Band<'_>| kassigner_fw::ui::dice::draw(b, scale, kit, 37, 99)),
    ));
    out.push((
        "dice_refused",
        Box::new(move |b: &mut Band<'_>| kassigner_fw::ui::dice::refused(b, scale, kit)),
    ));
    out.push((
        "dice_uneven",
        Box::new(move |b: &mut Band<'_>| {
            let (mut first, mut second) = ([0u8; 32], [0u8; 16]);
            let d = dialog::uneven_rolls((4, 6, 99), &mut first, &mut second);
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    // The backup check's screens, and a seed with no backup on the seeds
    // screen.
    for (name, qr) in [("backup_check", false), ("backup_check_qr", true)] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                dialog::draw(b, scale, kit, &dialog::backup_check(qr), None)
            }),
        ));
    }
    for (name, lit) in [
        ("word_check", None),
        ("word_check_lit", Some(word_ui::CheckTarget::Choice(2))),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                word_ui::check(b, scale, kit, (1, 3), 6, CHECK_SAMPLE, lit)
            }),
        ));
    }
    out.push((
        "backup_checked",
        Box::new(move |b: &mut Band<'_>| word_ui::checked(b, scale, kit)),
    ));
    out.push((
        "backup_scan",
        Box::new(move |b: &mut Band<'_>| {
            camera::chrome(b, scale, kit, camera::CHECK_BACKUP, "", None);
        }),
    ));
    out.push((
        "seeds_no_backup",
        Box::new(move |b: &mut Band<'_>| {
            seeds::draw(b, scale, kit, &unbacked_seeds(), CAPACITY, 0, None)
        }),
    ));
    out.push((
        "bip85",
        Box::new(move |b: &mut Band<'_>| kassigner_fw::ui::bip85::draw(b, scale, kit, 12, 42)),
    ));
    out.push((
        "multisig_menu",
        Box::new(move |b: &mut Band<'_>| {
            menu::draw_dimmed(b, scale, kit, &menu::MULTISIG, 0, None, 0b110)
        }),
    ));
    out.push((
        "multisig_menu_held",
        Box::new(move |b: &mut Band<'_>| menu::draw(b, scale, kit, &menu::MULTISIG, 0, None)),
    ));
    for (name, m, n) in [
        ("create_multisig", 2, 3),
        ("create_multisig_one", 1, 1),
        ("create_multisig_five", 5, 5),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::multisig::draw_create(b, scale, kit, m, n)
            }),
        ));
    }
    for (name, key, of) in [
        ("add_key_first", 1, 3),
        ("add_key_third", 3, 3),
        ("add_key_fifth", 5, 5),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::multisig::draw_add_key(b, scale, kit, (key, of), None)
            }),
        ));
    }
    for (name, page) in [("select_seed", 0), ("select_seed_more", 1)] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let title = kassigner_fw::ui::multisig::select_seed(2, 3);
                seeds::draw_pick(b, scale, kit, title, &SEEDS, page, None)
            }),
        ));
    }
    for (name, address, at, cosigner) in [
        (
            "group_address",
            "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9",
            (false, 0),
            2,
        ),
        (
            "group_address_change",
            "kaspa:pqr82f7wkmsa35682a7crkc6ay8zxzx5ct4m56k7pa7arnktwy4m5f6k30s8s",
            (true, 5),
            0,
        ),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::address::draw_group(b, scale, kit, address, at, (2, 3, cosigner))
            }),
        ));
    }
    out.push((
        "group_deriving",
        Box::new(move |b: &mut Band<'_>| {
            loading::draw(b, scale, kit, loading::GROUP_ADDRESS, 4, 9)
        }),
    ));
    // DESCRIPTOR QR: a 2-of-3's codes, and a 1-of-1's.
    for (name, hints) in [
        ("descriptor_qr", ("Text, 2 QR", "Text, 8 QR")),
        ("descriptor_qr_one", ("Text, 1 QR", "Text, 3 QR")),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::kpub::format(
                    b,
                    scale,
                    kit,
                    kassigner_fw::ui::kpub::DESCRIPTOR_TITLE,
                    hints,
                )
            }),
        ));
    }
    // DESCRIPTOR: the 2-of-3 of zoo 12, abandon 24 and abandon 12 in
    // cosigner order, abandon 12 in use; the Go wallet's five, none of them
    // in use; a 1-of-1, its key in use.
    const DESCRIPTOR_23: [&str; 3] = [
        "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU",
        "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW",
        "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14",
    ];
    for (name, (m, n), keys, own) in [
        ("descriptor", (2, 3), &DESCRIPTOR_23[..], Some(2)),
        (
            "descriptor_five",
            (2, 5),
            &kassigner_kaspa::kat::MULTISIG_45.kpubs[..],
            None,
        ),
        ("descriptor_one", (1, 1), &DESCRIPTOR_23[2..], Some(0)),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::multisig::draw_descriptor(b, scale, kit, (m, n), keys, own, None)
            }),
        ));
    }
    // LOAD MULTISIG?: no group held, the seed in use cosigner 2; replacing
    // a 3-of-5, the seed not in it; the group already held; no seed. Then
    // Import from SD's Multisig Address, read from MS0001.TXT.
    for (name, (m, n), seed, held) in [
        (
            "load_group",
            (2, 3),
            kassigner_fw::ui::multisig::SeedIn::Cosigner(2),
            kassigner_fw::ui::multisig::Held::Nothing,
        ),
        (
            "load_group_replace",
            (2, 3),
            kassigner_fw::ui::multisig::SeedIn::Not,
            kassigner_fw::ui::multisig::Held::Other(3, 5),
        ),
        (
            "load_group_same",
            (5, 5),
            kassigner_fw::ui::multisig::SeedIn::Cosigner(4),
            kassigner_fw::ui::multisig::Held::Same,
        ),
        (
            "load_group_no_seed",
            (1, 1),
            kassigner_fw::ui::multisig::SeedIn::NoSeed,
            kassigner_fw::ui::multisig::Held::Other(2, 3),
        ),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::multisig::draw_load(b, scale, kit, (m, n), (seed, held), None)
            }),
        ));
    }
    out.push((
        "file_address",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::address::draw_file(
                b,
                scale,
                kit,
                kassigner_fw::ui::address::FILE_ADDRESS_TITLE,
                "kaspa:prvfzy9wjlewtyk9qeczkd0ehyxfcycxz9c99yr2x3nu7uk6zw872c06xr7d9",
                "MS0001.TXT",
            )
        }),
    ));
    // SAVINGS CARD: its pages, a key's as the seed in use holds it, with no
    // recovery wallet, and read from a file; opening at 14:30 UTC, the card
    // with none at midnight.
    for (name, recovery, seen, file, page) in [
        (
            "savings_card",
            Some(CARD_RECOVERY),
            (Seen::At(0), Seen::NotFound),
            false,
            0,
        ),
        (
            "savings_owner",
            Some(CARD_RECOVERY),
            (Seen::At(0), Seen::NotFound),
            false,
            1,
        ),
        (
            "savings_recovery_not_found",
            Some(CARD_RECOVERY),
            (Seen::At(0), Seen::NotFound),
            false,
            2,
        ),
        (
            "savings_owner_not_found",
            Some(CARD_RECOVERY),
            (Seen::NotFound, Seen::At(3)),
            false,
            1,
        ),
        (
            "savings_recovery",
            Some(CARD_RECOVERY),
            (Seen::NotFound, Seen::At(3)),
            false,
            2,
        ),
        (
            "savings_owner_search",
            Some(CARD_RECOVERY),
            (Seen::Missed(20), Seen::At(3)),
            false,
            1,
        ),
        (
            "savings_owner_searching",
            Some(CARD_RECOVERY),
            (Seen::Searching(137), Seen::At(3)),
            false,
            1,
        ),
        (
            "savings_owner_found_deep",
            Some(CARD_RECOVERY),
            (Seen::At(150), Seen::At(3)),
            false,
            1,
        ),
        (
            "savings_recovery_search",
            Some(CARD_RECOVERY),
            (Seen::At(0), Seen::Missed(220)),
            false,
            2,
        ),
        (
            "savings_owner_no_seed",
            Some(CARD_RECOVERY),
            (Seen::NoSeed, Seen::NoSeed),
            false,
            1,
        ),
        (
            "savings_none_card",
            None,
            (Seen::At(0), Seen::NoSeed),
            false,
            0,
        ),
        (
            "savings_none_owner",
            None,
            (Seen::At(0), Seen::NoSeed),
            false,
            1,
        ),
        (
            "savings_file",
            Some(CARD_RECOVERY),
            (Seen::At(0), Seen::NotFound),
            true,
            0,
        ),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                let unlock = if name == "savings_none_card" {
                    1_798_761_600_000
                } else {
                    1_798_813_800_000
                };
                let shown = savings::Shown {
                    address: CARD,
                    unlock,
                    owner: CARD_OWNER,
                    recovery,
                    owner_seen: seen.0,
                    recovery_seen: seen.1,
                    file,
                };
                savings::draw(b, scale, kit, &shown, page, None)
            }),
        ));
    }
    // SAVINGS CARD QR: a line with a recovery wallet, and one with none.
    for (name, hints) in [
        ("savings_qr", ("Text, 2 QR", "Text, 5 QR")),
        ("savings_qr_one", ("Text, 1 QR", "Text, 4 QR")),
    ] {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                kassigner_fw::ui::kpub::format(
                    b,
                    scale,
                    kit,
                    kassigner_fw::ui::kpub::SAVINGS_TITLE,
                    hints,
                )
            }),
        ));
    }
    out.push((
        "savings_list",
        Box::new(move |b: &mut Band<'_>| {
            let names: Vec<[u8; 11]> = (1..=3)
                .map(|i| kassigner_fw::card::name83(format!("CV000{i}").as_bytes(), b"TXT"))
                .collect();
            backup::list(b, scale, kit, "SELECT CARD", (0, &names), 0)
        }),
    ));
    out.push((
        "savings_saved",
        Box::new(move |b: &mut Band<'_>| {
            let said = sd_card::Said {
                saved: "!! Card Saved !!",
                ..SAID
            };
            sd_card::done(b, scale, kit, (Job::Write, Outcome::Written), said)
        }),
    ));
    out.push((
        "cosigner_key",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::cosigner_key(), None)
        }),
    ));
    out.push((
        "show_word",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::words::show(b, scale, kit, 2, 12, "abandon")
        }),
    ));
    out.push((
        "word_count",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::words::count(b, scale, kit, "IMPORT WORDS")
        }),
    ));
    out.push((
        "last_word",
        Box::new(move |b: &mut Band<'_>| {
            kassigner_fw::ui::words::last(b, scale, kit, 12, "actress", (5, 128))
        }),
    ));
    out.push((
        "keyboard_filename",
        Box::new(move |b: &mut Band<'_>| {
            let line = keyboard::Line {
                text: "SD0002",
                cursor: 6,
                note: Some(keyboard::Note::Count { used: 6, of: 8 }),
                mode: keyboard::Mode::Name { full: false },
                word: None,
            };
            keyboard::draw(b, scale, kit, "FILENAME", 2, line)
        }),
    ));
    out.push((
        "restore_list_one",
        Box::new(move |b: &mut Band<'_>| {
            let names = [kassigner_fw::card::name83(b"SD0001", b"KAS")];
            backup::list(b, scale, kit, "SELECT BACKUP", (0, &names), 0)
        }),
    ));
    // A full card: the 64 the list holds, 16 pages, and more besides.
    out.push((
        "restore_list_full",
        Box::new(move |b: &mut Band<'_>| {
            let names = full_list();
            backup::list(b, scale, kit, "SELECT BACKUP", (2, &names), 37)
        }),
    ));
    out.push((
        "import_export",
        Box::new(move |b: &mut Band<'_>| backup::import_export(b, scale, kit)),
    ));
    out.push((
        "stego_carriers",
        Box::new(move |b: &mut Band<'_>| kassigner_fw::ui::stego::draw(b, scale, kit)),
    ));
    out.push((
        "stego_photos",
        Box::new(move |b: &mut Band<'_>| {
            let names = [
                kassigner_fw::card::name83(b"ROCKY", b"JPG"),
                kassigner_fw::card::name83(b"IMG_2041", b"JPG"),
            ];
            let long = long_slots(&["ROCKY.JPG", "IMG_20241014_153022.jpg"]);
            backup::list_with(
                b,
                scale,
                kit,
                "SELECT PHOTO",
                (0, &names, &long),
                0,
                (kassigner_fw::ui::gen::Icon::Page, false),
            )
        }),
    ));
    out.push((
        "stego_preview",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::preview("Rocky at the beach, summer 2024");
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_hint_ask",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &kassigner_fw::ui::stego::add_hint(), None)
        }),
    ));
    out.push((
        "stego_hints",
        Box::new(move |b: &mut Band<'_>| kassigner_fw::ui::stego::draw_hints(b, scale, kit)),
    ));
    out.push((
        "stego_embedding",
        Box::new(move |b: &mut Band<'_>| loading::draw(b, scale, kit, loading::EMBEDDING, 50, 100)),
    ));
    out.push((
        "stego_done",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::done(
                "ROCKY.JPG",
                kassigner_protocol::stego::Carrier::Picture,
            );
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_confirm",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::confirm(
                "ROCKY.JPG",
                kassigner_protocol::stego::Carrier::Both,
                "Rocky at the beach, summer 2024",
                true,
            );
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_preview_long",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::preview(
                "Me at the age of twenty with my family on the hill by the lake",
            );
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_reading",
        Box::new(move |b: &mut Band<'_>| loading::draw(b, scale, kit, loading::READING, 50, 100)),
    ));
    out.push((
        "stego_found",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::found(
                12,
                kassigner_protocol::stego::Carrier::Picture,
                true,
            );
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_overwrite",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::overwrite("ROCKY.JPG");
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "stego_hint_shown",
        Box::new(move |b: &mut Band<'_>| {
            let d = kassigner_fw::ui::stego::hint_shown("Name of my loved one?");
            dialog::draw(b, scale, kit, &d, None)
        }),
    ));
    out.push((
        "backup_warning",
        Box::new(move |b: &mut Band<'_>| backup::warning(b, scale, kit)),
    ));
    out.push((
        "backup_sealing",
        Box::new(move |b: &mut Band<'_>| {
            loading::draw(b, scale, kit, loading::ENCRYPTING, 40, 100)
        }),
    ));
    out.push((
        "backup_sealing_wait",
        Box::new(move |b: &mut Band<'_>| {
            loading::draw(b, scale, kit, loading::ENCRYPTING_WAIT, 50, 100)
        }),
    ));
    out.push((
        "restore_opening_wait",
        Box::new(move |b: &mut Band<'_>| {
            loading::draw(b, scale, kit, loading::DECRYPTING_WAIT, 50, 100)
        }),
    ));
    out.push((
        "backup_overwrite",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(b, scale, kit, &dialog::overwrite("SD0003.KAS"), None)
        }),
    ));
    out.push((
        "restore_delete",
        Box::new(move |b: &mut Band<'_>| {
            dialog::draw(
                b,
                scale,
                kit,
                &dialog::delete_backup("SD0003.KAS", Some(40)),
                None,
            )
        }),
    ));
    let menus: [(&'static str, &'static Menu); 12] = [
        ("tools", &menu::TOOLS),
        ("seed_tools", &menu::SEED_TOOLS),
        ("import", &menu::IMPORT),
        ("import_sd", &menu::IMPORT_SD),
        ("export", &menu::EXPORT),
        ("seed_backup", &menu::SEED_BACKUP),
        ("qr_export", &menu::QR_EXPORT),
        ("watch_only", &menu::WATCH_ONLY),
        ("signing_keys", &menu::SIGNING_KEYS),
        ("sign_message", &menu::SIGN_MESSAGE),
        ("settings", &menu::SETTINGS),
        ("settings_no_audio", &menu::SETTINGS_NO_AUDIO),
    ];
    for (name, m) in menus {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| {
                menu::draw(b, scale, kit, m, 0, Some(menu::Target::Item(1)))
            }),
        ));
    }
    for (name, words) in REFUSALS {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| refusal::draw(b, scale, kit, words)),
        ));
    }
    let halts = [
        "panic_self_test",
        "panic_camera",
        "panic_decoder",
        "panic_generator",
    ];
    for (name, reason) in halts.into_iter().zip(refusal::HALTS) {
        out.push((
            name,
            Box::new(move |b: &mut Band<'_>| refusal::panic(b, scale, kit, reason)),
        ));
    }
    out
}

const SIZES: [Size; 2] = [Size::new(320, 240), Size::new(480, 320)];

/// Whether two zones share a pixel.
fn overlap(a: &Zone, b: &Zone) -> bool {
    a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height
}

/// Every zone fits the panel, none overlaps another, and a touch in the
/// middle of each finds its target. `nested` pairs may overlap: a button
/// inside its row.
fn check<T: Copy + PartialEq + core::fmt::Debug>(
    size: Size,
    zones: &[(T, Zone)],
    find: impl Fn(u16, u16) -> Option<T>,
    nested: impl Fn(T, T) -> bool,
) {
    for (i, (t, z)) in zones.iter().enumerate() {
        assert!(
            Rect::new(z.x, z.y, z.width, z.height).fits(size),
            "{t:?} at {size:?}"
        );
        for (u, w) in &zones[i + 1..] {
            let allowed = nested(*t, *u) || nested(*u, *t);
            assert!(allowed || !overlap(z, w), "{t:?} and {u:?} at {size:?}");
        }
        let (cx, cy) = (z.x + z.width / 2, z.y + z.height / 2);
        assert_eq!(find(cx, cy), Some(*t), "the middle of {t:?} at {size:?}");
    }
}

/// The 64 names a full SELECT BACKUP holds, 16 pages.
fn full_list() -> Vec<[u8; 11]> {
    (1..=64)
        .map(|i| card::name83(format!("SD{i:04}").as_bytes(), b"KAS"))
        .collect()
}

/// Long names as the photo list keeps them, a [`card::LONG_SLOT`] each.
fn long_slots(names: &[&str]) -> Vec<u8> {
    let slot = kassigner_fw::card::LONG_SLOT;
    let mut out = vec![0u8; names.len() * slot];
    for (i, name) in names.iter().enumerate() {
        out[i * slot] = name.len() as u8;
        out[i * slot + 1..i * slot + 1 + name.len()].copy_from_slice(name.as_bytes());
    }
    out
}
