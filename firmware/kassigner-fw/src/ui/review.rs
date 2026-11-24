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

//! The review: a transaction's pages before it is signed, and the question
//! that signs it, in this order.
//!
//! - TX REVIEW: the totals a row each, decimal points aligned; the counts;
//!   a group spend's M of N in orange.
//! - SAVINGS CARD, for each Time-Locked Savings card spent: what this unit
//!   does, when the card opens (said as LOCK TIME says a time, so the two
//!   compare), its address, and the ends of its other key's address.
//! - OUTPUT n: the amount, orange unless the output is the seed's own; the
//!   address, its first and last five characters in teal, the ones a person
//!   compares with the wallet's. A script's address says so over it; the
//!   seed's own change (or the held group's) and receive addresses get a
//!   teal title and their place, so a place no wallet would use shows.
//! - LOCK TIME, when there is one: "Valid only after" (a block takes the
//!   transaction once its DAA score or time is past the lock time, not at
//!   it), or "Ignored" when every input is final.
//! - CONFIRM SEND?, past the last page: the totals again, CANCEL red (here
//!   alone among the dialogs, as this is where funds move) and CONFIRM
//!   green, whose tap signs.
//!
//! Only the side arrows turn a page. Covenant bindings, a payload and a
//! relative lock have no page yet: such a request is refused as it arrives
//! ([`crate::flow`]).

use super::band::Band;
use super::camera::Part;
use super::chrome::{
    buttons, card, corner, header, header_in, lit_edge, Nav, CORNER_DEPTH, RIGHT_COLUMN,
    SIDE_COLUMN,
};
use super::color::{
    ACCENT, GREEN_BUTTON, ORANGE, RED, RED_BUTTON, TEAL, TEAL_DARK, TEXT, TEXT_DIM, WARN,
};
use super::dialog;
use super::font::Font;
use super::scale::{bounds, Kit, Scale};
use crate::touch::Zone;
use kassigner_kaspa::constants::{classify_lock_time, LockTime, SOMPI_PER_KASPA};

/// The three totals, in sompi: every output, every input, and the
/// difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    /// What the outputs receive, change included.
    pub out: u64,
    /// What the inputs spend.
    pub spent: u64,
    pub fee: u64,
}

/// What TX REVIEW and CONFIRM SEND? say under the totals: the inputs and
/// outputs counted, and a multisig spend's M and N, or, `unchecked`, that no
/// group is held to check the spend against ([`unchecked_line`]). Both
/// screens say the same: the warning is on the last one before the
/// signature too, and stands whether the inputs share one M of N or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counted {
    pub inputs: usize,
    pub outputs: usize,
    pub group: Option<(usize, usize)>,
    pub unchecked: bool,
}

/// Whether an output is the seed's own, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Anyone's: a payment.
    No,
    /// The seed's own, or the held group's, at this index on the change
    /// chain.
    At(u32),
    /// A raw key's one address, which is its change too, at no index.
    Key,
    /// The seed's own receive address at this index on its single-key
    /// account: a payment to itself.
    Yours(u32),
}

/// What a review page shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown<'a> {
    /// TX REVIEW; `group`, a multisig spend's M and N, none when its inputs
    /// share none; `unchecked` when no group is held to check its inputs and
    /// change against, which the line under the counts then says
    /// ([`unchecked_line`]), with the M of N or without.
    Summary {
        totals: Totals,
        inputs: usize,
        outputs: usize,
        group: Option<(usize, usize)>,
        unchecked: bool,
    },
    /// OUTPUT n, `number` counting from 1; `value` in sompi.
    Output {
        number: usize,
        value: u64,
        address: &'a str,
        script: bool,
        change: Change,
    },
    /// LOCK TIME: the transaction's lock time, read by
    /// [`classify_lock_time`]; `ignored` when every input's sequence is
    /// final, which consensus takes as no lock at all.
    LockTime { value: u64, ignored: bool },
    /// SAVINGS CARD: a Time-Locked Savings card the transaction spends.
    Card {
        /// The card's own address, `kaspa:p…`.
        address: &'a str,
        /// When it opens, a whole minute UTC, in milliseconds.
        unlock: u64,
        /// How many of the inputs are the card's UTXOs.
        utxos: usize,
        /// Whether this unit signs as the recovery wallet, not the owner.
        recover: bool,
        /// The card's other key's address: the recovery wallet's when this
        /// unit claims, the owner's when it recovers; `None` with no
        /// recovery wallet.
        other: Option<&'a str>,
    },
    /// COVENANT, or NEW COVENANT: one covenant the transaction touches, its
    /// id under what becomes of it ([`covenant_lines`]).
    Covenant {
        /// The covenant's id, drawn as its 64 hex characters.
        id: [u8; 32],
        /// How many inputs spend UTXOs bound to it; none for a new one.
        spent: usize,
        /// The outputs bound to it, bit `i` for output `i`.
        outputs: u32,
        /// For a covenant that starts here, its authorizing input, counted
        /// from 0.
        from: Option<usize>,
    },
}

/// What a touch on the review can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Back and Home: both cancel, as on every dialog.
    Nav(Nav),
    /// The left arrow: the page before; on CONFIRM SEND?, the last page.
    Previous,
    /// The right arrow: the page after, or past the last one CONFIRM SEND?.
    Next,
    /// CONFIRM SEND?'s CANCEL.
    Cancel,
    /// CONFIRM SEND?'s CONFIRM: the tap that signs.
    Confirm,
}

/// Where the arrows stop counting, in design rows: over CONFIRM SEND?'s
/// answers, on the pages too, so a second tap where the last page was
/// turned cannot land on CONFIRM.
const SIDE_FOOT: i32 = 180;

/// Where a target counts on a page, or on CONFIRM SEND? when `confirm`. The
/// arrows count in the side columns, under Back and Home.
pub const fn zone(scale: Scale, confirm: bool, target: Target) -> Option<Zone> {
    let side = SIDE_FOOT - CORNER_DEPTH;
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Previous => Some(scale.zone(0, CORNER_DEPTH, SIDE_COLUMN, side)),
        Target::Next if confirm => None,
        Target::Next => Some(scale.zone(RIGHT_COLUMN, CORNER_DEPTH, SIDE_COLUMN, side)),
        Target::Cancel if confirm => dialog::zone(scale, dialog::Target::Cancel),
        Target::Confirm if confirm => dialog::zone(scale, dialog::Target::Accept),
        Target::Cancel | Target::Confirm => None,
    }
}

/// What is under a point, on a page or on CONFIRM SEND?.
pub fn target(scale: Scale, confirm: bool, x: u16, y: u16) -> Option<Target> {
    [
        Target::Nav(Nav::Back),
        Target::Nav(Nav::Home),
        Target::Previous,
        Target::Next,
        Target::Cancel,
        Target::Confirm,
    ]
    .into_iter()
    .find(|&t| zone(scale, confirm, t).is_some_and(|z| z.contains(x, y)))
}

/// The room between an amount's characters past the font's own, in design
/// pixels: digits a little apart, to be read one by one.
pub const DIGIT_GAP: i32 = 1;

/// How wide an amount's text is drawn, in `font`, its characters
/// [`DIGIT_GAP`] apart.
pub fn amount_width(scale: Scale, font: &Font, number: &str) -> i32 {
    font.width_spaced(number, scale.len(DIGIT_GAP))
}

/// The longest amount: `u64::MAX` sompi is 184,467,440,737.09551615.
pub const AMOUNT_MAX: usize = 24;

/// `sompi` in KAS, eight decimals, the whole part grouped in thousands with
/// commas: `1,234.50000000`.
pub fn kas(sompi: u64, out: &mut [u8; AMOUNT_MAX]) -> &str {
    let (whole, frac) = (sompi / 100_000_000, sompi % 100_000_000);
    let mut digits = [0u8; 20];
    let (mut v, mut start) = (whole, digits.len());
    loop {
        start -= 1;
        digits[start] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let whole = &digits[start..];
    let mut n = 0;
    for (i, d) in whole.iter().enumerate() {
        if i > 0 && (whole.len() - i) % 3 == 0 {
            out[n] = b',';
            n += 1;
        }
        out[n] = *d;
        n += 1;
    }
    out[n] = b'.';
    n += 1;
    let mut f = frac;
    for k in (0..8).rev() {
        out[n + k] = b'0' + (f % 10) as u8;
        f /= 10;
    }
    n += 8;
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// A review page: `shown`, page `index` of `pages`.
pub fn draw(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    shown: &Shown<'_>,
    (index, pages): (usize, usize),
) {
    match *shown {
        Shown::Summary {
            totals,
            inputs,
            outputs,
            group,
            unchecked,
        } => {
            header(band, scale, kit, "TX REVIEW");
            rows(band, scale, kit, &totals, (76, 0));
            let counted = Counted {
                inputs,
                outputs,
                group,
                unchecked,
            };
            notes(band, scale, kit, &counted, (170, GROUP_BASE));
        }
        Shown::Output {
            number,
            value,
            address,
            script,
            change,
        } => {
            let mut title = [0u8; 24];
            let mut n = Part::Text("OUTPUT ").write(&mut title, 0);
            n = Part::Number(number).write(&mut title, n);
            match change {
                Change::No => {}
                Change::Yours(_) => n = Part::Text(" (YOURS)").write(&mut title, n),
                Change::At(_) | Change::Key => n = Part::Text(" (CHANGE)").write(&mut title, n),
            }
            let title = core::str::from_utf8(&title[..n]).unwrap_or("");
            let ink = if change == Change::No {
                header(band, scale, kit, title);
                ORANGE
            } else {
                header_in(band, scale, kit, title, TEAL, TEAL);
                TEXT_DIM
            };
            amount(band, scale, kit, (76, value), ink);
            // The line over the address: a script's says so, the seed's own
            // say where they are. An index can run to ten digits, too many
            // for the title.
            let mut line = [0u8; 32];
            let n = match (change, script) {
                (Change::At(index), script) => {
                    let lead = if script { "P2SH change #" } else { "Change #" };
                    let n = Part::Text(lead).write(&mut line, 0);
                    Part::Number(usize::try_from(index).unwrap_or(usize::MAX)).write(&mut line, n)
                }
                (Change::Yours(index), _) => {
                    let n = Part::Text("Receive #").write(&mut line, 0);
                    Part::Number(usize::try_from(index).unwrap_or(usize::MAX)).write(&mut line, n)
                }
                (_, true) => Part::Text("To P2SH address").write(&mut line, 0),
                (_, false) => 0,
            };
            let top = if n > 0 {
                let line = core::str::from_utf8(&line[..n]).unwrap_or("");
                band.text_centered(kit.body, scale.x(160), scale.y(100), ACCENT, line);
                132
            } else {
                120
            };
            address_lines(band, scale, kit, address, (top, ADDRESS_STEP));
        }
        Shown::LockTime { value, ignored } => {
            header(band, scale, kit, "LOCK TIME");
            let (lead, ink, note, note_ink) = if ignored {
                ("Set to", TEXT_DIM, "Ignored: every input is final", ACCENT)
            } else {
                (
                    "Valid only after",
                    ORANGE,
                    "Until then no block can take it",
                    TEXT_DIM,
                )
            };
            band.text_centered(kit.body, scale.x(160), scale.y(96), TEXT_DIM, lead);
            let mut buf = [0u8; LOCK_TIME_MAX];
            let text = lock_time(value, &mut buf);
            band.text_centered(kit.title, scale.x(160), scale.y(126), ink, text);
            band.text_centered(kit.body, scale.x(160), scale.y(164), note_ink, note);
        }
        Shown::Card {
            address,
            unlock,
            utxos,
            recover,
            other,
        } => {
            header(band, scale, kit, "SAVINGS CARD");
            let mut what = [0u8; 40];
            let mut n = Part::Text(if recover { "Recover " } else { "Claim " }).write(&mut what, 0);
            n = Part::Number(utxos).write(&mut what, n);
            n = Part::Text(if utxos == 1 {
                " UTXO, as "
            } else {
                " UTXOs, as "
            })
            .write(&mut what, n);
            n = Part::Text(if recover { "recovery" } else { "owner" }).write(&mut what, n);
            let what = core::str::from_utf8(&what[..n]).unwrap_or("");
            band.text_centered(kit.body, scale.x(160), scale.y(78), ACCENT, what);
            let mut buf = [0u8; LOCK_TIME_MAX];
            let when = lock_time(unlock, &mut buf);
            let mut line = [0u8; 56];
            let mut n = Part::Text("Opens ").write(&mut line, 0);
            n = Part::Text(when).write(&mut line, n);
            let line = core::str::from_utf8(&line[..n]).unwrap_or("");
            band.text_centered(kit.body, scale.x(160), scale.y(100), ORANGE, line);
            address_lines(band, scale, kit, address, (128, ADDRESS_STEP));
            let mut tail = [0u8; 48];
            let lead = if recover { "Owner: " } else { "Recovery: " };
            let mut n = Part::Text(lead).write(&mut tail, 0);
            match other {
                None => n = Part::Text("none").write(&mut tail, n),
                Some(a) => {
                    // Its ends only, the characters a person compares.
                    let start = a.find(':').map_or(0, |c| c + 1);
                    let head = a.get(..start + LIT_ENDS).unwrap_or(a);
                    let end = a.get(a.len().saturating_sub(LIT_ENDS)..).unwrap_or("");
                    n = Part::Text(head).write(&mut tail, n);
                    n = Part::Text("...").write(&mut tail, n);
                    n = Part::Text(end).write(&mut tail, n);
                }
            }
            let tail = core::str::from_utf8(&tail[..n]).unwrap_or("");
            band.text_centered(kit.body, scale.x(160), scale.y(206), TEXT_DIM, tail);
        }
        Shown::Covenant {
            id,
            spent,
            outputs,
            from,
        } => {
            header(
                band,
                scale,
                kit,
                if from.is_some() {
                    "NEW COVENANT"
                } else {
                    "COVENANT"
                },
            );
            let (mut first, mut second) = ([0u8; COVENANT_LINE_MAX], [0u8; COVENANT_LINE_MAX]);
            let lines = covenant_lines((spent, outputs, from), &mut first, &mut second);
            band.text_centered(kit.body, scale.x(160), scale.y(78), lines[0].1, lines[0].0);
            band.text_centered(kit.body, scale.x(160), scale.y(100), lines[1].1, lines[1].0);
            // The id as an address is drawn, its ends teal: the characters
            // a person compares.
            let mut hex = [0u8; 64];
            for (pair, byte) in hex.chunks_exact_mut(2).zip(id) {
                pair[0] = HEX[usize::from(byte >> 4)];
                pair[1] = HEX[usize::from(byte & 0x0F)];
            }
            let hex = core::str::from_utf8(&hex).unwrap_or("");
            address_lines(band, scale, kit, hex, (136, ADDRESS_STEP));
        }
    }
    buttons(band, scale);
    let mut foot = [0u8; 16];
    let mut n = Part::Text("Page ").write(&mut foot, 0);
    n = Part::Number(index + 1).write(&mut foot, n);
    n = Part::Text("/").write(&mut foot, n);
    n = Part::Number(pages).write(&mut foot, n);
    let foot = core::str::from_utf8(&foot[..n]).unwrap_or("");
    band.text_centered(kit.body, scale.x(160), scale.y(229), TEXT_DIM, foot);
    // The right arrow is always live: on the last page it leads to CONFIRM
    // SEND?.
    sides(band, scale, (index > 0, true), SIDES_MID);
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The longest a covenant page's line runs: `Continues in outputs` and the
/// eight outputs a unit takes.
pub const COVENANT_LINE_MAX: usize = 48;

/// The two lines over a covenant's id, each with its colour, written into
/// `first` and `second`. `outputs` has bit `i` set for output `i`, said
/// counting from 1 as the OUTPUT pages' titles do.
///
/// A covenant some input's UTXO is bound to (`from` is `None`):
/// `Spends 2 UTXOs`, then `Continues in outputs 1, 2`, or in orange
/// `No output continues it` where it ends here. One that starts here: in
/// orange `Starts in output 2`, then `From input 1`, its authorizing input.
pub fn covenant_lines<'a>(
    (spent, outputs, from): (usize, u32, Option<usize>),
    first: &'a mut [u8; COVENANT_LINE_MAX],
    second: &'a mut [u8; COVENANT_LINE_MAX],
) -> [(&'a str, u16); 2] {
    // `lead`, then `output 2` or `outputs 1, 2`.
    fn listed(lead: &str, outputs: u32, out: &mut [u8; COVENANT_LINE_MAX]) -> usize {
        let mut n = Part::Text(lead).write(out, 0);
        n = Part::Text(if outputs.count_ones() == 1 {
            "output "
        } else {
            "outputs "
        })
        .write(out, n);
        let mut any = false;
        for i in (0..32usize).filter(|i| outputs >> i & 1 == 1) {
            if any {
                n = Part::Text(", ").write(out, n);
            }
            n = Part::Number(i + 1).write(out, n);
            any = true;
        }
        n
    }
    let said = |line: &'a [u8; COVENANT_LINE_MAX], n: usize| {
        core::str::from_utf8(&line[..n]).unwrap_or("")
    };
    match from {
        Some(input) => {
            let a = listed("Starts in ", outputs, first);
            let mut b = Part::Text("From input ").write(second, 0);
            b = Part::Number(input + 1).write(second, b);
            [(said(first, a), ORANGE), (said(second, b), TEXT_DIM)]
        }
        None => {
            let mut a = Part::Text("Spends ").write(first, 0);
            a = Part::Number(spent).write(first, a);
            a = Part::Text(if spent == 1 { " UTXO" } else { " UTXOs" }).write(first, a);
            if outputs == 0 {
                let b = Part::Text("No output continues it").write(second, 0);
                [(said(first, a), ACCENT), (said(second, b), ORANGE)]
            } else {
                let b = listed("Continues in ", outputs, second);
                [(said(first, a), ACCENT), (said(second, b), ACCENT)]
            }
        }
    }
}

/// CONFIRM SEND?: TX REVIEW's totals (moved right to balance the buttons'
/// weight on the left), counts and M of N; CANCEL and CONFIRM.
pub fn draw_confirm(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    totals: &Totals,
    counted: &Counted,
) {
    header(band, scale, kit, "CONFIRM SEND?");
    buttons(band, scale);
    rows(band, scale, kit, totals, (CONFIRM_TOP, 14));
    notes(band, scale, kit, counted, (CONFIRM_COUNTS, CONFIRM_GROUP));
    sides(band, scale, (true, false), SIDES_MID);
    let r = scale.len(8);
    let thick = lit_edge(scale);
    for (at, face, said) in [
        (dialog::Target::Cancel, RED_BUTTON, "CANCEL"),
        (dialog::Target::Accept, GREEN_BUTTON, "CONFIRM"),
    ] {
        if let Some(z) = dialog::zone(scale, at) {
            card(band, z, r, face, face, thick);
            let (x, y, w, _) = bounds(z);
            band.text_centered(kit.title, x + w / 2, y + scale.len(27), TEXT, said);
        }
    }
}

/// TX REVIEW's M-of-N line's baseline, in design rows.
const GROUP_BASE: i32 = 196;

/// What TX REVIEW and CONFIRM SEND? say of a multisig spend when no group
/// is held: nothing the unit holds says whose the inputs are, so no output
/// is marked CHANGE.
pub const UNCHECKED: &str = "No Descriptor: change unchecked";

/// Room for [`unchecked_line`]: two numbers of up to three digits, " of ",
/// ". " and [`UNCHECKED`].
const UNCHECKED_MAX: usize = 3 + 4 + 3 + 2 + UNCHECKED.len();

/// The line for a multisig spend with no group held: `M of N. ` where the
/// inputs share one, then [`UNCHECKED`]. Inputs of more than one shape (a
/// single key's beside a multisig's, or two thresholds) share no M of N,
/// and the warning stands without it: it is what must not go unsaid.
pub fn unchecked_line(shape: Option<(usize, usize)>, out: &mut [u8]) -> &str {
    let mut k = 0;
    if let Some((m, n)) = shape {
        k = Part::Number(m).write(out, k);
        k = Part::Text(" of ").write(out, k);
        k = Part::Number(n).write(out, k);
        k = Part::Text(". ").write(out, k);
    }
    k = Part::Text(UNCHECKED).write(out, k);
    core::str::from_utf8(&out[..k]).unwrap_or("")
}

/// CONFIRM SEND?'s first row, counts line and M-of-N line, in design rows:
/// all above the buttons, which start at 185.
const CONFIRM_TOP: i32 = 72;
const CONFIRM_COUNTS: i32 = 155;
const CONFIRM_GROUP: i32 = 176;

/// Under the totals: the counts in gray and, at design rows
/// `(counts, group)`, a group's M of N in orange, or in the warning's colour
/// that no group is held ([`unchecked_line`]). Never the orange M of N for
/// a spend no group was checked against: that is a checked group's look.
fn notes(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    counted: &Counted,
    (counts_y, group_y): (i32, i32),
) {
    let mut line = [0u8; 48];
    let said = counts(counted.inputs, counted.outputs, &mut line);
    band.text_centered(kit.body, scale.x(160), scale.y(counts_y), TEXT_DIM, said);
    if counted.unchecked {
        let mut line = [0u8; UNCHECKED_MAX];
        let said = unchecked_line(counted.group, &mut line);
        band.text_centered(kit.body, scale.x(160), scale.y(group_y), WARN, said);
    } else if let Some((m, n)) = counted.group {
        let mut note = [0u8; 24];
        let mut k = Part::Number(m).write(&mut note, 0);
        k = Part::Text("-of-").write(&mut note, k);
        k = Part::Number(n).write(&mut note, k);
        k = Part::Text(" multisig").write(&mut note, k);
        let note = core::str::from_utf8(&note[..k]).unwrap_or("");
        band.text_centered(kit.body, scale.x(160), scale.y(group_y), ORANGE, note);
    }
}

/// The totals' labels, in their rows' order.
const LABELS: [&str; 3] = ["Out", "In", "Fee"];

/// Where the totals' rows put their parts, in panel pixels: the labels'
/// left edge, the numbers' right edge, KAS's left edge; and the numbers'
/// font.
#[derive(Clone, Copy, Debug)]
pub struct Columns {
    pub label: i32,
    pub right: i32,
    pub kas: i32,
    pub number: &'static Font,
    /// The room between the numbers' characters, in panel pixels:
    /// [`DIGIT_GAP`]'s, or none where nothing else fits.
    pub spacing: i32,
}

/// The least room, in design pixels, between a label and its number, and
/// between the number and KAS in the full-width rows.
pub const GAP: i32 = 8;

/// The rows' columns for `totals`, moved `dx` design pixels right: the
/// usual places if every number fits beside its label, [`DIGIT_GAP`]
/// spaced; else the width between the arrows, then the body font, then no
/// spacing. Kaspa's whole supply, and `u64::MAX` sompi, fit either panel.
pub fn columns(scale: Scale, kit: &Kit, totals: &Totals, dx: i32) -> Columns {
    let label_w = LABELS.iter().map(|l| kit.body.width(l)).max().unwrap_or(0);
    let gap = scale.len(GAP);
    let fits = |c: &Columns| {
        let widest = [totals.out, totals.spent, totals.fee]
            .iter()
            .map(|&v| {
                let mut buf = [0u8; AMOUNT_MAX];
                c.number.width_spaced(kas(v, &mut buf), c.spacing)
            })
            .max()
            .unwrap_or(0);
        c.label + label_w + gap + widest <= c.right
    };
    let agreed = Columns {
        label: scale.x(48 + dx),
        right: scale.x(222 + dx),
        kas: scale.x(234 + dx),
        number: kit.title,
        spacing: scale.len(DIGIT_GAP),
    };
    if fits(&agreed) {
        return agreed;
    }
    let kas_x = scale.x(SIDE_RIGHT) - kit.body.width("KAS");
    let wide = Columns {
        label: scale.x(SIDE_LEFT),
        right: kas_x - gap,
        kas: kas_x,
        ..agreed
    };
    if fits(&wide) {
        return wide;
    }
    let small = Columns {
        number: kit.body,
        ..wide
    };
    if fits(&small) {
        return small;
    }
    // Kaspa's whole supply, on either panel: the characters as the font
    // sets them.
    Columns {
        spacing: 0,
        ..small
    }
}

/// The room between the side arrows, in design columns: from just past the
/// left one, which ends at 22...
pub const SIDE_LEFT: i32 = 26;
/// ...to just short of the right one, which starts at 298.
pub const SIDE_RIGHT: i32 = 294;

/// The Fee's colour: red over one KAS, else the usual text colour. All that
/// the outputs leave behind goes to the miners, so an outsized fee is worth
/// seeing at a glance.
pub fn fee_ink(fee: u64) -> u16 {
    if fee > SOMPI_PER_KASPA {
        RED
    } else {
        TEXT
    }
}

/// The three totals' rows from design row `top`, moved `dx` design pixels
/// right, in [`columns`].
fn rows(band: &mut Band<'_>, scale: Scale, kit: &Kit, totals: &Totals, (top, dx): (i32, i32)) {
    let c = columns(scale, kit, totals, dx);
    for (i, (label, sompi, ink)) in [
        (LABELS[0], totals.out, TEXT),
        (LABELS[1], totals.spent, ORANGE),
        (LABELS[2], totals.fee, fee_ink(totals.fee)),
    ]
    .into_iter()
    .enumerate()
    {
        let y = scale.y(top + i as i32 * 28);
        band.text(kit.body, c.label, y, TEXT_DIM, label);
        let mut buf = [0u8; AMOUNT_MAX];
        let number = kas(sompi, &mut buf);
        let w = c.number.width_spaced(number, c.spacing);
        band.text_spaced(c.number, c.right - w, y, ink, number, c.spacing);
        band.text(kit.body, c.kas, y, TEXT_DIM, "KAS");
    }
}

/// An amount centred at design row `y`, the number in `ink`.
fn amount(band: &mut Band<'_>, scale: Scale, kit: &Kit, (y, sompi): (i32, u64), ink: u16) {
    let mut buf = [0u8; AMOUNT_MAX];
    let number = kas(sompi, &mut buf);
    let gap = kit.body.width(" ");
    let w = amount_width(scale, kit.title, number) + gap + kit.body.width("KAS");
    let x = scale.x(160) - w / 2;
    let y = scale.y(y);
    let n = band.text_spaced(kit.title, x, y, ink, number, scale.len(DIGIT_GAP));
    band.text(kit.body, x + n + gap, y, TEXT_DIM, "KAS");
}

/// The characters on each end of an address drawn in teal.
pub const LIT_ENDS: usize = 5;

/// Whether character `at` of `address` is one of the ends drawn in teal:
/// the first [`LIT_ENDS`] after the prefix's colon, and the last.
pub fn lit(address: &str, at: usize) -> bool {
    let start = address.find(':').map_or(0, |c| c + 1);
    (at >= start && at < start + LIT_ENDS) || at + LIT_ENDS >= address.len()
}

/// An address in [`super::address::address_per_line`]'s lines, centred,
/// baselines from design row `top` `step` apart, its ends teal.
pub(super) fn address_lines(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    address: &str,
    (top, step): (i32, i32),
) {
    let per = super::address::address_per_line(scale, kit, address);
    for (row, line) in address.as_bytes().chunks(per).enumerate() {
        let line = core::str::from_utf8(line).unwrap_or("");
        let y = scale.y(top + row as i32 * step);
        let mut x = scale.x(160) - kit.title.width(line) / 2;
        for (j, c) in line.char_indices() {
            let ink = if lit(address, row * per + j) {
                TEAL
            } else {
                TEXT
            };
            let mut one = [0u8; 4];
            x += band.text(kit.title, x, y, ink, c.encode_utf8(&mut one));
        }
    }
}

/// `1 input, 2 outputs`.
fn counts(inputs: usize, outputs: usize, out: &mut [u8; 48]) -> &str {
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let mut n = Part::Number(inputs).write(out, 0);
    n = Part::Text(" input").write(out, n);
    n = Part::Text(plural(inputs)).write(out, n);
    n = Part::Text(", ").write(out, n);
    n = Part::Number(outputs).write(out, n);
    n = Part::Text(" output").write(out, n);
    n = Part::Text(plural(outputs)).write(out, n);
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// Bytes [`lock_time`] writes at most: a time's year can run to nine
/// digits.
pub const LOCK_TIME_MAX: usize = 40;

/// A lock time as LOCK TIME says it, by [`classify_lock_time`]: a DAA
/// score as `DAA score 412,345,678`; a time in milliseconds, day first in
/// UTC, as `DD/MM/YYYY HH:MM:SS UTC`, with `.mmm` after the seconds when it
/// has any. Zero, no lock time and no page, as `None`.
pub fn lock_time(value: u64, out: &mut [u8; LOCK_TIME_MAX]) -> &str {
    let mut n = 0usize;
    let mut put = |out: &mut [u8; LOCK_TIME_MAX], bytes: &[u8]| {
        for &b in bytes {
            if let Some(slot) = out.get_mut(n) {
                *slot = b;
                n += 1;
            }
        }
    };
    let two = |v: u64| [b'0' + (v / 10 % 10) as u8, b'0' + (v % 10) as u8];
    match classify_lock_time(value) {
        LockTime::None => put(out, b"None"),
        LockTime::DaaScore(score) => {
            put(out, b"DAA score ");
            let mut digits = [0u8; 20];
            let digits = decimal(score, &mut digits);
            for (i, &c) in digits.iter().enumerate() {
                if i > 0 && (digits.len() - i).is_multiple_of(3) {
                    put(out, b",");
                }
                put(out, &[c]);
            }
        }
        LockTime::Timestamp(millis) => {
            let secs = millis / 1000;
            let (year, month, day) = civil(secs / 86_400);
            let t = secs % 86_400;
            put(out, &two(day));
            put(out, b"/");
            put(out, &two(month));
            put(out, b"/");
            let mut digits = [0u8; 20];
            put(out, decimal(year, &mut digits));
            put(out, b" ");
            put(out, &two(t / 3600));
            put(out, b":");
            put(out, &two(t / 60 % 60));
            put(out, b":");
            put(out, &two(t % 60));
            let rest = millis % 1000;
            if rest != 0 {
                put(out, &[b'.', b'0' + (rest / 100) as u8]);
                put(out, &two(rest % 100));
            }
            put(out, b" UTC");
        }
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// `value`'s decimal digits, at the end of `out`.
fn decimal(mut value: u64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    loop {
        at -= 1;
        out[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &out[at..];
        }
    }
}

/// The Gregorian year, month and day `days` after the Unix epoch, by
/// `civil_from_days` ("chrono-Compatible Low-Level Date Algorithms").
const fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// The arrows at the sides, teal where they lead somewhere, dark where
/// they do not, their tips at design row `mid`.
pub(super) fn sides(band: &mut Band<'_>, scale: Scale, (left, right): (bool, bool), mid: i32) {
    let p = |x: i32, y: i32| (scale.x(x), scale.y(y));
    let ink = |live: bool| if live { TEAL } else { TEAL_DARK };
    band.triangle([p(5, mid), p(22, mid - 14), p(22, mid + 14)], ink(left));
    band.triangle(
        [p(315, mid), p(298, mid - 14), p(298, mid + 14)],
        ink(right),
    );
}

/// The review's arrows' tips, in design rows.
const SIDES_MID: i32 = 130;

/// The review's address lines, apart, in design rows.
const ADDRESS_STEP: i32 = 26;
