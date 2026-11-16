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

//! The brand screens: the logo screen, the verification screen and the home
//! grid. A home card is drawn and touched where [`zone`] says, so the two
//! cannot drift apart.

use super::band::Band;
use super::camera::Part;
use super::chrome::{card, header, lit_edge, place};
use super::color::{ACCENT, CARD, DANGER, ORANGE, TEAL, TEXT, TEXT_DIM};
use super::gen;
use super::image::Image;
use super::scale::{bounds, Kit, Scale};
use crate::text::write_hex;
use crate::touch::Zone;
use kassigner_hal::battery::{self, ChargeState, Reading};
use kassigner_hal::provisioning::Verdict;

// ── The logo screen ─────────────────────────────────────────────────────────

/// The logo screen. `version` is drawn as given, so the caller writes the
/// `v`.
pub fn logo(band: &mut Band<'_>, scale: Scale, kit: &Kit, version: &str, unit: &str) {
    mark(band, scale);

    let mid = scale.x(160);
    band.text_centered(kit.title, mid, scale.y(122), TEXT, version);
    let line = "Air-Gapped Offline Signer for Kaspa";
    band.text_centered(kit.body, mid, scale.y(146), TEXT_DIM, line);
    let line = "100% Rust | Stateless | no_std";
    band.text_centered(kit.body, mid, scale.y(166), TEXT_DIM, line);
    band.text_centered(kit.hint, mid, scale.y(186), TEXT_DIM, unit);
    band.text_centered(kit.hint, mid, scale.y(206), TEAL, "kassigner.org");
}

/// The logo alone, where the logo screen has it: 20 rows above its place in
/// its 320 by 240 frame. Also what a finished SD Card job is drawn over.
pub fn mark(band: &mut Band<'_>, scale: Scale) {
    let (lx, ly) = gen::LOGO_AT;
    let (lw, lh) = (i32::from(gen::LOGO.width), i32::from(gen::LOGO.height));
    let at = scale.zone(i32::from(lx), i32::from(ly) - 20, lw, lh);
    place(band, scale, &gen::LOGO, at);
}

// ── The verification screen ─────────────────────────────────────────────────

/// The coin over the verification screen, 90 pixels square.
static COIN: Image = Image::new(90, 90, include_bytes!("../../assets/images/kascoin_90.raw"));

/// Bytes of the image's hash the screen keeps ([`shown`]): the first 4 and
/// the last 4, the two ends a reader compares against a list.
pub const HASH_SHOWN: usize = 8;

/// The part of a SHA-256 the screen shows: its first 4 bytes, then its last
/// 4.
pub fn shown(sha256: &[u8; 32]) -> [u8; HASH_SHOWN] {
    let mut kept = [0u8; HASH_SHOWN];
    kept[..4].copy_from_slice(&sha256[..4]);
    kept[4..].copy_from_slice(&sha256[28..]);
    kept
}

/// What boot found: the fuses' verdict and whether the image's hash was
/// read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Check {
    /// The board's verdict on its fuses.
    pub verdict: Verdict,
    /// Whether the image's hash was read.
    pub image_read: bool,
}

impl Check {
    /// Whether the screen ends in teal: provisioned and the hash read.
    pub const fn clean(self) -> bool {
        self.verdict.is_closed() && self.image_read
    }

    /// Whether anything on the screen is red: a hole open, or the hash not
    /// read. The screen then waits for a tap.
    pub const fn red(self) -> bool {
        matches!(self.verdict, Verdict::Holes(_)) || !self.image_read
    }
}

/// The verification screen: the coin, the version, the running image's
/// hash, the fuses' verdict, and what that makes the unit. The last lines:
///
/// | verdict     | fuse line                | status            |
/// |-------------|--------------------------|-------------------|
/// | blank       | `eFuse: Secure Boot off` | `Not provisioned` |
/// |             | orange                   | orange            |
/// | provisioned | `eFuse: provisioned`     | `Verified OK`     |
/// |             | grey                     | teal              |
/// | holes       | `Open: key slot, ...`    | `NOT SECURE`      |
/// |             | red                      | red               |
///
/// `hash` is [`shown`] of the SHA-256 of the image in flash up to the end
/// of the image proper (`kassigner_hal::image`): what `sha256sum` prints
/// for the unsigned `.bin`. `None` when the board could not read it.
///
/// `unit` is About's: the unit's name at the foot. At boot it is `None`,
/// and the foot says to tap when anything is red ([`Check::red`]).
pub fn verification(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    version: &str,
    hash: Option<&[u8; HASH_SHOWN]>,
    verdict: Verdict,
    unit: Option<&str>,
) {
    let check = Check {
        verdict,
        image_read: hash.is_some(),
    };
    place(band, scale, &COIN, scale.zone(115, 10, 90, 90));
    let mid = scale.x(160);

    let mut line = [0u8; 32];
    let n = Part::Text("Version: ").write(&mut line, 0);
    let n = Part::Text(version).write(&mut line, n);
    let said = core::str::from_utf8(&line[..n]).unwrap_or("");
    band.text_centered(kit.title, mid, scale.y(135), TEXT, said);

    let mut line = *b"Hash: ________...________";
    let (said, ink) = match hash {
        Some(hash) => {
            write_hex(&hash[..4], &mut line[6..14]);
            write_hex(&hash[4..], &mut line[17..25]);
            (core::str::from_utf8(&line).unwrap_or(""), TEXT_DIM)
        }
        None => (HASH_UNREAD, DANGER),
    };
    band.text_centered(kit.body, mid, scale.y(165), ink, said);

    let (ink, status, status_ink) = match verdict {
        Verdict::Blank => (ORANGE, NOT_PROVISIONED, ORANGE),
        Verdict::Provisioned if check.image_read => (TEXT_DIM, VERIFIED, TEAL),
        Verdict::Provisioned => (TEXT_DIM, CHECK_FAILED, DANGER),
        Verdict::Holes(_) => (DANGER, NOT_SECURE, DANGER),
    };
    band.text_centered(kit.body, mid, scale.y(190), ink, verdict.line());
    band.text_centered(kit.title, mid, scale.y(215), status_ink, status);

    let foot = match unit {
        Some(unit) => Some(unit),
        None => check.red().then_some(TAP),
    };
    if let Some(foot) = foot {
        band.text_centered(kit.hint, mid, scale.y(234), TEXT_DIM, foot);
    }
}

/// The hash line when the board could not read its image.
pub const HASH_UNREAD: &str = "Hash: not read";

/// What a provisioned unit with nothing open ends on, its hash read.
pub const VERIFIED: &str = "Verified OK";

/// What a blank unit ends on.
pub const NOT_PROVISIONED: &str = "Not provisioned";

/// What a provisioned unit with a hole open ends on.
pub const NOT_SECURE: &str = "NOT SECURE";

/// What a provisioned unit with nothing open ends on when its hash was not
/// read.
pub const CHECK_FAILED: &str = "Check failed";

/// The foot of a verification screen with red on it, which waits.
pub const TAP: &str = "tap to continue";

// ── The home grid ───────────────────────────────────────────────────────────

/// The small logo at the top left of the home grid.
static HOME_LOGO: Image = Image::new(
    30,
    30,
    include_bytes!("../../assets/images/icon_logo_30.raw"),
);

/// A card icon: 56 pixels square, on the card colour.
const fn icon(pixels: &'static [u8]) -> Image {
    Image::new(56, 56, pixels)
}

/// The cards' labels, in reading order.
pub const LABELS: [&str; 4] = ["Scan", "Seeds", "Tools", "Settings"];

/// Their icons, in the same order.
static ICONS: [Image; 4] = [
    icon(include_bytes!("../../assets/images/icon_send.raw")),
    icon(include_bytes!("../../assets/images/icon_addr.raw")),
    icon(include_bytes!("../../assets/images/icon_settings.raw")),
    icon(include_bytes!("../../assets/images/icon_about.raw")),
];

/// What a touch on the home grid can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A card, by its place in [`LABELS`].
    Card(usize),
    /// The header band above the rule, right of the logo.
    Header,
    /// The logo's corner, down to just above the first cards: held for
    /// [`crate::flow::WIPE_HOLD_US`], it wipes everything a seed left.
    Logo,
}

/// Where a target is, for the drawing and the touch alike.
///
/// # Panics
///
/// If a card's index is not a card.
pub const fn zone(scale: Scale, target: Target) -> Zone {
    match target {
        Target::Card(i) => {
            let (x, y) = [(8, 46), (164, 46), (8, 143), (164, 143)][i];
            scale.zone(x, y, 148, 90)
        }
        Target::Header => scale.zone(LOGO_W, 0, 320 - LOGO_W, 40),
        // From the panel's own corner, as Back's and Home's buttons count:
        // on a panel wider than the design, the margin beside it too.
        Target::Logo => Zone::new(0, 0, scale.x(LOGO_W) as u16, scale.y(44) as u16),
    }
}

/// How wide the logo's corner is, in design pixels.
const LOGO_W: i32 = 48;

/// What is under a point, if anything.
pub fn target(scale: Scale, x: u16, y: u16) -> Option<Target> {
    (0..LABELS.len())
        .map(Target::Card)
        .chain([Target::Header, Target::Logo])
        .find(|&t| zone(scale, t).contains(x, y))
}

/// WIPED: the logo and [`WIPED`] in teal, as a finished card job is said.
pub fn wiped(band: &mut Band<'_>, scale: Scale, kit: &Kit) {
    mark(band, scale);
    band.text_centered(kit.title, scale.x(160), scale.y(150), TEAL, WIPED);
}

/// What WIPED says.
pub const WIPED: &str = "!! Wiped !!";

/// What Home shows of the battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gauge {
    /// A cell's level.
    Level {
        /// 0 to 100.
        percent: u8,
        /// The board says current flows into the cell.
        charging: bool,
    },
    /// No cell: the empty outline, no figure. For a board that says none is
    /// fitted, and for the Waveshare, which reads nothing: its battery pin
    /// is on ADC1, which the random generator keeps.
    Empty,
}

impl Gauge {
    /// What a reading lets Home show: nothing for a failed read or a value
    /// no cell gives; the empty outline when the board says no cell is
    /// fitted; nothing at 100% on a board that cannot tell, where a full
    /// cell and no cell read the same.
    pub fn of(reading: Result<Reading, battery::Error>) -> Option<Self> {
        let Ok(Reading::Battery(cell)) = reading else {
            return None;
        };
        match cell.present {
            Some(false) => Some(Self::Empty),
            None if cell.percentage >= 100 => None,
            _ => Some(Self::Level {
                percent: cell.percentage.min(100),
                charging: cell.state == ChargeState::Charging,
            }),
        }
    }

    /// What Home shows when `read` comes in while `shown` is up: `read`, or
    /// `shown` when both are levels, charging alike, a point apart at most. A
    /// cell's voltage wanders a few millivolts between reads, a point is
    /// 9 mV, and a figure flicking between two values says nothing.
    pub fn after(shown: Option<Self>, read: Option<Self>) -> Option<Self> {
        match (shown, read) {
            (
                Some(Self::Level {
                    percent: was,
                    charging: was_charging,
                }),
                Some(Self::Level { percent, charging }),
            ) if was_charging == charging && was.abs_diff(percent) <= 1 => shown,
            _ => read,
        }
    }
}

/// Where Home's battery and its figure are drawn: what is redrawn when only
/// the battery changed.
pub const fn gauge_zone(scale: Scale) -> Zone {
    scale.zone(240, 8, 72, 26)
}

/// The home grid. `lit` is what is under a finger, if anything; `battery`,
/// at the top right, what [`Gauge::of`] made of a reading, if anything.
pub fn home(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    lit: Option<Target>,
    battery: Option<Gauge>,
) {
    place(band, scale, &HOME_LOGO, scale.zone(2, 5, 30, 30));
    header(band, scale, kit, "HOME");
    if let Some(g) = battery {
        gauge(band, scale, kit, g);
    }

    for (i, (label, icon)) in LABELS.iter().zip(ICONS.iter()).enumerate() {
        let z = zone(scale, Target::Card(i));
        let (edge, thick) = if lit == Some(Target::Card(i)) {
            (ACCENT, lit_edge(scale))
        } else {
            (TEAL, 1)
        };
        card(band, z, scale.len(8), CARD, edge, thick);

        // The icon centred in the slot above the label, which in the design
        // is rows 2 to 58 of the card.
        let (x, y, w, _) = bounds(z);
        let slot = scale.len(2) + scale.len(58);
        let (iw, ih) = (
            scale.len(i32::from(icon.width)),
            scale.len(i32::from(icon.height)),
        );
        band.image_sized(x + (w - iw) / 2, y + (slot - ih) / 2, iw, ih, icon);
        band.text_centered(kit.title, x + w / 2, y + scale.len(80), TEXT, label);
    }
}

/// The battery at the top right of Home, filled to its level, the
/// percentage to its left. While charging it is teal with a white `+` (a
/// teal one would not show on the fill).
fn gauge(band: &mut Band<'_>, scale: Scale, kit: &Kit, g: Gauge) {
    let (x, y, w, h) = (scale.x(280), scale.y(15), scale.len(24), scale.len(12));
    let line = scale.len(1).max(1);
    band.fill(x, y, w, line, TEXT);
    band.fill(x, y + h - line, w, line, TEXT);
    band.fill(x, y, line, h, TEXT);
    band.fill(x + w - line, y, line, h, TEXT);
    band.fill(x + w, y + scale.len(3), scale.len(2), scale.len(6), TEXT);

    let Gauge::Level { percent, charging } = g else {
        return;
    };
    let inner = w - 2 * line;
    let filled = (i32::from(percent) * inner / 100).max(1);
    let color = match percent {
        _ if charging => TEAL,
        0..=15 => DANGER,
        16..=30 => ORANGE,
        _ => TEAL,
    };
    band.fill(x + line, y + line, filled, h - 2 * line, color);

    let mut digits = [0u8; 4];
    let text = percent_text(percent, &mut digits);
    let baseline = scale.y(26);
    let width = kit.hint.width(text);
    band.text(kit.hint, x - width - scale.len(6), baseline, TEXT, text);
    if charging {
        band.text(kit.hint, scale.x(287), baseline, TEXT, "+");
    }
}

/// `percent`, at most 100, and `%`, written into `out`.
fn percent_text(percent: u8, out: &mut [u8; 4]) -> &str {
    let p = percent.min(100);
    let mut n = 0;
    if p >= 100 {
        out[n] = b'1';
        n += 1;
    }
    if p >= 10 {
        out[n] = b'0' + (p / 10) % 10;
        n += 1;
    }
    out[n] = b'0' + p % 10;
    out[n + 1] = b'%';
    // Digits and `%` only, so always text.
    core::str::from_utf8(&out[..n + 2]).unwrap_or("")
}
