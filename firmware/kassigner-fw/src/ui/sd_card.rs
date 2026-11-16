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

//! Settings' SD Card: the slot with Format FAT32 and Test R/W, and the
//! screens a card job shows while it runs and when it is done. Nothing
//! moves while a job runs: on both S3 units the card holds the display's
//! pins until it ends.

use super::band::Band;
use super::brand;
use super::camera::Part;
use super::chrome::{buttons, card, corner, header, header_in, lit_edge, Nav};
use super::color::{ACCENT, CARD, DANGER, TEAL, TEXT, TEXT_DIM};
use super::scale::{bounds, Kit, Scale};
use crate::card::{Job, Outcome, Status, NO_CARD};
use crate::touch::Zone;

/// The screen's title.
pub const TITLE: &str = "SD CARD";

/// A failed card job's title. The flow picks one (`Flow::card_said`): a
/// job alone cannot tell a backup from a kpub's save, or a restore from
/// Sign Message's file.
pub const BACKUP_FAILED: &str = "Backup Failed";
pub const KPUB_SAVE_FAILED: &str = "kpub Save Failed";
pub const SIGNATURE_SAVE_FAILED: &str = "Signature Save Failed";
pub const TX_SAVE_FAILED: &str = "Signed TX Save Failed";
pub const ADDRESS_SAVE_FAILED: &str = "Address Save Failed";
pub const CARD_SAVE_FAILED: &str = "Card Save Failed";
pub const DESCRIPTOR_SAVE_FAILED: &str = "Descriptor Save Failed";
pub const RESTORE_FAILED: &str = "Restore Failed";
pub const KPUB_LOAD_FAILED: &str = "kpub Load Failed";
pub const DESCRIPTOR_LOAD_FAILED: &str = "Descriptor Load Failed";
pub const ADDRESS_LOAD_FAILED: &str = "Address Load Failed";
pub const CARD_LOAD_FAILED: &str = "Card Load Failed";
pub const MESSAGE_LOAD_FAILED: &str = "Message Load Failed";
pub const TX_LOAD_FAILED: &str = "TX Load Failed";
pub const PHOTO_LOAD_FAILED: &str = "Photo Load Failed";
pub const STEGO_FAILED: &str = "Stego Export Failed";
pub const DELETE_FAILED: &str = "Delete Failed";
pub const FORMAT_FAILED: &str = "Format Failed";
pub const TEST_FAILED: &str = "Test FAILED";

/// The flow's words for a job's result screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Said {
    /// What a write saved: `!! Backup Saved !!`, `!! kpub Saved !!`.
    pub saved: &'static str,
    /// A failure's title: one of the `*_FAILED` above.
    pub failed: &'static str,
    /// An empty list's title and its line: `NO BACKUPS`, or no `.TXT` files.
    pub empty: (&'static str, &'static str),
}

/// What a touch on the SD Card screen can land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Nav(Nav),
    /// Format FAT32.
    Format,
    /// Test R/W.
    Test,
}

/// The two buttons as drawn, in design pixels.
const FORMAT_AT: (i32, i32, i32, i32) = (15, 105, 140, 34);
const TEST_AT: (i32, i32, i32, i32) = (165, 105, 140, 34);

/// Where a target counts: each button and 5 design pixels round it, which
/// meet in the middle.
pub const fn zone(scale: Scale, target: Target) -> Option<Zone> {
    match target {
        Target::Nav(nav @ (Nav::Back | Nav::Home)) => Some(corner(scale, nav)),
        Target::Nav(_) => None,
        Target::Format => Some(scale.zone(10, 100, 150, 44)),
        Target::Test => Some(scale.zone(160, 100, 150, 44)),
    }
}

/// What is under a point; the buttons only while a card is in.
pub fn target(scale: Scale, status: Status, x: u16, y: u16) -> Option<Target> {
    let buttons: &[Target] = match status {
        Status::Present(_) => &[Target::Format, Target::Test],
        _ => &[],
    };
    [Target::Nav(Nav::Back), Target::Nav(Nav::Home)]
        .iter()
        .chain(buttons)
        .copied()
        .find(|&t| zone(scale, t).is_some_and(|z| z.contains(x, y)))
}

/// The SD Card screen: the card's kind and the two buttons, no card, or
/// "Checking for a card..." while the slot is probed. `lit` is what is
/// under a finger.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, status: Status, lit: Option<Target>) {
    header(band, scale, kit, TITLE);
    buttons(band, scale);
    let mid = scale.x(160);
    match status {
        Status::Checking => {
            band.text_centered(
                kit.body,
                mid,
                scale.y(100),
                TEXT_DIM,
                "Checking for a card...",
            );
        }
        Status::Absent => {
            band.text_centered(kit.body, mid, scale.y(100), TEXT_DIM, "No SD card detected");
            band.text_centered(
                kit.body,
                mid,
                scale.y(125),
                TEXT_DIM,
                "Insert a microSD card",
            );
        }
        Status::Present(kind) => {
            band.text_centered(kit.body, mid, scale.y(65), TEXT, kind.label());
            band.text_centered(kit.body, mid, scale.y(85), TEAL, "Card detected");
            let r = scale.len(6);
            for (t, at, label) in [
                (Target::Format, FORMAT_AT, "Format FAT32"),
                (Target::Test, TEST_AT, "Test R/W"),
            ] {
                let z = scale.zone(at.0, at.1, at.2, at.3);
                let (edge, thick) = if lit == Some(t) {
                    (ACCENT, lit_edge(scale))
                } else {
                    (TEAL, 1)
                };
                card(band, z, r, CARD, edge, thick);
                let (x, y, w, _) = bounds(z);
                band.text_centered(kit.body, x + w / 2, y + scale.len(22), TEXT, label);
            }
        }
    }
}

/// What the screen says while `job` runs: two lines, no buttons.
pub fn busy(band: &mut Band<'_>, scale: Scale, kit: &Kit, job: Job) {
    let title = match job {
        Job::Format => "Formatting...",
        Job::Test => "Testing R/W...",
        Job::Write => "Writing...",
        Job::Delete => "Deleting...",
        Job::Probe
        | Job::NextName
        | Job::Exists
        | Job::List
        | Job::ListText
        | Job::ListGroups
        | Job::ListAddresses
        | Job::ListCards
        | Job::ListPhotos
        | Job::Read => "Reading card...",
    };
    let mid = scale.x(160);
    band.text_centered(kit.title, mid, scale.y(100), TEAL, title);
    band.text_centered(kit.body, mid, scale.y(135), TEXT_DIM, "Do not remove card");
}

/// What `job` came to: the logo and its lines when it worked (an empty
/// list's two lines without it), else the failure in red with why under
/// it, in the words of `said`. A failed test has its own screen.
pub fn done(
    band: &mut Band<'_>,
    scale: Scale,
    kit: &Kit,
    (job, outcome): (Job, Outcome),
    said: Said,
) {
    let mid = scale.x(160);
    match (job, outcome) {
        (_, Outcome::Formatted) => {
            brand::mark(band, scale);
            band.text_centered(kit.title, mid, scale.y(150), TEAL, "!! Format Complete !!");
        }
        (_, Outcome::Written) => {
            brand::mark(band, scale);
            band.text_centered(kit.title, mid, scale.y(150), TEAL, said.saved);
        }
        (_, Outcome::Listed { .. }) => {
            band.text_centered(kit.title, mid, scale.y(120), TEAL, said.empty.0);
            band.text_centered(kit.body, mid, scale.y(150), TEXT_DIM, said.empty.1);
        }
        (_, Outcome::Tested { bytes, files }) => {
            brand::mark(band, scale);
            band.text_centered(kit.title, mid, scale.y(148), TEAL, "!! Test PASSED !!");
            let mut first = [0u8; 40];
            let mut second = [0u8; 40];
            let lines = [
                line(
                    &[
                        Part::Text("Write+Read: "),
                        Part::Number(bytes),
                        Part::Text(" bytes OK"),
                    ],
                    &mut first,
                ),
                line(
                    &[
                        Part::Text("Root dir: "),
                        Part::Number(files as usize),
                        Part::Text(" files"),
                    ],
                    &mut second,
                ),
                "Data verify: match",
            ];
            for (i, text) in lines.iter().enumerate() {
                band.text_centered(kit.body, mid, scale.y(175 + i as i32 * 18), TEXT, text);
            }
        }
        (Job::Test, other) => {
            header_in(band, scale, kit, TEST_FAILED, DANGER, DANGER);
            band.text_centered(kit.body, mid, scale.y(60), TEXT, "SD card test failed:");
            band.text_centered(kit.body, mid, scale.y(80), TEXT, why(other));
        }
        (_, other) => {
            band.text_centered(kit.title, mid, scale.y(120), DANGER, said.failed);
            band.text_centered(kit.body, mid, scale.y(150), TEXT_DIM, why(other));
        }
    }
}

/// Why a job failed: [`NO_CARD`] for a card that did not answer.
const fn why(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Failed(e) => e.describe(),
        _ => NO_CARD,
    }
}

/// `parts` written into `out`, as much as fits.
fn line<'a>(parts: &[Part<'_>], out: &'a mut [u8; 40]) -> &'a str {
    let mut n = 0;
    for p in parts {
        n = p.write(out, n);
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}
