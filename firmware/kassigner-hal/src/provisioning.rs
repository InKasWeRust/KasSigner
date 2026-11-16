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

//! Whether a unit is provisioned, judged once for every board.
//!
//! A board reads its fuses into a [`Reading`] and decides nothing (the S3
//! crate by address, the P4 crate through esp-hal's field table). The
//! meaning is decided here, once, so no two boards judge a fuse differently:
//! [`Reading::verdict`] for the flow, and [`Reading::lines`],
//! [`Reading::slot`] and the key blocks for the console's boot report.
//!
//! # The three verdicts
//!
//! - **Blank**: Secure Boot is off. Any image runs, so nothing else counts.
//!   The owner chose this by not provisioning the unit, and the unit says so.
//! - **Provisioned**: Secure Boot is on and none of the holes below is open.
//! - **Holes**: Secure Boot is on and at least one hole is open; every open
//!   one is named.
//!
//! None of the three stops the unit: the flow decides what each shows and
//! what the unit does next.
//!
//! # The holes
//!
//! Three things leave a provisioned unit open, worst first:
//!
//! 1. **A key slot.** Secure Boot accepts a signature matching any of three
//!    burned digests; a slot someone could still fill with their own digest
//!    is a second root of trust, and their firmware would boot ([`Slot`]).
//! 2. **JTAG, either route.** Pads and USB bridge reach one debug port, and
//!    whoever reaches it halts the CPU and reads RAM.
//! 3. **Download mode.** Secure Boot checks images in flash, not a program
//!    the ROM's download mode loads into RAM and runs (S3 TRM, Chip Boot
//!    Control: "it is also possible to load a program into SRAM and execute
//!    it in this mode"), and internal RAM survives a reset. Secure Download
//!    Mode keeps flash writes, the update path, and refuses the rest;
//!    disabling download closes it too. Espressif's Secure Boot V2
//!    production workflow burns Secure Download Mode last.
//!
//! The ESP-IDF Secure Boot bootloader closes all three on the owner's first
//! boot (ESP-IDF v6.1, `secure_boot_secure_features.c` and the unused digest
//! revocation in `secure_boot.c`). Holes come from fuses burned by hand, or
//! a bootloader built to leave them.
//!
//! # What is only shown
//!
//! Espressif's S3 production list ("Enable Secure Boot v2 Externally",
//! ESP-IDF v6.1) recommends more than these, most of which the ESP-IDF
//! bootloader burns on a blank chip. Printed as recommended, outside the
//! verdict:
//!
//! - **Direct boot disabled.** Direct boot runs flash code unchecked, but
//!   only with Secure Boot off (S3 TRM, Chip Boot Control: "does not support
//!   Security Boot"; Espressif's direct-boot example: "Secure boot is
//!   disabled"). On a provisioned unit the fuse is a second lock on a closed
//!   door.
//! - **Soft JTAG disabled.** Moot when both hard JTAG disables hold, as on a
//!   unit with no holes.
//! - **Aggressive revoke.** Lets a failed check revoke a key: a key-rotation
//!   choice, not a defence.
//! - **Read-protect lock**, the write protection on the read-disable bits.
//!   Unlocked, someone with eFuse access can read-protect the digest blocks
//!   so the unit stops booting: a way to brick it, not to get in.
//!
//! Shown with no recommendation: whether software may force the next reset
//! into download mode (which lands in whatever mode the fuses allow), and
//! whether USB Serial/JTAG is disabled altogether (kept on as the update
//! path; only the S3 has this fuse).
//!
//! # What this is not
//!
//! Not tamper evidence: firmware running unsigned code would control this
//! read and its screen. It catches our own provisioning mistakes: a unit
//! flashed but never burned, a burn that did not take, a step forgotten.

use core::fmt;

/// Key blocks a chip has, `KEY0` to `KEY5`: BLOCK4 to BLOCK9 on both the S3
/// and the P4.
pub const KEY_BLOCKS: usize = 6;

/// Secure Boot digest slots, `SECURE_BOOT_DIGEST0` to `2`.
pub const DIGEST_SLOTS: usize = 3;

/// Set bits from which a key block's data can no longer be made someone
/// else's digest.
///
/// eFuse bits only go from 0 to 1, so unlocked data can still become any
/// digest that covers its set bits. Finding a key whose digest covers `n`
/// given bits takes about `2^n` tries: moments for a few, past anyone's reach
/// for 64. A real digest has 128 of 256 bits set on average and fewer than 64
/// about once in `10^16`, so it reads as held, locked or not.
pub const FILLABLE_BELOW: u32 = 64;

/// The key purpose that names digest slot 0; slot `k` is this plus `k`.
/// S3 TRM Table 5-2 (9, 10, 11), and the same values in ESP-IDF's
/// `esp_efuse_chip.h` for the P4.
pub const PURPOSE_DIGEST: u8 = 9;

/// One key block, as read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyBlock {
    /// `KEY_PURPOSE_n`, the raw four bits.
    pub purpose: u8,
    /// The purpose field's write protection is burned.
    pub purpose_locked: bool,
    /// How many of the block's 256 bits read as set. A read-protected block
    /// reads as zeros, so as empty; [`Slot::Open`] says why that errs the
    /// safe way.
    pub bits: u32,
    /// The block's data write protection is burned.
    pub locked: bool,
}

impl KeyBlock {
    /// The purpose's name for the values judged here; any other is "other".
    pub const fn purpose_name(&self) -> &'static str {
        match self.purpose {
            0 => "user",
            9 => "digest 0",
            10 => "digest 1",
            11 => "digest 2",
            _ => "other",
        }
    }

    /// Whether this block names digest slot `k`, or could still be made to:
    /// eFuse bits only go from 0 to 1, so an unlocked purpose can become any
    /// value whose set bits include its own (from 0 or 8, any slot; from 2,
    /// slot 1 or 2).
    const fn reaches(&self, k: usize) -> bool {
        let want = PURPOSE_DIGEST + k as u8;
        self.purpose == want || (!self.purpose_locked && (self.purpose & !want) == 0)
    }

    /// Whether any bit reads as set: "written" on the console.
    pub const fn written(&self) -> bool {
        self.bits > 0
    }

    /// Whether someone with eFuse access could still burn their own digest
    /// into this block: data unlocked, fewer than [`FILLABLE_BELOW`] bits set.
    /// A few set bits are no defence: a digest covering them can be found.
    const fn fillable(&self) -> bool {
        !self.locked && self.bits < FILLABLE_BELOW
    }
}

impl fmt::Display for KeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lock = |locked: bool| if locked { "locked" } else { "open" };
        write!(
            f,
            "purpose {:>2} ({}), purpose {}, data {}, data {}",
            self.purpose,
            self.purpose_name(),
            lock(self.purpose_locked),
            if self.written() { "written" } else { "empty" },
            lock(self.locked),
        )
    }
}

/// The fuses that matter, as a board read them: plain facts named for what
/// they do, not for the chip's registers, one fuse or fuse field each. A
/// fuse some chip lacks is an `Option`, `None` on that chip.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// `SECURE_BOOT_EN`.
    pub secure_boot: bool,
    /// `DIS_PAD_JTAG`: JTAG over the pads disabled for good.
    pub pad_jtag_off: bool,
    /// `DIS_USB_JTAG`: JTAG over the USB bridge disabled.
    pub usb_jtag_off: bool,
    /// `DIS_DOWNLOAD_MODE`: every download mode disabled.
    pub download_off: bool,
    /// `ENABLE_SECURITY_DOWNLOAD`: download mode limited to flash.
    pub secure_download: bool,
    /// `SECURE_BOOT_KEY_REVOKE0` to `2`.
    pub revoked: [bool; DIGEST_SLOTS],
    /// `KEY0` to `KEY5`.
    pub keys: [KeyBlock; KEY_BLOCKS],
    /// `DIS_DIRECT_BOOT`, `DIS_LEGACY_SPI_BOOT` in the S3 TRM.
    pub direct_boot_off: bool,
    /// `SOFT_DIS_JTAG`, an odd number of its bits set.
    pub soft_jtag_off: bool,
    /// `SECURE_BOOT_AGGRESSIVE_REVOKE`.
    pub aggressive_revoke: bool,
    /// The write protection on `RD_DIS`, `WR_DIS` bit 0.
    pub read_protect_locked: bool,
    /// `DIS_FORCE_DOWNLOAD`: software can no longer force the next reset into
    /// download mode.
    pub force_download_off: bool,
    /// `DIS_USB_SERIAL_JTAG`: USB Serial/JTAG disabled altogether. `None` on
    /// a chip with no such fuse, which the P4 is.
    pub usb_serial_off: Option<bool>,
}

/// The holes a provisioned unit has open, each a way around Secure Boot its
/// fuses left; the module header says what each lets in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Holes {
    /// A digest slot someone could still fill: see [`Slot::Open`].
    pub key_slot: bool,
    /// JTAG still reachable, by pad or by USB.
    pub jtag: bool,
    /// Download mode can still load code into RAM: neither Secure Download
    /// Mode nor download disabled.
    pub download: bool,
}

impl Holes {
    /// Whether any is open.
    pub const fn any(self) -> bool {
        self.key_slot || self.jtag || self.download
    }

    /// The screen's line for them, at most 30 characters: each open hole by
    /// name, worst first. Empty when none is.
    pub const fn line(self) -> &'static str {
        match (self.key_slot, self.jtag, self.download) {
            (true, true, true) => "Open: key slot, JTAG, download",
            (true, true, false) => "Open: key slot, JTAG",
            (true, false, true) => "Open: key slot, download",
            (true, false, false) => "Open: key slot",
            (false, true, true) => "Open: JTAG, download",
            (false, true, false) => "Open: JTAG",
            (false, false, true) => "Open: download",
            (false, false, false) => "",
        }
    }
}

/// A board's verdict on its own fuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Secure Boot is off: any image runs.
    Blank,
    /// Secure Boot is on and no hole is open.
    Provisioned,
    /// Secure Boot is on, and these are open; at least one is.
    Holes(Holes),
}

impl Verdict {
    /// Whether Secure Boot is on: the unit runs only what its owner signed.
    pub const fn is_provisioned(self) -> bool {
        !matches!(self, Verdict::Blank)
    }

    /// Whether it is on with nothing open.
    pub const fn is_closed(self) -> bool {
        matches!(self, Verdict::Provisioned)
    }

    /// The fuse line, for the console and the verification screen: at most
    /// 30 characters.
    pub const fn line(self) -> &'static str {
        match self {
            Verdict::Blank => "eFuse: Secure Boot off",
            Verdict::Provisioned => "eFuse: provisioned",
            Verdict::Holes(holes) => holes.line(),
        }
    }
}

/// Where a digest slot stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Revoked: no signature is checked against it, whatever it holds.
    Revoked,
    /// Held by this key block: the first naming the slot, its data a digest
    /// ([`FILLABLE_BELOW`] bits or more) or locked, so its digest is checked
    /// and nobody can put theirs there. For good if its purpose is locked;
    /// otherwise only while no later block could be filled and pointed at
    /// the slot.
    Held(usize),
    /// No block names it, and none that could be made to can still be
    /// filled with someone else's digest. Nothing is checked against it.
    Unused,
    /// Through this key block someone with eFuse access can burn their own
    /// digest and have the ROM accept their signatures: it names the slot or
    /// can be made to, its data is unlocked with fewer than
    /// [`FILLABLE_BELOW`] bits set, and no block before it has its purpose
    /// locked on the slot.
    ///
    /// For each slot not revoked the ROM checks only the first key block,
    /// KEY0 up, whose purpose names it. On the S3, `ets_efuse_find_purpose`
    /// (ROM, 0x4004247c) walks blocks 4 to 10 and returns the first match,
    /// and `ets_secure_boot_read_key_digests` (0x4004483c) calls it once per
    /// unrevoked slot; the P4's ROM (rev0, 0x4fc04e24, as ESP-IDF ships it)
    /// walks blocks 4 to 9 alike, and so does ESP-IDF's bootloader for the
    /// app (`esp_secure_boot_read_key_digests`). So a first block with its
    /// purpose locked on the slot closes it for good; one with its purpose
    /// unlocked closes nothing, as its purpose can move on and a later block
    /// become the first.
    ///
    /// A read-protected block reads as empty, so counts as fillable unless
    /// locked: a false alarm at worst, never a false all-clear.
    Open(usize),
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Slot::Revoked => f.write_str("revoked"),
            Slot::Held(i) => write!(f, "held by KEY{i}"),
            Slot::Unused => f.write_str("unused"),
            Slot::Open(i) => write!(f, "OPEN through KEY{i}"),
        }
    }
}

/// How much a printed fuse counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weight {
    /// Part of the verdict.
    Required,
    /// On Espressif's production list, not part of the verdict; the module
    /// header says why for each.
    Recommended,
    /// Shown, with no recommendation either way.
    Shown,
}

/// One fuse, or one judged condition, for the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// What it is.
    pub what: &'static str,
    /// What it reads.
    pub state: &'static str,
    /// How much it counts.
    pub weight: Weight,
    /// For [`Weight::Required`] and [`Weight::Recommended`], whether it is as
    /// required or recommended; always true for [`Weight::Shown`].
    pub holds: bool,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let note = match (self.weight, self.holds) {
            (Weight::Required, true) => "required",
            (Weight::Required, false) => "required, MISSING",
            (Weight::Recommended, true) => "recommended",
            (Weight::Recommended, false) => "recommended, not burned",
            (Weight::Shown, _) => "",
        };
        write!(f, "{:<18} {:<8} {}", self.what, self.state, note)
    }
}

/// Lines in [`Reading::lines`].
pub const LINES: usize = 11;

impl Reading {
    /// Where digest slot `k` stands, walking the key blocks in the ROM's
    /// order (see [`Slot::Open`]). `k` past the last slot reads as revoked:
    /// nothing could fill it.
    pub fn slot(&self, k: usize) -> Slot {
        if k >= DIGEST_SLOTS || self.revoked[k] {
            return Slot::Revoked;
        }
        let want = PURPOSE_DIGEST + k as u8;
        let mut held = None;
        for (i, block) in self.keys.iter().enumerate() {
            // Fillable and pointable, nothing locked on the slot before it:
            // it can be made the first, and only the first is checked.
            if block.reaches(k) && block.fillable() {
                return Slot::Open(i);
            }
            if block.purpose == want {
                if block.purpose_locked {
                    // The first block checked for this slot, for good.
                    return Slot::Held(i);
                }
                // Checked today, until its purpose is moved on.
                held.get_or_insert(i);
            }
        }
        held.map_or(Slot::Unused, Slot::Held)
    }

    /// Whether any digest slot is open.
    pub fn digest_slot_open(&self) -> bool {
        (0..DIGEST_SLOTS).any(|k| matches!(self.slot(k), Slot::Open(_)))
    }

    /// Whether download mode is closed to anything but flash.
    pub const fn download_closed(&self) -> bool {
        self.download_off || self.secure_download
    }

    /// The holes open, whether or not Secure Boot is on.
    pub fn holes(&self) -> Holes {
        Holes {
            key_slot: self.digest_slot_open(),
            jtag: !(self.pad_jtag_off && self.usb_jtag_off),
            download: !self.download_closed(),
        }
    }

    /// The verdict: blank without Secure Boot, else provisioned or every
    /// hole open.
    pub fn verdict(&self) -> Verdict {
        if !self.secure_boot {
            return Verdict::Blank;
        }
        let holes = self.holes();
        if holes.any() {
            Verdict::Holes(holes)
        } else {
            Verdict::Provisioned
        }
    }

    /// Every fuse that matters, for the console: the five judged lines first
    /// (JTAG is two), Secure Boot then the others in the order a unit is
    /// provisioned; then the recommended, then the shown.
    pub fn lines(&self) -> [Line; LINES] {
        const fn on(b: bool) -> &'static str {
            if b {
                "on"
            } else {
                "off"
            }
        }
        const fn off(b: bool) -> &'static str {
            if b {
                "off"
            } else {
                "OPEN"
            }
        }
        let slots_open = self.digest_slot_open();
        let line = |what, state, weight, holds| Line {
            what,
            state,
            weight,
            holds,
        };
        [
            line(
                "secure boot",
                on(self.secure_boot),
                Weight::Required,
                self.secure_boot,
            ),
            line(
                "JTAG by pad",
                off(self.pad_jtag_off),
                Weight::Required,
                self.pad_jtag_off,
            ),
            line(
                "JTAG by USB",
                off(self.usb_jtag_off),
                Weight::Required,
                self.usb_jtag_off,
            ),
            line(
                "digest slots",
                if slots_open { "OPEN" } else { "closed" },
                Weight::Required,
                !slots_open,
            ),
            line(
                "download mode",
                if self.download_off {
                    "off"
                } else if self.secure_download {
                    "secure"
                } else {
                    "OPEN"
                },
                Weight::Required,
                self.download_closed(),
            ),
            line(
                "direct boot",
                if self.direct_boot_off { "off" } else { "on" },
                Weight::Recommended,
                self.direct_boot_off,
            ),
            line(
                "soft JTAG",
                if self.soft_jtag_off { "off" } else { "on" },
                Weight::Recommended,
                self.soft_jtag_off,
            ),
            line(
                "aggressive revoke",
                on(self.aggressive_revoke),
                Weight::Recommended,
                self.aggressive_revoke,
            ),
            line(
                "read-protect lock",
                if self.read_protect_locked {
                    "locked"
                } else {
                    "open"
                },
                Weight::Recommended,
                self.read_protect_locked,
            ),
            line(
                "forced download",
                if self.force_download_off { "off" } else { "on" },
                Weight::Shown,
                true,
            ),
            line(
                "USB serial",
                match self.usb_serial_off {
                    Some(true) => "off",
                    Some(false) => "on",
                    None => "n/a",
                },
                Weight::Shown,
                true,
            ),
        ]
    }
}

/// A board's fuse reader. The fuses are read at boot, as they do not change
/// while the unit runs. The board reads and this module judges: a board gets
/// [`Provisioning::verdict`] and does not write its own.
pub trait Provisioning {
    /// The fuses, as read.
    fn read(&self) -> Reading;

    /// The verdict on them.
    fn verdict(&self) -> Verdict {
        self.read().verdict()
    }
}

/// The unit's console and debug port, the one that reaches a host.
///
/// On the ESP32-S3, USB Serial/JTAG: console and JTAG bridge on the same
/// pads. A provisioned unit closes it once the verification screen has
/// passed, holes or not, so nothing goes in or out that way until the next
/// reset. A blank unit keeps it open: its owner chose not to provision it,
/// and the console is how it is developed and watched.
pub trait Console {
    /// Close the port until the next reset.
    fn close(&mut self);
}
