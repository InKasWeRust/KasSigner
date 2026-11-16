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

//! The fuse verdict, on the host, for every board at once.
//!
//! Fixtures: the two provisioned units as their fuses were read, a blank
//! chip, and one built to pass; each case moves one fuse from one of them.
//! The M5's were read by its own firmware, as its Secure Download refuses
//! `espefuse`. A state not read (the Waveshare's key data locks) takes the
//! worse value, so no pass rests on a guess in the unit's favour.

use kassigner_hal::provisioning::{
    Holes, KeyBlock, Line, Provisioning, Reading, Slot, Verdict, Weight, DIGEST_SLOTS,
    FILLABLE_BELOW, KEY_BLOCKS, LINES, PURPOSE_DIGEST,
};

/// The bits a digest has set, on average: half of its 256.
const DIGEST_BITS: u32 = 128;

/// A key block holding a digest for slot `k`, written, both locks burned.
fn digest(k: u8) -> KeyBlock {
    KeyBlock {
        purpose: PURPOSE_DIGEST + k,
        purpose_locked: true,
        bits: DIGEST_BITS,
        locked: true,
    }
}

/// A key block never used, its purpose locked at "user", its data open.
fn spare() -> KeyBlock {
    KeyBlock {
        purpose: 0,
        purpose_locked: true,
        bits: 0,
        locked: false,
    }
}

/// A chip as it leaves the factory.
fn blank() -> Reading {
    Reading {
        usb_serial_off: Some(false),
        ..Reading::default()
    }
}

/// The provisioned Waveshare as `espefuse summary` read it: its key's digest
/// in key blocks 0 and 1, every key purpose write-protected, download mode
/// open. Its key data locks were not noted, so they are taken as open, the
/// worse case.
fn waveshare() -> Reading {
    let mut keys = [spare(); KEY_BLOCKS];
    keys[0] = KeyBlock {
        locked: false,
        ..digest(0)
    };
    keys[1] = KeyBlock {
        locked: false,
        ..digest(1)
    };
    Reading {
        secure_boot: true,
        pad_jtag_off: true,
        usb_jtag_off: true,
        revoked: [false, false, true],
        keys,
        usb_serial_off: Some(false),
        ..Reading::default()
    }
}

/// A key block never touched: purpose "user" and not write-protected, data
/// empty and open.
fn untouched() -> KeyBlock {
    KeyBlock {
        purpose: 0,
        purpose_locked: false,
        bits: 0,
        locked: false,
    }
}

/// The provisioned M5 as its own firmware read it (the v1.1.0 release build
/// signed with its owner's key): its key's digest in key block 0, both locks
/// burned; key blocks 1 to 5 untouched, purposes never write-protected;
/// Secure Download on.
fn m5() -> Reading {
    let mut keys = [untouched(); KEY_BLOCKS];
    keys[0] = digest(0);
    Reading {
        secure_boot: true,
        pad_jtag_off: true,
        usb_jtag_off: true,
        secure_download: true,
        revoked: [false, true, true],
        keys,
        usb_serial_off: Some(false),
        ..Reading::default()
    }
}

/// Everything judged as it should be, nothing recommended burned.
fn provisioned() -> Reading {
    Reading {
        secure_download: true,
        ..waveshare()
    }
}

/// No holes open.
const NONE: Holes = Holes {
    key_slot: false,
    jtag: false,
    download: false,
};

/// Only download mode open.
const DOWNLOAD: Holes = Holes {
    download: true,
    ..NONE
};

#[test]
fn a_blank_chip_is_blank() {
    assert_eq!(blank().verdict(), Verdict::Blank);
    assert_eq!(blank().verdict().line(), "eFuse: Secure Boot off");
    assert!(!blank().verdict().is_provisioned());
    assert!(!blank().verdict().is_closed());
}

/// **Blank is blank whatever else is burned**: with Secure Boot off any
/// image runs, so no other fuse is judged.
#[test]
fn without_secure_boot_nothing_else_counts() {
    let r = Reading {
        secure_boot: false,
        ..provisioned()
    };
    assert_eq!(r.verdict(), Verdict::Blank);
    let r = Reading {
        secure_boot: false,
        ..waveshare()
    };
    assert_eq!(r.verdict(), Verdict::Blank);
}

/// **The Waveshare, as read, has download mode open and nothing else.**
/// Burned to Secure Download it is provisioned.
#[test]
fn the_waveshare_as_read_has_only_download_open() {
    let w = waveshare();
    assert_eq!(w.verdict(), Verdict::Holes(DOWNLOAD));
    assert_eq!(w.verdict().line(), "Open: download");
    assert!(w.verdict().is_provisioned());
    assert!(!w.verdict().is_closed());
    assert!(!w.digest_slot_open());
    assert_eq!(provisioned().verdict(), Verdict::Provisioned);
    assert_eq!(provisioned().verdict().line(), "eFuse: provisioned");
}

/// **The M5 as read is provisioned.** Its key blocks 1 to 5 could be
/// pointed at slot 0 and filled, but key block 0 comes first with its
/// purpose locked on the slot, and the ROM checks only the first.
#[test]
fn the_m5_as_read_is_provisioned() {
    let m = m5();
    assert_eq!(m.slot(0), Slot::Held(0));
    assert_eq!(m.slot(1), Slot::Revoked);
    assert_eq!(m.slot(2), Slot::Revoked);
    assert!(!m.digest_slot_open());
    assert_eq!(m.verdict(), Verdict::Provisioned);
    assert!(m.verdict().is_closed());
    assert_eq!(m.verdict().line(), "eFuse: provisioned");
    // What its console printed, line for line.
    assert_eq!(m.slot(0).to_string(), "held by KEY0");
    assert_eq!(
        m.keys[0].to_string(),
        "purpose  9 (digest 0), purpose locked, data written, data locked"
    );
    assert_eq!(
        m.keys[1].to_string(),
        "purpose  0 (user), purpose open, data empty, data open"
    );
    let lines: Vec<String> = m.lines().iter().map(|l| l.to_string()).collect();
    assert_eq!(lines[3], "digest slots       closed   required");
    assert_eq!(lines[4], "download mode      secure   required");
}

/// **Each hole, alone, is named alone.**
#[test]
fn each_hole_alone_is_named() {
    type Case = (fn(&mut Reading), Holes, &'static str);
    let jtag = Holes { jtag: true, ..NONE };
    let slot = Holes {
        key_slot: true,
        ..NONE
    };
    let cases: [Case; 5] = [
        (|r| r.pad_jtag_off = false, jtag, "Open: JTAG"),
        (|r| r.usb_jtag_off = false, jtag, "Open: JTAG"),
        // Slot 1's block emptied, its data unlocked as in the fixture.
        (|r| r.keys[1].bits = 0, slot, "Open: key slot"),
        // Slot 0's holder with its purpose unlocked, and a later empty spare
        // whose purpose can still be set.
        (
            |r| {
                r.keys[0].purpose_locked = false;
                r.keys[5].purpose_locked = false;
            },
            slot,
            "Open: key slot",
        ),
        (|r| r.secure_download = false, DOWNLOAD, "Open: download"),
    ];
    for (i, (break_it, holes, line)) in cases.into_iter().enumerate() {
        let mut r = provisioned();
        break_it(&mut r);
        assert_eq!(r.verdict(), Verdict::Holes(holes), "case {i}");
        assert_eq!(r.verdict().line(), line, "case {i}");
    }
}

/// **Every open hole is named, not only the first**, worst first.
#[test]
fn every_open_hole_is_named() {
    let mut r = provisioned();
    r.secure_download = false;
    r.keys[0].purpose_locked = false;
    r.keys[3].purpose_locked = false;
    let both = Holes {
        key_slot: true,
        download: true,
        ..NONE
    };
    assert_eq!(r.verdict(), Verdict::Holes(both));
    assert_eq!(r.verdict().line(), "Open: key slot, download");
    r.usb_jtag_off = false;
    let all = Holes {
        key_slot: true,
        jtag: true,
        download: true,
    };
    assert_eq!(r.verdict(), Verdict::Holes(all));
    assert_eq!(r.verdict().line(), "Open: key slot, JTAG, download");
    r.secure_boot = false;
    assert_eq!(r.verdict(), Verdict::Blank);
}

/// The holes are read the same whether Secure Boot is on or not; only the
/// verdict sets them aside on a blank chip.
#[test]
fn the_holes_do_not_depend_on_secure_boot() {
    let all = Holes {
        key_slot: true,
        jtag: true,
        download: true,
    };
    assert_eq!(blank().holes(), all);
    assert_eq!(provisioned().holes(), NONE);
    assert_eq!(waveshare().holes(), DOWNLOAD);
}

/// Download mode is closed by Secure Download, by download disabled, or by
/// both; by neither it is open.
#[test]
fn download_closes_either_way() {
    for (off, secure, closed) in [
        (false, false, false),
        (true, false, true),
        (false, true, true),
        (true, true, true),
    ] {
        let r = Reading {
            download_off: off,
            secure_download: secure,
            ..provisioned()
        };
        assert_eq!(r.download_closed(), closed, "off {off}, secure {secure}");
        assert_eq!(r.verdict().is_closed(), closed);
    }
}

/// **No recommended or shown fuse moves the verdict**, either way, on a
/// passing unit or a failing one.
#[test]
fn recommended_and_shown_fuses_do_not_judge() {
    let flips: [fn(&mut Reading); 7] = [
        |r| r.direct_boot_off = !r.direct_boot_off,
        |r| r.soft_jtag_off = !r.soft_jtag_off,
        |r| r.aggressive_revoke = !r.aggressive_revoke,
        |r| r.read_protect_locked = !r.read_protect_locked,
        |r| r.force_download_off = !r.force_download_off,
        |r| r.usb_serial_off = Some(true),
        |r| r.usb_serial_off = None,
    ];
    for base in [provisioned(), waveshare(), m5(), blank()] {
        for (i, flip) in flips.iter().enumerate() {
            let mut r = base;
            flip(&mut r);
            assert_eq!(r.verdict(), base.verdict(), "flip {i}");
        }
    }
}

// ── The digest slots ────────────────────────────────────────────────────────

/// A revoked slot is closed whatever could be aimed at it.
#[test]
fn a_revoked_slot_is_closed() {
    let mut r = blank();
    r.revoked = [true; DIGEST_SLOTS];
    for k in 0..DIGEST_SLOTS {
        assert_eq!(r.slot(k), Slot::Revoked);
    }
    assert!(!r.digest_slot_open());
}

/// A blank chip's slots are all open, through its first key block: every
/// purpose is writable and every block empty.
#[test]
fn a_blank_chips_slots_are_open() {
    for k in 0..DIGEST_SLOTS {
        assert_eq!(blank().slot(k), Slot::Open(0));
    }
}

/// **A slot is held only by a block that holds a digest or is locked**: one
/// naming the slot with empty, unlocked data can take someone else's digest.
#[test]
fn a_named_but_empty_block_is_a_door() {
    let mut r = provisioned();
    assert_eq!(r.slot(1), Slot::Held(1));

    r.keys[1].bits = 0;
    r.keys[1].locked = true;
    assert_eq!(
        r.slot(1),
        Slot::Held(1),
        "empty but locked: nothing goes in"
    );

    r.keys[1].locked = false;
    assert_eq!(r.slot(1), Slot::Open(1));
    assert!(r.digest_slot_open());
}

/// **A first holder with its purpose locked closes its slot for good**: a
/// later spare pointed at the slot and filled would never be read, as the
/// ROM checks only the first block naming the slot.
#[test]
fn a_locked_holder_met_first_closes_its_slot() {
    let mut r = provisioned();
    r.keys[4].purpose_locked = false;
    assert_eq!(r.slot(0), Slot::Held(0));
    assert_eq!(r.slot(1), Slot::Held(1));
    assert_eq!(r.slot(2), Slot::Revoked);
    assert!(!r.digest_slot_open());
}

/// **A holder with its purpose unlocked closes nothing**: its purpose can
/// move on, and a later spare, pointed at the slot and filled, becomes the
/// first.
#[test]
fn a_movable_holder_closes_nothing() {
    let mut r = provisioned();
    r.keys[0].purpose_locked = false;
    assert_eq!(r.slot(0), Slot::Held(0), "nothing after it to fill");
    r.keys[4].purpose_locked = false;
    assert_eq!(r.slot(0), Slot::Open(4));
    assert_eq!(r.slot(1), Slot::Held(1), "slot 1's holder is still locked");
    assert_eq!(
        r.verdict(),
        Verdict::Holes(Holes {
            key_slot: true,
            jtag: false,
            download: false,
        })
    );
}

/// **A door before a locked holder counts**: met first, it is the one the
/// ROM would check.
#[test]
fn a_door_before_a_locked_holder_counts() {
    let mut r = provisioned();
    r.keys[0] = untouched();
    r.keys[2] = digest(0);
    assert_eq!(r.slot(0), Slot::Open(0));
    r.keys[0].purpose_locked = true;
    assert_eq!(r.slot(0), Slot::Held(2), "a locked spare reaches nothing");
}

/// **Stray bits are no lock.** A block naming the slot with a few bits set
/// and its data unlocked still takes a digest that covers them, found by
/// trying keys. From [`FILLABLE_BELOW`] bits on, the data is a digest nobody
/// can make their own, locked or not, as a real digest is.
#[test]
fn stray_bits_in_an_unlocked_block_are_a_door() {
    let mut r = provisioned();
    r.keys[1].bits = 3;
    assert_eq!(r.slot(1), Slot::Open(1));
    assert_eq!(r.verdict().line(), "Open: key slot");
    r.keys[1].bits = FILLABLE_BELOW - 1;
    assert_eq!(r.slot(1), Slot::Open(1));
    r.keys[1].bits = FILLABLE_BELOW;
    assert_eq!(r.slot(1), Slot::Held(1));
    r.keys[1].bits = 3;
    r.keys[1].locked = true;
    assert_eq!(r.slot(1), Slot::Held(1), "locked: nothing more goes in");
    assert_eq!(r.verdict(), Verdict::Provisioned);
    // The console says written for any bit set, whatever the threshold.
    assert_eq!(
        r.keys[1].to_string(),
        "purpose 10 (digest 1), purpose locked, data written, data locked"
    );
}

/// A writable purpose over written data is no door: the ROM would check
/// that data, which nobody can make their own.
#[test]
fn a_writable_purpose_over_written_data_is_no_door() {
    let mut r = provisioned();
    r.revoked = [false; DIGEST_SLOTS];
    r.keys[3] = KeyBlock {
        purpose: 0,
        purpose_locked: false,
        bits: DIGEST_BITS,
        locked: false,
    };
    assert_eq!(r.slot(0), Slot::Held(0));
    assert_eq!(r.slot(1), Slot::Held(1));
    assert_eq!(r.slot(2), Slot::Unused);
    assert!(!r.digest_slot_open());
}

/// **A purpose only gains bits.** From 2 a block reaches digest 1 and 2 (10
/// and 11), never digest 0 (9); from 8 it reaches all three; from 4 none.
#[test]
fn a_purpose_reaches_only_its_supersets() {
    let open_slots = |purpose: u8| -> [bool; DIGEST_SLOTS] {
        let mut r = blank();
        r.keys = [spare(); KEY_BLOCKS];
        r.keys[2] = KeyBlock {
            purpose,
            purpose_locked: false,
            bits: 0,
            locked: false,
        };
        [0, 1, 2].map(|k| r.slot(k) == Slot::Open(2))
    };
    assert_eq!(open_slots(0), [true, true, true]);
    assert_eq!(open_slots(1), [true, false, true]);
    assert_eq!(open_slots(2), [false, true, true]);
    assert_eq!(open_slots(3), [false, false, true]);
    assert_eq!(open_slots(4), [false, false, false]);
    assert_eq!(open_slots(8), [true, true, true]);
    assert_eq!(open_slots(9), [true, false, true]);
    assert_eq!(open_slots(12), [false, false, false]);
}

/// A locked purpose reaches only the slot it already names.
#[test]
fn a_locked_purpose_reaches_only_its_own_slot() {
    let mut r = blank();
    r.keys = [spare(); KEY_BLOCKS];
    r.keys[3] = KeyBlock {
        purpose: PURPOSE_DIGEST + 2,
        purpose_locked: true,
        bits: 0,
        locked: false,
    };
    assert_eq!(r.slot(0), Slot::Unused);
    assert_eq!(r.slot(1), Slot::Unused);
    assert_eq!(r.slot(2), Slot::Open(3));
}

/// A digest is found in whichever block it sits.
#[test]
fn a_digest_is_found_wherever_it_sits() {
    let mut r = provisioned();
    r.revoked = [false; DIGEST_SLOTS];
    r.keys = [spare(), spare(), spare(), digest(2), digest(0), digest(1)];
    assert_eq!(r.slot(0), Slot::Held(4));
    assert_eq!(r.slot(1), Slot::Held(5));
    assert_eq!(r.slot(2), Slot::Held(3));
    assert_eq!(r.verdict(), Verdict::Provisioned);
}

/// A slot past the last reads as revoked, not as a panic.
#[test]
fn a_slot_past_the_last_is_revoked() {
    assert_eq!(blank().slot(DIGEST_SLOTS), Slot::Revoked);
}

// ── What the console shows ──────────────────────────────────────────────────

/// **Every verdict's line is distinct and fits the screen's 30
/// characters**: all eight hole sets, blank and provisioned.
#[test]
fn every_verdict_line_fits() {
    let mut lines = vec![Verdict::Blank.line(), Verdict::Provisioned.line()];
    for bits in 1u8..8 {
        let holes = Holes {
            key_slot: bits & 1 != 0,
            jtag: bits & 2 != 0,
            download: bits & 4 != 0,
        };
        assert!(holes.any());
        let line = Verdict::Holes(holes).line();
        assert!(line.starts_with("Open: "), "{line:?}");
        assert_eq!(line.contains("key slot"), holes.key_slot, "{line:?}");
        assert_eq!(line.contains("JTAG"), holes.jtag, "{line:?}");
        assert_eq!(line.contains("download"), holes.download, "{line:?}");
        lines.push(line);
    }
    assert!(!NONE.any());
    assert_eq!(NONE.line(), "");
    for line in &lines {
        assert!(line.len() <= 30, "{line:?} is {} characters", line.len());
    }
    let mut unique = lines.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), lines.len(), "every line distinct");
}

/// **The judged lines agree with the verdict**: on every fixture Secure
/// Boot's line holds exactly when the unit is not blank, and with Secure
/// Boot on the other required lines that fail are exactly its holes.
#[test]
fn the_lines_agree_with_the_verdict() {
    let mut jtag = provisioned();
    jtag.pad_jtag_off = false;
    for r in [blank(), waveshare(), m5(), provisioned(), jtag] {
        let lines = r.lines();
        assert_eq!(lines.len(), LINES);
        let required: Vec<&Line> = lines
            .iter()
            .filter(|l| l.weight == Weight::Required)
            .collect();
        assert_eq!(required.len(), 5, "Secure Boot, two JTAG, slots, download");
        assert!(lines[..5].iter().all(|l| l.weight == Weight::Required));
        let missing = |what: &str| required.iter().any(|l| l.what == what && !l.holds);
        assert_eq!(missing("secure boot"), r.verdict() == Verdict::Blank);
        let holes = Holes {
            key_slot: missing("digest slots"),
            jtag: missing("JTAG by pad") || missing("JTAG by USB"),
            download: missing("download mode"),
        };
        match r.verdict() {
            Verdict::Blank => {}
            Verdict::Provisioned => assert!(!holes.any()),
            Verdict::Holes(open) => assert_eq!(open, holes),
        }
    }
}

/// What the console prints, character for character, for the Waveshare.
#[test]
fn the_waveshare_report_reads_as_expected() {
    let w = waveshare();
    let lines: Vec<String> = w.lines().iter().map(|l| l.to_string()).collect();
    assert_eq!(lines[0], "secure boot        on       required");
    assert_eq!(lines[4], "download mode      OPEN     required, MISSING");
    assert_eq!(
        lines[5],
        "direct boot        on       recommended, not burned"
    );
    assert_eq!(lines[10].trim_end(), "USB serial         on");
    assert_eq!(w.slot(0).to_string(), "held by KEY0");
    assert_eq!(w.slot(2).to_string(), "revoked");
    assert_eq!(
        w.keys[0].to_string(),
        "purpose  9 (digest 0), purpose locked, data written, data open"
    );
    assert_eq!(
        w.keys[2].to_string(),
        "purpose  0 (user), purpose locked, data empty, data open"
    );
    let mut r = provisioned();
    r.keys[0].purpose_locked = false;
    r.keys[4].purpose_locked = false;
    assert_eq!(r.slot(0).to_string(), "OPEN through KEY4");
}

/// The P4 has no USB Serial/JTAG disable fuse, and says so.
#[test]
fn a_fuse_the_chip_lacks_reads_not_applicable() {
    let r = Reading {
        usb_serial_off: None,
        ..provisioned()
    };
    assert_eq!(r.lines()[10].state, "n/a");
}

// ── The trait ───────────────────────────────────────────────────────────────

/// A board reads and this crate judges: a board's reader gets
/// [`Provisioning::verdict`] without writing one.
#[test]
fn a_reader_gets_the_verdict_for_free() {
    struct Bench(Reading);
    impl Provisioning for Bench {
        fn read(&self) -> Reading {
            self.0
        }
    }
    assert_eq!(Bench(waveshare()).verdict(), waveshare().verdict());
    assert_eq!(Bench(m5()).verdict(), Verdict::Provisioned);
}
