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

//! The S3's eFuse registers decoded, without a chip.
//!
//! What the fuses mean is tested in `kassigner-hal`'s
//! `tests/provisioning.rs`; what is the S3's own is where each fuse sits.
//! Each case sets one bit or field in otherwise zero registers and checks
//! that exactly the fuse the TRM puts there changes: a wrong address or
//! shift reads a real fuse as another, and looks fine until measured.

use kassigner_hal::provisioning::{Holes, KeyBlock, Reading, Verdict, KEY_BLOCKS, PURPOSE_DIGEST};
use kassigner_hal_esp32s3::efuse::{decode, Words};

/// All-zero registers: a factory-blank S3, its USB Serial/JTAG fuse present
/// and unburned.
fn zero() -> Reading {
    Reading {
        usb_serial_off: Some(false),
        ..Reading::default()
    }
}

/// Registers with one bit of one `RD_REPEAT_DATAn` set.
fn repeat_bit(n: usize, bit: u32) -> Words {
    let mut w = Words::default();
    w.repeat[n] = 1 << bit;
    w
}

#[test]
fn zero_registers_are_a_blank_chip() {
    assert_eq!(decode(&Words::default()), zero());
}

/// Each single-bit fuse is where TRM Registers 5.13 to 5.16 put it, and
/// setting it changes that fuse only.
#[test]
fn each_fuse_bit_is_where_the_trm_puts_it() {
    type Case = (&'static str, usize, u32, fn(&mut Reading));
    let cases: [Case; 13] = [
        ("DIS_FORCE_DOWNLOAD", 0, 12, |r| r.force_download_off = true),
        ("DIS_PAD_JTAG", 0, 19, |r| r.pad_jtag_off = true),
        ("SECURE_BOOT_KEY_REVOKE0", 1, 21, |r| r.revoked[0] = true),
        ("SECURE_BOOT_KEY_REVOKE1", 1, 22, |r| r.revoked[1] = true),
        ("SECURE_BOOT_KEY_REVOKE2", 1, 23, |r| r.revoked[2] = true),
        ("SECURE_BOOT_EN", 2, 20, |r| r.secure_boot = true),
        ("SECURE_BOOT_AGGRESSIVE_REVOKE", 2, 21, |r| {
            r.aggressive_revoke = true
        }),
        ("DIS_USB_JTAG", 2, 22, |r| r.usb_jtag_off = true),
        ("DIS_USB_SERIAL_JTAG", 2, 23, |r| {
            r.usb_serial_off = Some(true)
        }),
        ("DIS_DOWNLOAD_MODE", 3, 0, |r| r.download_off = true),
        ("DIS_LEGACY_SPI_BOOT", 3, 1, |r| r.direct_boot_off = true),
        ("ENABLE_SECURITY_DOWNLOAD", 3, 5, |r| {
            r.secure_download = true
        }),
        // A neighbour that must read as nothing: bit 4 is not a fuse this
        // module reads.
        ("DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE", 3, 4, |_| ()),
    ];
    for (name, n, bit, expect) in cases {
        let mut want = zero();
        expect(&mut want);
        assert_eq!(decode(&repeat_bit(n, bit)), want, "{name}");
    }
}

/// `SOFT_DIS_JTAG` is three bits, 18:16, and an odd count of them disables.
#[test]
fn soft_jtag_counts_its_bits() {
    for (field, off) in [
        (0b000, false),
        (0b001, true),
        (0b010, true),
        (0b011, false),
        (0b100, true),
        (0b111, true),
    ] {
        let mut w = Words::default();
        w.repeat[0] = field << 16;
        assert_eq!(decode(&w).soft_jtag_off, off, "{field:03b}");
    }
    // The bits on either side are other fuses.
    assert!(!decode(&repeat_bit(0, 15)).soft_jtag_off);
    assert!(!decode(&repeat_bit(0, 19)).soft_jtag_off);
}

/// The six key purposes are four bits each where Registers 5.14 and 5.15
/// put them: 0 and 1 in `DATA1`'s top byte, 2 to 5 in `DATA2`'s low half.
#[test]
fn the_key_purposes_are_where_the_trm_puts_them() {
    let mut w = Words::default();
    w.repeat[1] = (9 << 24) | (10 << 28);
    w.repeat[2] = 11 | (1 << 4) | (2 << 8) | (3 << 12);
    let r = decode(&w);
    let purposes = r.keys.map(|k| k.purpose);
    assert_eq!(purposes, [9, 10, 11, 1, 2, 3]);
    // Nothing else read from those nibbles.
    assert_eq!(
        Reading {
            keys: [KeyBlock::default(); KEY_BLOCKS],
            ..r
        },
        zero()
    );
}

/// `WR_DIS` locks what Tables 5-1 and 5-3 say: bit 0 the read-disable
/// field, bits 8 to 13 the purposes, bits 23 to 28 the key data.
#[test]
fn write_protection_bits_are_where_the_trm_puts_them() {
    let w = Words {
        wr_dis: 1,
        ..Words::default()
    };
    assert_eq!(
        decode(&w),
        Reading {
            read_protect_locked: true,
            ..zero()
        }
    );
    for i in 0..KEY_BLOCKS {
        let purpose = decode(&Words {
            wr_dis: 1 << (8 + i),
            ..Words::default()
        });
        let data = decode(&Words {
            wr_dis: 1 << (23 + i),
            ..Words::default()
        });
        for j in 0..KEY_BLOCKS {
            assert_eq!(
                purpose.keys[j].purpose_locked,
                i == j,
                "purpose {i}, block {j}"
            );
            assert!(!purpose.keys[j].locked);
            assert_eq!(data.keys[j].locked, i == j, "data {i}, block {j}");
            assert!(!data.keys[j].purpose_locked);
        }
    }
}

/// A key block counts as written when any of its eight words has a bit set,
/// and only that block; its bits are counted across all eight words.
#[test]
fn any_set_bit_writes_only_its_own_block() {
    for i in 0..KEY_BLOCKS {
        for word in [0, 7] {
            let mut w = Words::default();
            w.keys[i][word] = 1 << 31;
            let r = decode(&w);
            for j in 0..KEY_BLOCKS {
                assert_eq!(r.keys[j].written(), i == j, "block {i} word {word}");
                assert_eq!(r.keys[j].bits, u32::from(i == j), "block {i} word {word}");
            }
        }
        let mut w = Words::default();
        w.keys[i] = [0xFFFF_FFFF, 0, 0, 0, 0, 0, 0, 0x8000_0001];
        assert_eq!(decode(&w).keys[i].bits, 34, "block {i}");
    }
}

/// End to end: a Waveshare unit's registers, as its fuse summary read them,
/// decode to its verdict, download mode open; with secure download burned,
/// provisioned.
#[test]
fn the_waveshare_registers_decode_to_its_verdict() {
    let digest = [0xb136_7b78; 8];
    let mut w = Words {
        // Every purpose write-protected, no key data locked.
        wr_dis: 0b11_1111 << 8,
        repeat: [
            1 << 19,
            (1 << 23) | (u32::from(PURPOSE_DIGEST) << 24) | (u32::from(PURPOSE_DIGEST + 1) << 28),
            (1 << 20) | (1 << 22),
            0,
        ],
        keys: [digest, digest, [0; 8], [0; 8], [0; 8], [0; 8]],
    };
    let r = decode(&w);
    let download = Holes {
        key_slot: false,
        jtag: false,
        download: true,
    };
    assert_eq!(r.verdict(), Verdict::Holes(download));
    w.repeat[3] = 1 << 5;
    assert_eq!(decode(&w).verdict(), Verdict::Provisioned);
}
