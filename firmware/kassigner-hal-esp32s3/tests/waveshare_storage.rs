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

//! What the storage wrapper relies on, checked without a card: what an
//! unknown card size means for the bounds check, and the capacity a CSD
//! gives. The SDHOST registers cannot run here.

#![cfg(feature = "waveshare")]

use kassigner_fat32::block::{BlockDevice, Error, BLOCK_SIZE};
use kassigner_fat32::fat32::{csd_plausible, csd_sectors};

/// An unknown card size is not an empty card: a card that did not answer
/// CMD9 leaves `blocks()` zero, which means unchecked. Empty would refuse
/// every access on a card that works.
#[test]
fn an_unknown_size_skips_the_bounds_check() {
    struct Unsized;
    impl BlockDevice for Unsized {
        fn blocks(&self) -> u32 {
            0
        }
        fn read(&mut self, _b: u32, _buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
            Ok(())
        }
        fn write(&mut self, _b: u32, _d: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
            Ok(())
        }
    }
    let d = Unsized;
    assert!(d.check_range(0, 1).is_ok());
    assert!(
        d.check_range(u32::MAX - 1, 1).is_ok(),
        "unknown means unchecked"
    );
}

/// A known size is checked, and the last block that fits is allowed.
#[test]
fn a_known_size_is_checked_at_the_edge() {
    struct Sized_(u32);
    impl BlockDevice for Sized_ {
        fn blocks(&self) -> u32 {
            self.0
        }
        fn read(&mut self, _b: u32, _buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
            Ok(())
        }
        fn write(&mut self, _b: u32, _d: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
            Ok(())
        }
    }
    let d = Sized_(1000);
    assert!(d.check_range(999, 1).is_ok(), "the last block");
    assert!(d.check_range(1000, 1).is_err(), "one past it");
    assert!(d.check_range(996, 4).is_ok());
    assert!(d.check_range(997, 4).is_err());
}

/// A v2 CSD gives a capacity, and a real card's is plausible.
#[test]
fn the_csd_gives_a_capacity() {
    // A v2 CSD: the top two bits of byte 0 select the version, and for v2 the
    // capacity is `(C_SIZE + 1) * 1024` sectors from bits 69:48.
    let mut csd = [0u8; 16];
    csd[0] = 0x40; // CSD version 2
                   // C_SIZE = 15271, 8 GB: (15271 + 1) * 1024 = 15,638,528
    csd[7] = 0x00;
    csd[8] = 0x3B;
    csd[9] = 0xA7;
    let sectors = csd_sectors(&csd).expect("v2 CSD");
    assert_eq!(sectors, (0x3BA7 + 1) * 1024);
    assert!(csd_plausible(sectors));
}

/// A capacity that cannot be right, zero or too small for any card, is
/// refused: a wrong capacity is worse than none.
#[test]
fn an_implausible_capacity_is_refused() {
    assert!(!csd_plausible(0));

    // A v2 CSD with C_SIZE zero: 1024 sectors, half a megabyte. No SD card is
    // that small.
    let mut tiny = [0u8; 16];
    tiny[0] = 0x40;
    let sectors = csd_sectors(&tiny).expect("parses");
    assert_eq!(sectors, 1024);
    assert!(!csd_plausible(sectors), "half a megabyte is not a card");
}
