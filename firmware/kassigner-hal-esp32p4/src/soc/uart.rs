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

//! Raw UART0 output.
//!
//! Not through esp-println or anything that takes a lock: nothing that
//! acquires a critical section may run before `esp_hal::init()`. The
//! bootloader leaves UART0 configured, with a 128-byte FIFO, so a bare store
//! is enough.

const UART0: u32 = 0x500C_A000;
const UART0_FIFO: *mut u32 = UART0 as *mut u32;
/// status +0x1c, txfifo_cnt `[23:16]`. The FIFO is 128 bytes.
const UART0_STATUS: *const u32 = (UART0 + 0x1c) as *const u32;
const TXFIFO_HIGH_WATER: u32 = 100;

#[inline(always)]
/// One byte to UART0, without waiting for FIFO space. No locks.
pub fn putc(c: u8) {
    // SAFETY: one volatile write to UART0's FIFO register, at its fixed
    // address. Debug output: a byte lost to a full FIFO is only lost.
    unsafe { core::ptr::write_volatile(UART0_FIFO, c as u32) }
}

/// Wait for UART0's FIFO to empty, bounded as [`putc_blocking`] is so a
/// stalled UART never wedges the caller. The byte left in the shifter is the
/// caller's to wait for, as the console's close does.
pub fn drain() {
    // SAFETY: volatile reads of UART0's status register, at its fixed address.
    unsafe {
        let mut spins = 0u32;
        while ((core::ptr::read_volatile(UART0_STATUS) >> 16) & 0xff) != 0 {
            spins += 1;
            if spins > 10_000_000 {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Like `putc`, but waits for FIFO space first. `putc` drops bytes under
/// sustained output, which in an entropy dump would look like bad
/// randomness: bulk writers use this.
#[inline]
pub fn putc_blocking(c: u8) {
    // SAFETY: volatile reads of UART0's status register and one write to its
    // FIFO register, at fixed addresses.
    unsafe {
        let mut spins = 0u32;
        while ((core::ptr::read_volatile(UART0_STATUS) >> 16) & 0xff) > TXFIFO_HIGH_WATER {
            spins += 1;
            if spins > 10_000_000 {
                break; // never wedge on a stalled UART
            }
            core::hint::spin_loop();
        }
        core::ptr::write_volatile(UART0_FIFO, c as u32);
    }
}

/// Bulk write with flow control.
pub fn write_bytes(b: &[u8]) {
    for x in b {
        putc_blocking(*x);
    }
}

/// A string to UART0.
pub fn puts(s: &str) {
    for b in s.as_bytes() {
        putc(*b);
    }
}

/// `0x` + 8 hex digits.
pub fn puthex(v: u32) {
    puts("0x");
    for sh in (0..8).rev() {
        let n = ((v >> (sh * 4)) & 0xF) as u8;
        putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
    }
}

/// 2 hex digits, no prefix.
pub fn puthex8(v: u8) {
    for sh in [4u8, 0] {
        let n = (v >> sh) & 0xF;
        putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
    }
}

/// Unsigned decimal.
pub fn putdec(v: u32) {
    if v >= 10 {
        putdec(v / 10);
    }
    putc(b'0' + (v % 10) as u8);
}

/// `label = 0x........` followed by CRLF.
pub fn line(label: &str, v: u32) {
    puts(label);
    puts(" = ");
    puthex(v);
    puts("\r\n");
}

/// Print a u32 as four ASCII characters. Synopsys cores report their version
/// this way: the CSI-2 host reads 0x3135302a = "150*", dw_gdma "200*".
pub fn put_ascii(v: u32) {
    puts("\"");
    for sh in [24u32, 16, 8, 0] {
        let c = ((v >> sh) & 0xff) as u8;
        putc(if (0x20..0x7f).contains(&c) { c } else { b'.' });
    }
    puts("\"");
}
