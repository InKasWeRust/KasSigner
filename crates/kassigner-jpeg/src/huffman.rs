// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Huffman tables and their bit streams (T.81 annexes C and F).
//!
//! A table is sixteen counts (codes of each length, 1 to 16 bits) and the
//! symbols in code order; the codes are canonical (C.2). Decoding (F.2.2.3)
//! reads a bit at a time against each length's largest code; encoding (C.3)
//! looks the code up by symbol.

use crate::Error;

/// One table, decode and encode sides built together.
#[derive(Clone, Copy)]
pub struct Table {
    present: bool,
    /// Largest code of each length, `-1` for a length with no codes.
    maxcode: [i32; 17],
    /// First code of each length.
    mincode: [i32; 17],
    /// Index into `symbols` of the first symbol of each length.
    first: [u16; 17],
    symbols: [u8; 256],
    /// Code and its length by symbol; length 0 is a symbol the table lacks.
    code: [u16; 256],
    length: [u8; 256],
}

impl Table {
    pub const EMPTY: Table = Table {
        present: false,
        maxcode: [-1; 17],
        mincode: [0; 17],
        first: [0; 17],
        symbols: [0; 256],
        code: [0; 256],
        length: [0; 256],
    };

    /// Whether a DHT segment defined this table.
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Build from a DHT entry's counts and symbols, in place (a table is
    /// about 1.2 KB).
    ///
    /// # Errors
    ///
    /// `Malformed` for more than 256 symbols, fewer symbols than the counts
    /// claim, or codes that do not fit their length. The table is then
    /// empty.
    pub fn build(&mut self, counts: &[u8; 16], symbols: &[u8]) -> Result<(), Error> {
        *self = Table::EMPTY;
        let total: usize = counts.iter().map(|&c| usize::from(c)).sum();
        if total > 256 || symbols.len() < total {
            return Err(Error::Malformed);
        }
        let t = self;
        t.symbols[..total].copy_from_slice(&symbols[..total]);
        let mut code: i32 = 0;
        let mut k: usize = 0;
        for len in 1..=16usize {
            let n = i32::from(counts[len - 1]);
            if n == 0 {
                t.maxcode[len] = -1;
            } else {
                // Every code of this length must fit in it.
                if code + n > (1 << len) {
                    *t = Table::EMPTY;
                    return Err(Error::Malformed);
                }
                t.first[len] = k as u16;
                t.mincode[len] = code;
                for i in 0..n {
                    let s = usize::from(t.symbols[k + i as usize]);
                    t.code[s] = (code + i) as u16;
                    t.length[s] = len as u8;
                }
                k += n as usize;
                code += n;
                t.maxcode[len] = code - 1;
            }
            code <<= 1;
        }
        t.present = true;
        Ok(())
    }

    /// Decode one symbol.
    pub fn decode(&self, r: &mut Reader<'_>) -> Result<u8, Error> {
        let mut code: i32 = r.bit() as i32;
        for len in 1..=16usize {
            if self.maxcode[len] >= 0 && code <= self.maxcode[len] {
                let i = i32::from(self.first[len]) + code - self.mincode[len];
                return self
                    .symbols
                    .get(usize::try_from(i).map_err(|_| Error::Malformed)?)
                    .copied()
                    .ok_or(Error::Malformed);
            }
            code = (code << 1) | r.bit() as i32;
        }
        Err(Error::Malformed)
    }

    /// Encode one symbol.
    ///
    /// # Errors
    ///
    /// `Unencodable` for a symbol the table has no code for.
    pub fn encode(&self, w: &mut Writer<'_>, symbol: u8) -> Result<(), Error> {
        let len = self.length[usize::from(symbol)];
        if len == 0 {
            return Err(Error::Unencodable);
        }
        w.bits(u32::from(self.code[usize::from(symbol)]), u32::from(len));
        Ok(())
    }
}

/// Reads bits from entropy-coded data, unstuffing the zero byte after each
/// `0xFF` (F.1.2.3).
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    byte: u32,
    left: u32,
    /// A bit was asked for past the end ([`crate::Error::Truncated`]).
    over: bool,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader {
            data,
            pos: 0,
            byte: 0,
            left: 0,
            over: false,
        }
    }

    /// Whether a bit was ever fabricated past the end of the data.
    pub const fn overran(&self) -> bool {
        self.over
    }

    #[inline]
    pub fn bit(&mut self) -> u32 {
        if self.left == 0 {
            if self.pos >= self.data.len() {
                self.over = true;
                return 0;
            }
            let b = self.data[self.pos];
            self.pos += 1;
            if b == 0xFF && self.pos < self.data.len() && self.data[self.pos] == 0x00 {
                self.pos += 1;
            }
            self.byte = u32::from(b);
            self.left = 8;
        }
        self.left -= 1;
        (self.byte >> self.left) & 1
    }

    /// The next `n` bits, most significant first.
    #[inline]
    pub fn bits(&mut self, n: u32) -> i32 {
        let mut v: i32 = 0;
        for _ in 0..n {
            v = (v << 1) | self.bit() as i32;
        }
        v
    }

    /// Drop the rest of the current byte and move past the next restart
    /// marker (F.2.2.5).
    pub fn restart(&mut self) {
        self.left = 0;
        while self.pos + 1 < self.data.len() {
            if self.data[self.pos] == 0xFF && matches!(self.data[self.pos + 1], 0xD0..=0xD7) {
                self.pos += 2;
                return;
            }
            self.pos += 1;
        }
        self.pos = self.data.len();
    }
}

/// Writes bits into entropy-coded data, stuffing a zero byte after each
/// `0xFF` (F.1.2.3).
pub struct Writer<'o> {
    out: &'o mut [u8],
    pos: usize,
    byte: u32,
    filled: u32,
    overflow: bool,
}

impl<'o> Writer<'o> {
    pub fn new(out: &'o mut [u8]) -> Self {
        Writer {
            out,
            pos: 0,
            byte: 0,
            filled: 0,
            overflow: false,
        }
    }

    /// Bytes written so far, the partial byte not counted.
    pub const fn written(&self) -> usize {
        self.pos
    }

    /// Whether anything did not fit.
    pub const fn overflowed(&self) -> bool {
        self.overflow
    }

    /// A whole byte, as it is: for markers.
    pub fn byte(&mut self, b: u8) {
        if self.pos < self.out.len() {
            self.out[self.pos] = b;
            self.pos += 1;
        } else {
            self.overflow = true;
        }
    }

    #[inline]
    pub fn bit(&mut self, v: u32) {
        self.byte = (self.byte << 1) | (v & 1);
        self.filled += 1;
        if self.filled == 8 {
            let b = self.byte as u8;
            self.byte(b);
            if b == 0xFF {
                self.byte(0x00);
            }
            self.byte = 0;
            self.filled = 0;
        }
    }

    /// `n` bits of `v`, most significant first.
    #[inline]
    pub fn bits(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit((v >> i) & 1);
        }
    }

    /// Pad the partial byte with one bits (F.1.2.3) and write it.
    pub fn flush(&mut self) {
        while self.filled != 0 {
            self.bit(1);
        }
    }

    /// Flush, then a restart marker `RSTn`.
    pub fn restart(&mut self, n: u8) {
        self.flush();
        self.byte(0xFF);
        self.byte(0xD0 + (n & 7));
    }
}
