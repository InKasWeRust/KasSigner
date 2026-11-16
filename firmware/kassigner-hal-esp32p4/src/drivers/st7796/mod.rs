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

//! ST7796 panel driver, 320x480 over SPI. Command tables and timing are in
//! [`cmds`]; this is the transport and the drawing surface.
//!
//! Every drawing entry point clips to the panel, except `push_pixels`,
//! which refuses a rectangle not wholly on it, since clipping would skew its
//! rows; `window` expects on-panel coordinates. With `overflow-checks` on in
//! release, an unclipped `LCD_W - x0` with `x0 >= LCD_W` panics instead of
//! drawing nothing.

pub mod cmds;
mod eg;

use crate::board::{LCD_H, LCD_W};
use cmds::{cmd, colour, InitCmd, COLMOD_RGB565, INIT, MADCTL_DEFAULT};
use esp_hal::{
    delay::Delay,
    dma::DmaTxBuf,
    gpio::Output,
    spi::master::{SpiDma, SpiDmaTransfer},
    Blocking,
};

/// ST7796 over SPI2 with DC/CS/RST/BL on GPIO.
pub struct Display<'d> {
    /// The bus, between transfers.
    spi: Option<SpiDma<'d, Blocking>>,
    /// The DMA buffer, between transfers.
    buf: Option<DmaTxBuf>,
    /// The last pixels of a blit, still going out while the caller draws
    /// its next band. Every other use of the bus lands them first.
    flight: Option<SpiDmaTransfer<'d, Blocking, DmaTxBuf>>,
    dc: Output<'d>,
    cs: Output<'d>,
    rst: Output<'d>,
    bl: Output<'d>,
}

impl<'d> Display<'d> {
    /// Wrap the SPI bus and control pins. Call `init()` next.
    pub fn new(
        spi: SpiDma<'d, Blocking>,
        buf: DmaTxBuf,
        dc: Output<'d>,
        cs: Output<'d>,
        rst: Output<'d>,
        bl: Output<'d>,
    ) -> Self {
        Self {
            spi: Some(spi),
            buf: Some(buf),
            flight: None,
            dc,
            cs,
            rst,
            bl,
        }
    }

    /// Wait for pixels still going out, and take the bus and buffer back.
    fn land(&mut self) {
        if let Some(flight) = self.flight.take() {
            let (spi, buf) = flight.wait();
            self.spi = Some(spi);
            self.buf = Some(buf);
        }
    }

    /// End whatever was being sent: land it and release the panel.
    fn end(&mut self) {
        self.land();
        self.cs.set_high();
    }

    /// Start sending what the buffer holds, `len` bytes, and leave it going.
    fn start(&mut self, len: usize) {
        if let (Some(spi), Some(buf)) = (self.spi.take(), self.buf.take()) {
            match spi.write_buffer(len, buf) {
                Ok(flight) => self.flight = Some(flight),
                Err((_, spi, buf)) => {
                    self.spi = Some(spi);
                    self.buf = Some(buf);
                }
            }
        }
    }

    /// Send `bytes` and wait for them, a buffer at a time.
    fn send(&mut self, bytes: &[u8]) {
        let cap = self.buf.as_ref().map_or(0, DmaTxBuf::capacity);
        if cap == 0 {
            return;
        }
        for part in bytes.chunks(cap) {
            self.land();
            if let Some(buf) = self.buf.as_mut() {
                buf.as_mut_slice()[..part.len()].copy_from_slice(part);
                buf.set_length(part.len());
            }
            self.start(part.len());
        }
        self.land();
    }

    fn cmd(&mut self, c: u8) {
        self.end();
        self.dc.set_low();
        self.cs.set_low();
        self.send(&[c]);
        self.cs.set_high();
    }

    fn data(&mut self, d: &[u8]) {
        if d.is_empty() {
            return;
        }
        self.end();
        self.dc.set_high();
        self.cs.set_low();
        self.send(d);
        self.cs.set_high();
    }

    /// Full init, as esp-bsp's `esp_lcd_st7796_general.c`.
    pub fn init(&mut self, delay: &Delay) {
        self.rst.set_low();
        delay.delay_millis(cmds::RESET_LOW_MS);
        self.rst.set_high();
        delay.delay_millis(cmds::RESET_HIGH_MS);

        self.cmd(cmd::SLPOUT);
        delay.delay_millis(cmds::SLPOUT_MS);

        self.cmd(cmd::MADCTL);
        self.data(&[MADCTL_DEFAULT]);
        self.cmd(cmd::COLMOD);
        self.data(&[COLMOD_RGB565]);

        for InitCmd(c, d) in INIT {
            self.cmd(*c);
            self.data(d);
        }

        // Without it every colour is inverted (see `cmds`).
        self.cmd(cmd::INVON);
        delay.delay_millis(10);

        self.cmd(cmd::DISPON);
        delay.delay_millis(50);
    }

    /// Backlight full on or off by the pin's level. No effect once
    /// `crate::backlight::init` has handed the pin to the LEDC for dimming.
    pub fn backlight(&mut self, on: bool) {
        if on {
            self.bl.set_high();
        } else {
            self.bl.set_low();
        }
    }

    /// Whether a rectangle is not empty and lies wholly on the panel.
    fn on_panel(x: u16, y: u16, w: u16, h: u16) -> bool {
        w != 0
            && h != 0
            && u32::from(x) + u32::from(w) <= u32::from(LCD_W)
            && u32::from(y) + u32::from(h) <= u32::from(LCD_H)
    }

    /// Clip a rectangle to the panel. `None` if nothing is left.
    fn clip(x: u16, y: u16, w: u16, h: u16) -> Option<(u16, u16, u16, u16)> {
        if x >= LCD_W || y >= LCD_H || w == 0 || h == 0 {
            return None;
        }
        let w = w.min(LCD_W - x);
        let h = h.min(LCD_H - y);
        Some((x, y, w, h))
    }

    /// Set the drawing window, inclusive and already on the panel, and
    /// leave the panel expecting pixels.
    pub fn window(&mut self, x0: u16, y0: u16, x1: u16, y1: u16) {
        self.cmd(cmd::CASET);
        self.data(&[(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8]);
        self.cmd(cmd::RASET);
        self.data(&[(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8]);
        self.cmd(cmd::RAMWR);
    }

    /// Push one colour `count` times. HIGH byte first.
    pub fn push_colour(&mut self, c: u16, count: u32) {
        self.end();
        let hi = (c >> 8) as u8;
        let lo = c as u8;
        let mut chunk = [0u8; 512];
        for i in 0..256 {
            chunk[i * 2] = hi;
            chunk[i * 2 + 1] = lo;
        }
        self.dc.set_high();
        self.cs.set_low();
        let mut sent = 0u32;
        while sent < count {
            let n = if count - sent >= 256 {
                256
            } else {
                count - sent
            };
            self.send(&chunk[..(n as usize * 2)]);
            sent += n;
        }
        self.cs.set_high();
    }

    /// Write `w * h` RGB565 pixels, row-major, into a window: the trait
    /// layer's `blit`. A rectangle not wholly on the panel, or a slice
    /// shorter than it, draws nothing: clipping it would skew the rows.
    pub fn push_pixels(&mut self, x0: u16, y0: u16, w: u16, h: u16, pixels: &[u16]) {
        if !Self::on_panel(x0, y0, w, h) {
            return;
        }
        let count = w as usize * h as usize;
        if pixels.len() < count {
            return;
        }
        self.window(x0, y0, x0 + w - 1, y0 + h - 1);
        let room = self.buf.as_ref().map_or(0, DmaTxBuf::capacity) / 2;
        if room == 0 {
            return;
        }
        self.dc.set_high();
        self.cs.set_low();
        // Byte-swapped into the DMA buffer, each part sent while the next
        // is filled. The last is left going, the panel selected, for the
        // next use of the bus to land: a full redraw takes 53 ms to send at
        // 80 MHz, time the caller spends drawing.
        for part in pixels[..count].chunks(room) {
            self.land();
            if let Some(buf) = self.buf.as_mut() {
                for (pair, &c) in buf.as_mut_slice().chunks_exact_mut(2).zip(part) {
                    pair[0] = (c >> 8) as u8;
                    pair[1] = c as u8;
                }
                buf.set_length(part.len() * 2);
            }
            self.start(part.len() * 2);
        }
    }

    /// Draw a grey image into a window, clipped, from `sample(x, y)`: one
    /// SPI transfer per row, not per pixel.
    pub fn blit_grey(
        &mut self,
        x0: u16,
        y0: u16,
        w: u16,
        h: u16,
        mut sample: impl FnMut(u32, u32) -> u8,
    ) {
        let Some((x0, y0, w, h)) = Self::clip(x0, y0, w, h) else {
            return;
        };
        self.window(x0, y0, x0 + w - 1, y0 + h - 1);
        let mut row = [0u8; LCD_W as usize * 2];
        self.dc.set_high();
        self.cs.set_low();
        for y in 0..h as u32 {
            for x in 0..w as u32 {
                let g = sample(x, y);
                let c = cmds::rgb565(g, g, g);
                row[x as usize * 2] = (c >> 8) as u8;
                row[x as usize * 2 + 1] = c as u8;
            }
            self.send(&row[..w as usize * 2]);
        }
        self.cs.set_high();
    }

    /// Stream RGB565 pixels, big-endian, into the current window, for
    /// `embedded-graphics`.
    fn stream(&mut self, pixels: impl Iterator<Item = u16>) {
        self.end();
        let mut chunk = [0u8; 512];
        let mut n = 0usize;
        self.dc.set_high();
        self.cs.set_low();
        for c in pixels {
            chunk[n] = (c >> 8) as u8;
            chunk[n + 1] = c as u8;
            n += 2;
            if n == chunk.len() {
                self.send(&chunk);
                n = 0;
            }
        }
        if n > 0 {
            self.send(&chunk[..n]);
        }
        self.cs.set_high();
    }

    /// Fill the whole panel with one RGB565 colour.
    pub fn fill(&mut self, c: u16) {
        self.window(0, 0, LCD_W - 1, LCD_H - 1);
        self.push_colour(c, LCD_W as u32 * LCD_H as u32);
    }

    /// Filled rectangle, clipped to the panel.
    pub fn fill_rect(&mut self, x: u16, y: u16, w: u16, h: u16, c: u16) {
        let Some((x, y, w, h)) = Self::clip(x, y, w, h) else {
            return;
        };
        self.window(x, y, x + w - 1, y + h - 1);
        self.push_colour(c, w as u32 * h as u32);
    }

    /// Fill the panel with black.
    pub fn clear(&mut self) {
        self.fill(colour::BLACK);
    }
}
