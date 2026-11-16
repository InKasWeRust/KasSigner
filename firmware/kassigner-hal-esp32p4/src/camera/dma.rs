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

//! DesignWare AXI-DMAC (dw_gdma) channel, base 0x5008_1000, compver0
//! 0x3230302a, "200*"; not the AXI_GDMA at 0x5008_A000 (LCD_CAM/DVP).
//!
//! Configured after ESP-IDF's `esp_cam_ctlr_csi.c`:
//!   src: role PERIPH_CSI, HW handshake, burst FIXED, 512 items, len 16,
//!        width 64, outstanding 5, status_fetch_addr = bridge MEM_BASE
//!   dst: role MEM, burst INCREMENT, same items/len/width
//!   flow control by the DMAC (P2M_DMAC), channel priority 1
//!
//! Driven through the `esp32p4` PAC (block `DMA`), whose fields match the
//! offsets verified on this silicon.

use esp32p4::{dma::RegisterBlock, DMA};

#[inline(always)]
fn regs() -> &'static RegisterBlock {
    // SAFETY: fixed MMIO block, always mapped; esp-hal does not drive the
    // dw_gdma on P4.
    unsafe { &*DMA::PTR }
}

/// Channel 1, the only one used: `ch(0)` in the PAC's numbering.
#[inline(always)]
fn ch1() -> &'static esp32p4::dma::CH {
    regs().ch(0)
}

/// `compver0` on this silicon: "200*".
pub const COMPVER_EXPECTED: u32 = 0x3230_302a;

/// Component version, raw. Prints as four ASCII bytes.
pub fn compver() -> u32 {
    regs().compver0().read().bits()
}

/// CSI bridge handshake interface number (`src_per`).
const PER_CSI: u8 = 1;
/// tt_fc: M2M_DMAC 0, M2P_DMAC 1, P2M_DMAC 2, P2P_DMAC 3.
const FLOW_P2M_DMAC: u8 = 2;
/// TRANS_WIDTH_8..512 = 0..6, so 64-bit = 3.
const WIDTH_64: u8 = 3;
/// BURST_ITEMS_1..1024 = 0..9, so 512 = 8.
const MSIZE_512: u8 = 8;
/// AXI burst length for both directions.
const BURST_LEN: u8 = 16;

/// True if the component version reads back (clocked and out of reset).
pub fn alive() -> bool {
    compver() == COMPVER_EXPECTED
}

/// Set channel 1 to move `words` 64-bit words from the CSI bridge to `dst`;
/// `start()` starts it.
pub fn configure(src: u32, dst: u32, words: u32) -> Result<(), Stuck> {
    // The engine refuses writes to an enabled channel's registers.
    if running() && !stop() {
        return Err(Stuck);
    }
    regs()
        .cfg0()
        .write(|w| w.dmac_en().set_bit().int_en().set_bit());

    let c = ch1();
    // SAFETY: an address in a 32-bit field: `bridge::MEM_BASE`, the only
    // `src` passed.
    c.sar0().write(|w| unsafe { w.ch1_sar0().bits(src) });
    // SAFETY: zero, the high word of a 32-bit address; any value fits.
    c.sar1().write(|w| unsafe { w.ch1_sar1().bits(0) });
    // SAFETY: the engine writes here: a frame buffer of `FRAME_WORDS`
    // words, the `words` asked for, from `Camera` (or the self-tests, with
    // `unstable`).
    c.dar0().write(|w| unsafe { w.ch1_dar0().bits(dst) });
    // SAFETY: zero, the high word of a 32-bit address; any value fits.
    c.dar1().write(|w| unsafe { w.ch1_dar1().bits(0) });
    c.sstatar0()
        // SAFETY: the bridge FIFO again, as the DesignWare manual asks for
        // a peripheral source.
        .write(|w| unsafe { w.ch1_sstatar0().bits(src) }); // status_fetch_addr
    debug_assert!(words > 0);
    c.block_ts0()
        // SAFETY: `words - 1`, as the field is defined; `FRAME_WORDS` fits.
        .write(|w| unsafe { w.ch1_block_ts().bits(words.saturating_sub(1)) }); // count - 1

    // ctl0, every field stated (reset is 0x1200; the PAC rule in
    // `csi_host.rs`). DesignWare polarity: sinc = 1 keeps the source
    // address fixed, as a peripheral FIFO needs.
    // SAFETY: the TRM's encodings: the constants above for width and burst
    // size, single bits for the flags.
    c.ctl0().write(|w| unsafe {
        w.ch1_sms()
            .clear_bit()
            .ch1_dms()
            .clear_bit()
            .ch1_sinc()
            .set_bit() // source fixed
            .ch1_dinc()
            .clear_bit() // destination increments
            .ch1_src_tr_width()
            .bits(WIDTH_64)
            .ch1_dst_tr_width()
            .bits(WIDTH_64)
            .ch1_src_msize()
            .bits(MSIZE_512)
            .ch1_dst_msize()
            .bits(MSIZE_512)
            .ch1_ar_cache()
            .bits(0)
            .ch1_aw_cache()
            .bits(0)
            .ch1_nonposted_lastwrite_en()
            .clear_bit()
    });
    // SAFETY: `BURST_LEN`, 16, fits the eight-bit AXI burst length fields.
    c.ctl1().write(|w| unsafe {
        w.ch1_arlen_en()
            .set_bit()
            .ch1_arlen()
            .bits(BURST_LEN)
            .ch1_awlen_en()
            .set_bit()
            .ch1_awlen()
            .bits(BURST_LEN)
    });
    // Contiguous on both sides: a single block.
    // SAFETY: zero, contiguous, is a defined value of both two-bit fields.
    c.cfg0().write(|w| unsafe {
        w.ch1_src_multblk_type()
            .bits(0)
            .ch1_dst_multblk_type()
            .bits(0)
    });
    // Every field stated: reset is 0x0006_001b, not 0.
    // SAFETY: the TRM's encodings for P2M flow control (2) and the CSI
    // handshake (1); priority and outstanding limits fit their fields.
    c.cfg1().write(|w| unsafe {
        w.ch1_tt_fc()
            .bits(FLOW_P2M_DMAC)
            .ch1_hs_sel_src()
            .clear_bit() // HW handshake
            .ch1_hs_sel_dst()
            .set_bit() // SW (memory side)
            .ch1_src_per()
            .bits(PER_CSI)
            .ch1_dst_per()
            .bits(0)
            .ch1_ch_prior()
            .bits(1)
            .ch1_src_osr_lmt()
            .bits(5)
            .ch1_dst_osr_lmt()
            .bits(5)
    });
    // SAFETY: all ones clears every interrupt status bit.
    c.intclear0().write(|w| unsafe { w.bits(0xffff_ffff) });
    Ok(())
}

/// Channel 1 would not stop, even aborted and reset, so it was not set up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Stuck;

/// Enable channel 1. DesignWare write-enable pattern: en_we plus en.
pub fn start() {
    regs()
        .chen0()
        .write(|w| w.ch1_en_we().set_bit().ch1_en().set_bit());
}

/// Disable channel 1 (en_we set, en clear) and wait, bounded, for `ch1_en`
/// to drop; whether it did.
///
/// A completed block leaves the channel off on this silicon, but a disable
/// mid-block waits for a burst that a stopped source never finishes (the
/// next `configure` then took a store fault). So a channel that will not
/// disable is aborted, and one that will not abort either (seen after a
/// camera restart) gets the whole controller reset; `configure` writes
/// every register again.
pub fn stop() -> bool {
    regs()
        .chen0()
        .write(|w| w.ch1_en_we().set_bit().ch1_en().clear_bit());
    if settle() {
        return true;
    }
    #[cfg(feature = "unstable")]
    ABORTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    regs()
        .chen1()
        .write(|w| w.ch1_abort_we().set_bit().ch1_abort().set_bit());
    if settle() {
        return true;
    }
    #[cfg(feature = "unstable")]
    RESETS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    regs().reset0().write(|w| w.dmac_rst().set_bit());
    // The controller clears the bit once its reset is done.
    let mut n = 0u32;
    while regs().reset0().read().dmac_rst().bit_is_set() && n < 1_000_000 {
        n += 1;
        core::hint::spin_loop();
    }
    settle()
}

/// Wait, bounded, for channel 1 to drop its enable. Whether it did.
fn settle() -> bool {
    let mut n = 0u32;
    while running() {
        n += 1;
        if n > 1_000_000 {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Diagnostics: how often `stop` aborted channel 1.
#[cfg(feature = "unstable")]
static ABORTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostics: how many times `stop` had to abort channel 1.
#[cfg(feature = "unstable")]
pub fn aborts() -> u32 {
    ABORTS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Diagnostics: how often `stop` reset the controller.
#[cfg(feature = "unstable")]
static RESETS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Diagnostics: how many times `stop` had to reset the whole controller.
#[cfg(feature = "unstable")]
pub fn resets() -> u32 {
    RESETS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Is channel 1 enabled? True while a transfer is in flight.
pub fn running() -> bool {
    regs().chen0().read().ch1_en().bit_is_set()
}

/// True once the block (or transfer) done interrupt is raised.
pub fn complete() -> bool {
    let s = ch1().intstatus0().read();
    s.ch1_dma_tfr_done_intstat().bit_is_set() || s.ch1_block_tfr_done_intstat().bit_is_set()
}

#[cfg(feature = "unstable")] // diagnostics: used by the self-tests, not by the HAL
/// Words transferred so far in the current block.
pub fn progress() -> u32 {
    ch1().status0().read().ch1_cmpltd_blk_tfr_size().bits()
}
