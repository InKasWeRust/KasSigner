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

// hw/camera.rs — OV5640 camera driver for Waveshare ESP32-S3-Touch-LCD-2
// 100% Rust, no-std, no-alloc
//
// OV5640 5MP autofocus sensor, SCCB (I2C-like) control, DVP 8-bit interface.
// QVGA 320x240 YUV422 output at 20MHz PCLK.


use esp_hal::delay::Delay;

const OV5640_ADDR: u8 = 0x3C;

// ═══ Sensor state ═══

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CameraStatus { Idle, Active, Error, NotReady, SensorReady, Capturing, Streaming }

pub static mut CAM_STATUS: CameraStatus = CameraStatus::Idle;
// ═══ SCCB register access (16-bit addresses) ═══

pub fn write_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u16, val: u8) -> bool {
    i2c.write(OV5640_ADDR, &[(reg >> 8) as u8, reg as u8, val]).is_ok()
}

pub fn read_reg<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, reg: u16) -> Option<u8> {
    let mut data = [0u8; 1];
    i2c.write(OV5640_ADDR, &[(reg >> 8) as u8, reg as u8]).ok()?;
    i2c.read(OV5640_ADDR, &mut data).ok()?;
    Some(data[0])
}

// ═══ Detection and initialization ═══

pub fn detect<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) -> bool {
    let id_h = read_reg(i2c, 0x300A).unwrap_or(0);
    let id_l = read_reg(i2c, 0x300B).unwrap_or(0);
    let id = ((id_h as u16) << 8) | id_l as u16;
    if id == 0x5640 {
        crate::log!("   OV5640 detected (ID=0x{:04X})", id);
        true
    } else {
        false
    }
}

/// Initialize OV5640 for QVGA 320x240 YUV422.
pub fn init<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) -> Result<(), &'static str> {
    if !detect(i2c) {
        return Err("OV5640 not detected at 0x3C");
    }
    for &(reg, val) in OV5640_INIT_REGS {
        if !write_reg(i2c, reg, val) {
            return Err("OV5640: SCCB write failed");
        }
    }
    delay.delay_millis(300);
    crate::log!("   OV5640 configured: QVGA 320x240 YUV422");
    load_af_firmware(i2c, delay);
    crate::log!("   OV5640 OK — registers configured");
    Ok(())
}

/// Apply proven image tuning for QR code scanning.
pub fn tune<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) {
    crate::log!("   OV5640: applying proven tune...");
    // AEC targets
    write_reg(i2c, 0x3A0F, 0x58); write_reg(i2c, 0x3A10, 0x48);
    write_reg(i2c, 0x3A1B, 0x58); write_reg(i2c, 0x3A1E, 0x48);
    write_reg(i2c, 0x3A11, 0x80); write_reg(i2c, 0x3A1F, 0x20);
    write_reg(i2c, 0x3A18, 0x00); write_reg(i2c, 0x3A19, 0xF8);
    // SDE — contrast + brightness
    let sde = read_reg(i2c, 0x5580).unwrap_or(0x06);
    write_reg(i2c, 0x5580, sde | 0x04);
    write_reg(i2c, 0x5586, 0x28); write_reg(i2c, 0x5585, 0x00);
    write_reg(i2c, 0x5587, 0x10); write_reg(i2c, 0x5588, 0x00);
    // PLL for 20MHz XCLK
    write_reg(i2c, 0x3036, 0x18); write_reg(i2c, 0x3035, 0x21);
    write_reg(i2c, 0x3037, 0x01);
    delay.delay_millis(200);
    let aec_h = read_reg(i2c, 0x3A0F);
    let sde_val = read_reg(i2c, 0x5580);
    crate::log!("   OV5640 tuned: AEC={:?} SDE={:?}", aec_h, sde_val);
}

/// Log diagnostic register values (CHIPID, PLL, timing, orientation).
pub fn log_diagnostics<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C) {
    let chipid_h = read_reg(i2c, 0x300A);
    let chipid_l = read_reg(i2c, 0x300B);
    let fmt_ctrl = read_reg(i2c, 0x4300);
    let polarity = read_reg(i2c, 0x4740);
    let dvp_ctrl = read_reg(i2c, 0x300E);
    crate::log!("   OV5640 regs: CHIPID={:?}/{:?} FMT={:?} POL={:?} DVP={:?}",
        chipid_h, chipid_l, fmt_ctrl, polarity, dvp_ctrl);
    let flip_reg = read_reg(i2c, 0x3820);
    let mirror_reg = read_reg(i2c, 0x3821);
    crate::log!("   OV5640 orientation: FLIP(0x3820)={:?} MIRROR(0x3821)={:?}",
        flip_reg, mirror_reg);
    let pll0 = read_reg(i2c, 0x3034);
    let pll1 = read_reg(i2c, 0x3035);
    let pll2 = read_reg(i2c, 0x3036);
    let pll3 = read_reg(i2c, 0x3037);
    let sclk = read_reg(i2c, 0x3108);
    let sc_ctrl = read_reg(i2c, 0x3103);
    crate::log!("   OV5640 PLL: 0x3034={:?} 0x3035={:?} 0x3036={:?} 0x3037={:?} 0x3108={:?} 0x3103={:?}",
        pll0, pll1, pll2, pll3, sclk, sc_ctrl);
    let hts_h = read_reg(i2c, 0x380C);
    let hts_l = read_reg(i2c, 0x380D);
    let vts_h = read_reg(i2c, 0x380E);
    let vts_l = read_reg(i2c, 0x380F);
    let dvpho_h = read_reg(i2c, 0x3808);
    let dvpho_l = read_reg(i2c, 0x3809);
    let dvpvo_h = read_reg(i2c, 0x380A);
    let dvpvo_l = read_reg(i2c, 0x380B);
    crate::log!("   OV5640 timing: HTS={:?}/{:?} VTS={:?}/{:?} DVPHO={:?}/{:?} DVPVO={:?}/{:?}",
        hts_h, hts_l, vts_h, vts_l, dvpho_h, dvpho_l, dvpvo_h, dvpvo_l);
}

// ═══ Frame constants ═══

pub const FRAME_WIDTH: usize = 320;
pub const FRAME_HEIGHT: usize = 240;
pub const FRAME_SIZE: usize = FRAME_WIDTH * FRAME_HEIGHT;

// ═══ ESP32-S3 LCD_CAM peripheral setup ═══

pub fn enable_lcd_cam_clocks() {
    unsafe {
        let clk_en1_addr = 0x600C_001Cu32 as *mut u32;
        let rst_en1_addr = 0x600C_0024u32 as *mut u32;
        let clk_en1 = core::ptr::read_volatile(clk_en1_addr);
        if clk_en1 & 1 == 0 {
            core::ptr::write_volatile(clk_en1_addr, clk_en1 | 1);
            let rst = core::ptr::read_volatile(rst_en1_addr);
            core::ptr::write_volatile(rst_en1_addr, rst | 1);
            for _ in 0..100u32 { core::ptr::read_volatile(&0u32); }
            core::ptr::write_volatile(rst_en1_addr, rst & !1u32);
            for _ in 0..100u32 { core::ptr::read_volatile(&0u32); }
        }
        let lcd_clock_addr = 0x6004_1000u32 as *mut u32;
        let lcd_clk = core::ptr::read_volatile(lcd_clock_addr);
        if lcd_clk & (1u32 << 31) == 0 {
            core::ptr::write_volatile(lcd_clock_addr, (1u32 << 31) | (2u32 << 29) | (2u32 << 8));
        }
        let cam_ctrl_addr = 0x6004_1004u32 as *mut u32;
        let cam_ctrl_pre = core::ptr::read_volatile(cam_ctrl_addr);
        let mut v = cam_ctrl_pre;
        v &= !(0xFF | (0xFF << 8) | (3 << 16) | (3 << 18));
        v |= 16; v |= 2 << 18;
        core::ptr::write_volatile(cam_ctrl_addr, v);
        let func_out_cfg_base = 0x6000_4554u32;
        core::ptr::write_volatile((func_out_cfg_base + 8 * 4) as *mut u32, 149u32);
        let gpio_en0 = 0x6000_4020u32 as *mut u32;
        let en = core::ptr::read_volatile(gpio_en0);
        core::ptr::write_volatile(gpio_en0, en | (1u32 << 8));
        let iomux_gpio8 = (0x6000_9000u32 + 0x04 + 8 * 4) as *mut u32;
        let mux_val = core::ptr::read_volatile(iomux_gpio8);
        core::ptr::write_volatile(iomux_gpio8, (mux_val & !0x7000) | 0x1000);
    }
}

pub fn configure_cam_vsync_eof() {
    unsafe {
        let cam_ctrl_addr = 0x6004_1004u32 as *mut u32;
        let cam_ctrl1_addr = 0x6004_1008u32 as *mut u32;
        let cur = core::ptr::read_volatile(cam_ctrl_addr);
        let mut val = cur;
        val |= 1u32 << 8;  val |= 0x07 << 1;
        val |= 1u32 << 0;  val |= 1u32 << 4;
        core::ptr::write_volatile(cam_ctrl_addr, val);
        let cur1 = core::ptr::read_volatile(cam_ctrl1_addr);
        let mut val1 = cur1;
        val1 |= 1u32 << 23; val1 |= 1u32 << 31;
        core::ptr::write_volatile(cam_ctrl1_addr, val1);
    }
}

pub fn setup_cam_gpio_routing() {
    unsafe {
        let gpio = &*esp_hal::peripherals::GPIO::PTR;
        let io_mux = &*esp_hal::peripherals::IO_MUX::PTR;
        let cam_gpios: [u8; 11] = [9, 6, 4, 12, 13, 15, 11, 14, 10, 7, 2];
        for &pin in &cam_gpios {
            io_mux.gpio(pin as usize).modify(|_, w| {
                w.fun_ie().set_bit(); w.mcu_sel().bits(1)
            });
        }
        let route = |signal_idx: usize, gpio_num: u8| {
            gpio.func_in_sel_cfg(signal_idx).write(|w| w.bits(0x80 | gpio_num as u32));
        };
        route(149, 9);  route(152, 6);
        gpio.func_in_sel_cfg(151).write(|w| w.bits(0x80 | 0x3C));
        route(150, 4);
        route(133, 12); route(134, 13); route(135, 15); route(136, 11);
        route(137, 14); route(138, 10); route(139, 7);  route(140, 2);
    }
}

pub fn verify_xclk_running() -> u32 {
    unsafe {
        let gpio_in = 0x6000_403Cu32 as *const u32;
        let mut last = core::ptr::read_volatile(gpio_in) & (1u32 << 8);
        let mut toggles = 0u32;
        for _ in 0..200_000u32 {
            let now = core::ptr::read_volatile(gpio_in) & (1u32 << 8);
            if now != last { toggles += 1; last = now; }
        }
        toggles
    }
}

// ═══ OV5640 register table — QVGA 320x240 YUV422 ═══

static OV5640_INIT_REGS: &[(u16, u8)] = &[
    (0x3008, 0x82), (0x3008, 0x42), (0x3103, 0x13),
    (0x3034, 0x18), (0x3035, 0x21), (0x3036, 0x18), (0x3037, 0x01), (0x3108, 0x01),
    (0x3017, 0xFF), (0x3018, 0xFF),
    (0x3000, 0x00), (0x3002, 0x00), (0x3004, 0xFF), (0x3006, 0xFF), (0x302E, 0x08),
    (0x3820, 0x41), (0x3821, 0x01),
    (0x3800, 0x00), (0x3801, 0x00), (0x3802, 0x00), (0x3803, 0x04),
    (0x3804, 0x0A), (0x3805, 0x3F), (0x3806, 0x07), (0x3807, 0x9B),
    (0x3808, 0x01), (0x3809, 0x40), (0x380A, 0x00), (0x380B, 0xF0),
    (0x380C, 0x07), (0x380D, 0x68), (0x380E, 0x03), (0x380F, 0xD8),
    (0x3810, 0x00), (0x3811, 0x10), (0x3812, 0x00), (0x3813, 0x06),
    (0x3814, 0x31), (0x3815, 0x31),
    (0x3630, 0x36), (0x3631, 0x0E), (0x3632, 0xE2), (0x3633, 0x12),
    (0x3621, 0xE0), (0x3704, 0xA0), (0x3703, 0x5A), (0x3715, 0x78),
    (0x3717, 0x01), (0x370B, 0x60), (0x3705, 0x1A), (0x3905, 0x02),
    (0x3906, 0x10), (0x3901, 0x0A), (0x3731, 0x12),
    (0x3600, 0x08), (0x3601, 0x33), (0x302D, 0x60), (0x3620, 0x52), (0x471C, 0x50),
    (0x3A13, 0x43), (0x3A18, 0x00), (0x3A19, 0xF8),
    (0x3635, 0x13), (0x3636, 0x03), (0x3634, 0x40), (0x3622, 0x01),
    (0x3C01, 0xA4), (0x3C04, 0x28), (0x3C05, 0x98),
    (0x3C06, 0x00), (0x3C07, 0x08), (0x3C08, 0x00), (0x3C09, 0x1C),
    (0x3C0A, 0x9C), (0x3C0B, 0x40),
    (0x3008, 0x02),
    (0x3618, 0x00), (0x3612, 0x29), (0x3708, 0x64), (0x3709, 0x52), (0x370C, 0x03),
    (0x4001, 0x02), (0x4004, 0x02),
    (0x3000, 0x00), (0x3002, 0x1C), (0x3004, 0xFF), (0x3006, 0xC3),
    (0x4300, 0x30), (0x501F, 0x00), (0x4740, 0x21),
    (0x5001, 0xA3),
    (0x3A02, 0x03), (0x3A03, 0xD8), (0x3A08, 0x01), (0x3A09, 0x3C),
    (0x3A0A, 0x01), (0x3A0B, 0x07), (0x3A0D, 0x04), (0x3A0E, 0x03),
    (0x3A0F, 0x58), (0x3A10, 0x48), (0x3A11, 0x80),
    (0x3A1B, 0x58), (0x3A1E, 0x48), (0x3A1F, 0x20),
    (0x5300, 0x08), (0x5301, 0x30), (0x5302, 0x10), (0x5303, 0x00),
    (0x5304, 0x08), (0x5305, 0x30), (0x5306, 0x10), (0x5307, 0x10),
    (0x5309, 0x08), (0x530A, 0x30), (0x530B, 0x02),
    (0x5480, 0x01),
    (0x5481, 0x08), (0x5482, 0x14), (0x5483, 0x28), (0x5484, 0x51),
    (0x5485, 0x65), (0x5486, 0x71), (0x5487, 0x7D), (0x5488, 0x87),
    (0x5489, 0x91), (0x548A, 0x9A), (0x548B, 0xAA), (0x548C, 0xB8),
    (0x548D, 0xCD), (0x548E, 0xDD), (0x548F, 0xEA), (0x5490, 0x1D),
    (0x5580, 0x06), (0x5583, 0x50), (0x5584, 0x10), (0x5586, 0x28),
    (0x5585, 0x00), (0x5587, 0x10), (0x5588, 0x00),
    (0x5688, 0x11), (0x5689, 0x11), (0x568A, 0x1F), (0x568B, 0xF1),
    (0x568C, 0x1F), (0x568D, 0xF1), (0x568E, 0x11), (0x568F, 0x11),
];

// ═══ Autofocus firmware loader ═══

fn load_af_firmware<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, delay: &mut Delay) {
    write_reg(i2c, 0x3000, 0x20);
    delay.delay_millis(10);
    for (i, &byte) in OV5640_AF_FW.iter().enumerate() {
        write_reg(i2c, 0x8000u16 + i as u16, byte);
    }
    write_reg(i2c, 0x3022, 0x00); write_reg(i2c, 0x3023, 0x00);
    write_reg(i2c, 0x3024, 0x00); write_reg(i2c, 0x3025, 0x00);
    write_reg(i2c, 0x3026, 0x00); write_reg(i2c, 0x3027, 0x00);
    write_reg(i2c, 0x3028, 0x00); write_reg(i2c, 0x3029, 0xFF);
    write_reg(i2c, 0x3000, 0x00);
    delay.delay_millis(500);
    let af_sta = read_reg(i2c, 0x3029);
    crate::log!("   OV5640 AF firmware: status={:?} (0x70=OK)", af_sta);
    write_reg(i2c, 0x3022, 0x04); write_reg(i2c, 0x3023, 0x01);
    delay.delay_millis(100);
    let af_sta2 = read_reg(i2c, 0x3029);
    crate::log!("   OV5640 AF continuous: status={:?}", af_sta2);
}

include!("ov5640_af_fw.rs");
