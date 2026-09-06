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

// ESP32-S3 LCD_CAM clock and GPIO routing for OV sensors.

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

