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

//! KasSigner P4 — full hardware self-test.
//!
//! Exercises every block through the library, in bring-up order, and
//! reports pass/fail per stage on the serial port, then a tally. On the
//! screen: six colour bands, then the camera's green plane with text under
//! it and an orange block cut off at the left edge, then ten seconds in
//! which a marker should land under the finger.
//!
//!   cargo +esp195 p4-hwtest     (from this crate's directory)
//!
//! The unit is built here, not by `unit::bring_up`, which stops at the
//! first part that refuses: this test reports every stage, after a failure
//! too. Each part is built as `bring_up` builds it, in its order; a change
//! there is a change here.
//!
//! 64-bit arithmetic is checked by the signing firmware's
//! `selftest::arithmetic` (if it fails, every number here is suspect), the
//! generator's raw output by the `p4_entropy` example.

#![cfg_attr(target_arch = "riscv32", no_std)]
#![cfg_attr(target_arch = "riscv32", no_main)]

// The host build is an empty program, so that clippy on a laptop has
// something to check: `cargo clippy --workspace --all-targets`.
#[cfg(not(target_arch = "riscv32"))]
fn main() {}

#[cfg(target_arch = "riscv32")]
mod app {

    use embedded_graphics::{
        mono_font::{ascii::FONT_10X20, ascii::FONT_6X10, MonoTextStyle},
        pixelcolor::Rgb565,
        prelude::*,
        primitives::{PrimitiveStyle, Rectangle},
        text::Text,
    };
    use esp_backtrace as _;
    use esp_hal::main;
    use kassigner_hal_esp32p4::{
        battery,
        board::{
            self,
            i2c::{self as i2cutil},
            i2c_addr, LCD_H, LCD_W,
        },
        camera::{self, bridge, csi_host, dma, dphy, isp, Camera, FrameBuffer, Ov5647},
        drivers::{axp2101::common, st7796::cmds::colour, touch::Controller},
        entropy,
        soc::{rom, uart::*, watchdog},
    };

    mod report {
        //! Pass/fail bookkeeping for the self-test, in a value rather than
        //! `static mut` counters, so the reporting path needs no `unsafe`.

        use kassigner_hal_esp32p4::soc::uart::*;

        /// Running tally.
        #[derive(Default)]
        pub struct Report {
            /// Checks that passed.
            pub pass: u32,
            /// Checks that failed.
            pub fail: u32,
        }

        impl Report {
            /// Fresh tally.
            pub const fn new() -> Self {
                Self { pass: 0, fail: 0 }
            }

            /// Record and print one check. Returns `ok` for chaining.
            pub fn check(&mut self, name: &str, ok: bool) -> bool {
                puts(if ok { "  [ ok ] " } else { "  [FAIL] " });
                puts(name);
                puts("\r\n");
                if ok {
                    self.pass += 1
                } else {
                    self.fail += 1
                }
                ok
            }

            /// `--- name ---` divider.
            pub fn section(&self, name: &str) {
                puts("\r\n--- ");
                puts(name);
                puts(" ---\r\n");
            }

            /// Final tally line.
            pub fn summary(&self, ok_msg: &str, fail_msg: &str) {
                puts("\r\n=========================================\r\n passed ");
                putdec(self.pass);
                puts("   failed ");
                putdec(self.fail);
                puts("\r\n");
                puts(if self.fail == 0 { ok_msg } else { fail_msg });
                puts("=========================================\r\n");
            }
        }

        /// Standard banner.
        pub fn banner(title: &str) {
            puts("\r\n=========================================\r\n KasSigner P4 :: ");
            puts(title);
            puts("\r\n=========================================\r\n");
        }

        /// Park forever, printing a heartbeat.
        pub fn idle(delay: &esp_hal::delay::Delay) -> ! {
            loop {
                delay.delay_millis(1000);
                putc(b'.');
            }
        }
    }
    use report::Report;

    esp_bootloader_esp_idf::esp_app_desc!();

    static mut FB: FrameBuffer = FrameBuffer::new();

    #[main]
    fn main() -> ! {
        watchdog::disable_lp();
        report::banner("hardware self-test");

        let p = esp_hal::init(esp_hal::Config::default());

        // The board crate links the decoder, which allocates; this test never
        // does, but a binary must have an allocator to link.
        esp_alloc::heap_allocator!(size: 8 * 1024);
        // The C6 down for the whole test, as the firmware has it.
        let _ = board::hold_c6_down();
        let board::Board {
            mut bus,
            mut lcd,
            mut touch,
            delay,
            ..
        } = match board::init(p) {
            Ok(b) => b,
            Err(part) => {
                puts("board::init refused: ");
                puts(part);
                puts("\r\n");
                report::idle(&esp_hal::delay::Delay::new())
            }
        };
        let mut r = Report::new();

        // ---- silicon --------------------------------------------------------
        r.section("silicon");
        puts("  ROM eco version = ");
        putdec(rom::rom_eco_version());
        puts("\r\n");
        r.check("esp_hal::init() returned", true);
        r.check("ROM is the verified ECO2", rom::is_verified_silicon());
        let (probe_ok, probe_total) = rom::table_probe();
        r.check(
            "ROM table lands on the right routines",
            probe_ok == probe_total,
        );

        // ---- I2C ------------------------------------------------------------
        r.section("I2C bus");
        let found = i2cutil::scan(&mut bus, |a| {
            puts("    0x");
            puthex8(a);
            puts(match a {
                i2c_addr::ES8311 => "  ES8311",
                i2c_addr::AXP2101 => "  AXP2101",
                i2c_addr::OV5647 => "  OV5647",
                i2c_addr::FT6336 => "  FT6336",
                _ => "",
            });
            puts("\r\n");
        });
        puts("  devices: ");
        putdec(found);
        puts("\r\n");
        r.check(
            "PMIC present",
            i2cutil::present(&mut bus, i2c_addr::AXP2101),
        );
        r.check(
            "codec present",
            i2cutil::present(&mut bus, i2c_addr::ES8311),
        );
        r.check("camera present", Ov5647::present(&mut bus));

        // The cell, through the PMU: reported, not checked, since a unit may
        // have none fitted.
        battery::enable_on(&mut bus);
        puts("  battery: ");
        match battery::read_on(&mut bus) {
            Ok(kassigner_hal::battery::Reading::Battery(b)) => {
                puts(match b.present {
                    Some(true) => "fitted, ",
                    Some(false) => "none fitted, ",
                    None => "fitted or not, ",
                });
                putdec(u32::from(b.voltage_mv));
                puts(" mV, ");
                putdec(u32::from(b.percentage));
                puts(match b.state {
                    kassigner_hal::battery::ChargeState::Charging => "%, charging\r\n",
                    kassigner_hal::battery::ChargeState::Discharging => "%, discharging\r\n",
                    kassigner_hal::battery::ChargeState::Unknown => "%, direction unknown\r\n",
                });
            }
            Ok(kassigner_hal::battery::Reading::Implausible { .. }) => puts("implausible\r\n"),
            Err(_) => puts("read failed\r\n"),
        }

        // The reset button as a power cut: on as the signer turns it on while
        // a secret is held, then off again, as the signer boots, so the next
        // flash can reach the unit. A press cycling the rails is a manual
        // check.
        for (on, name) in [
            (true, "reset button cuts power when asked"),
            (false, "reset button a plain reset again"),
        ] {
            let cut = board::reset_cuts_power(&mut bus, on);
            if let Some((before, after)) = cut {
                puts("  REG 10: 0x");
                puthex8(before);
                puts(" -> 0x");
                puthex8(after);
                puts("\r\n");
            }
            r.check(
                name,
                cut.is_some_and(|(_, after)| (after & common::PWROK_RESTART != 0) == on),
            );
        }

        // ---- touch ----------------------------------------------------------
        r.section("touch");
        let ctrl = touch.probe(&mut bus, &delay);
        r.check("controller found after releasing TP_RST", ctrl.is_some());
        if let Some(c) = ctrl {
            puts("  ");
            puts(match c {
                Controller::Ft6336 => "FT6336 @ 0x38",
                Controller::Gt911Primary => "GT911 @ 0x5D",
                Controller::Gt911Backup => "GT911 @ 0x14",
            });
            puts("\r\n");
        }

        // ---- display --------------------------------------------------------
        r.section("display");
        // Every send answers for itself, so the stage passes only if the bus
        // took all of it.
        let mut sent = lcd.init(&delay);
        // Black before the light, as the unit does: the panel may still hold
        // the last screen, perhaps a SeedQR.
        sent = sent.and(lcd.clear());
        lcd.backlight(true);
        let bands = [
            colour::RED,
            colour::GREEN,
            colour::BLUE,
            colour::WHITE,
            colour::BLACK,
            colour::YELLOW,
        ];
        let bh = LCD_H / 6;
        for (i, c) in bands.iter().enumerate() {
            sent = sent.and(lcd.fill_rect(0, bh * i as u16, LCD_W, bh, *c));
        }
        puts("  bands: RED GREEN BLUE WHITE BLACK YELLOW\r\n");
        r.check("display init completed", sent.is_ok());
        delay.delay_millis(2000);

        // ---- camera ---------------------------------------------------------
        r.section("camera");
        // Raw pointer, never `&mut`: the DMA writes this buffer.
        // SAFETY: `FB` lives for the program, and nothing else here uses it.
        let mut cam = unsafe { Camera::new(core::ptr::addr_of_mut!(FB)) };
        match cam.power_up(&delay) {
            Ok(()) => {
                r.check("MIPI D-PHY LDO enabled", true);
                r.check("CSI-2 host / ISP / dw_gdma alive", true);
            }
            Err(e) => {
                r.check("camera power-up", false);
                puts("  first failure: ");
                puts(match e {
                    camera::Error::LdoNotEnabled => "MIPI LDO",
                    camera::Error::CsiHostDead => "CSI-2 host",
                    camera::Error::IspDead => "ISP",
                    camera::Error::DmaDead => "dw_gdma",
                    _ => "?",
                });
                puts("\r\n");
            }
        }
        puts("  csi host ");
        put_ascii(csi_host::version());
        puts("   dw_gdma ");
        put_ascii(dma::compver());
        puts("\r\n");

        r.check(
            "sensor configured",
            cam.configure_sensor(&mut bus, &delay).is_ok(),
        );
        r.check("pipeline started", cam.start(&mut bus, &delay).is_ok());
        r.check("clock lane in high speed", dphy::clock_lane_active());
        r.check("no CSI errors", csi_host::errors() == 0);
        puts("  lane stopstate ");
        puthex(csi_host::stopstate());
        puts("  bridge fifo depth ");
        putdec(bridge::buf_depth());
        puts("  bridge status ");
        puthex(bridge::status());
        puts("\r\n");

        let progress;
        let isp_status;
        let mut rendered = false;
        match cam.capture() {
            Ok(f) => {
                r.check("frame captured", true);
                progress = dma::progress() + 1;
                isp_status = isp::status();
                r.check(
                    "dma channel idle after block",
                    !f.dma_was_running && !dma::running(),
                );
                let (gmin, gmax, gmean) = f.green_stats();
                // Checks the ECO2 memory.x ceiling: green_stats streams
                // 320 KB through L1, evicting every stack line, and a stack
                // in the unbacked top 128 KB of L2MEM would read `f` back as
                // zeros.
                let sp_marker = 0u32;
                let sp = &sp_marker as *const u32 as u32;
                puts("  stack ~ ");
                puthex(sp);
                puts("\r\n");
                r.check(
                    "stack below 0x4FFA0000 (ECO2 L2MEM ceiling)",
                    sp < 0x4FFA_0000,
                );
                // Against the sensor's own width, so it follows the mode.
                r.check(
                    "locals survive L1 thrash (memory.x fix)",
                    f.data.len() == camera::FRAME_BYTES && f.width == camera::ov5647::WIDTH,
                );
                puts("  green min=");
                putdec(gmin as u32);
                puts(" max=");
                putdec(gmax as u32);
                puts(" mean=");
                putdec(gmean);
                puts("\r\n");
                if !r.check("image has contrast", gmax as u32 - gmin as u32 > 6) {
                    puts("  (a covered lens or dark room fails this legitimately)\r\n");
                }
                // ---- camera -> display ---------------------------------------
                r.section("camera -> display");
                let (gw, gh) = f.green_dims();
                let sent = lcd.clear().and_then(|()| {
                    lcd.blit_grey(0, 0, gw as u16, gh as u16, |x, y| f.green_at(x, y))
                });
                r.check("the bus took the image", sent.is_ok());
                rendered = true;

                // ---- text via embedded-graphics ------------------------------
                r.section("text rendering (embedded-graphics)");
                let big = MonoTextStyle::new(&FONT_10X20, Rgb565::WHITE);
                let small = MonoTextStyle::new(&FONT_6X10, Rgb565::CSS_LIGHT_GRAY);
                let ok_text = Rectangle::new(Point::new(0, 210), Size::new(LCD_W as u32, 90))
                    .into_styled(PrimitiveStyle::with_fill(Rgb565::CSS_DARK_SLATE_GRAY))
                    .draw(&mut lcd)
                    .and_then(|_| Text::new("KasSigner P4", Point::new(8, 236), big).draw(&mut lcd))
                    .and_then(|_| {
                        Text::new("kaspa:qr7f2w6xnd9y0z4k8mh3", Point::new(8, 258), small)
                            .draw(&mut lcd)
                    })
                    .and_then(|_| {
                        Text::new("v5t3c8jl2p9a4e6g1u0b7s", Point::new(8, 270), small)
                            .draw(&mut lcd)
                    })
                    .and_then(|_| {
                        Rectangle::new(Point::new(-10, 290), Size::new(40, 20))
                            .into_styled(PrimitiveStyle::with_fill(Rgb565::CSS_ORANGE))
                            .draw(&mut lcd)
                    })
                    .is_ok();
                r.check("title, address text and a clipped rect drew", ok_text);
                puts("  expect: grey band under the image, white title, two grey\r\n");
                puts("  address lines, and an orange block cut off at the LEFT edge\r\n");
            }
            Err(_) => {
                r.check("frame captured", false);
                progress = dma::progress() + 1;
                isp_status = isp::status();
            }
        }
        puts("  words ");
        putdec(progress);
        puts(" / ");
        putdec(camera::FRAME_WORDS);
        puts("   isp ");
        puthex(isp_status);
        puts("\r\n");
        if rendered {
            r.check("frame rendered", true);
            if let Some((expo, gain)) = Ov5647::exposure(&mut bus) {
                puts("  exposure ");
                putdec(expo);
                puts(" lines, gain ");
                putdec(gain);
                puts("/1023\r\n");
            }
        }

        // ---- entropy --------------------------------------------------------
        r.section("entropy");
        let (d0, o0, b0) = entropy::sanity(64, &delay);
        let en = entropy::enable(&delay);
        let (d1, o1, b1) = entropy::sanity(64, &delay);
        puts("  before: distinct ");
        putdec(d0);
        puts("/64, ones ");
        putdec(o0 * 100 / b0);
        puts("%   after: distinct ");
        putdec(d1);
        puts("/64, ones ");
        putdec(o1 * 100 / b1);
        puts("%\r\n");
        if !r.check("entropy::enable() confirmed by readback", en.is_ok()) {
            puts("  ");
            puts(match en {
                Err(entropy::Error::RegI2c(_)) => "REGI2C write failed or timed out",
                Err(entropy::Error::NotRunning) => "ADC trigger not running",
                Err(entropy::Error::CalibrationMismatch(_)) => "calibration readback mismatch",
                Err(entropy::Error::SarInitMismatch(_)) => "SAR enable register readback mismatch",
                Ok(()) => "",
            });
            puts("\r\n");
        }
        r.check(
            "entropy register not stuck",
            d1 >= 62 && (40..=60).contains(&(o1 * 100 / b1)),
        );

        // ---- live touch -----------------------------------------------------
        r.section("live touch (10 s) - marker should land UNDER the finger");
        let mut hits = 0u32;
        for _ in 0..100u32 {
            if let Ok(Some(pt)) = touch.read_screen(&mut bus) {
                let c = if hits.is_multiple_of(2) {
                    colour::CYAN
                } else {
                    colour::MAGENTA
                };
                let _ = lcd.fill_rect(pt.x.saturating_sub(4), pt.y.saturating_sub(4), 9, 9, c);
                hits += 1;
            }
            delay.delay_millis(100);
        }
        r.check("touch produced coordinates", hits > 0);
        puts("  If the marker mirrored the finger, flip board::touch_map.\r\n");

        r.summary(
            " ALL HARDWARE OK\r\n",
            " see the section above that failed\r\n",
        );
        report::idle(&delay)
    }
}
