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

//! Pin maps for the ESP32-S3 boards.
//!
//! Every entry cites where v1.0.7 assigns it: `main.rs` or a driver, and for
//! the Waveshare `hw/board.rs`, which adds each bus's peripheral, the
//! sensor's pin numbering, and the battery, UART and USB pins `main.rs` never
//! names. The schematic is cited where it adds to or corrects them.
//!
//! Checked against documents: the Waveshare camera's signal indices and its
//! `CAM_H_SYNC` tie-off against the ESP32-S3 TRM ([`waveshare::CAMERA`]), the
//! strapping pins against `GPIO_STRAPPING` ([`Pin::strapping`]), and the
//! Waveshare map against its schematic's netlist (`tests/schematic.rs`).
//!
//! Most pins are bound through the HAL (`peripherals.GPIO39`). The Waveshare
//! camera writes the GPIO matrix directly, as `LCD_CAM` needs, so a search
//! for `peripherals.GPIO` misses its pins; they are here all the same.

/// What a pin is wired to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    /// GPIO number.
    pub gpio: u8,
    /// What it does on this board.
    pub function: &'static str,
    /// Where it is assigned in the firmware.
    pub source: &'static str,
}

impl Pin {
    pub const fn new(gpio: u8, function: &'static str, source: &'static str) -> Self {
        Self {
            gpio,
            function,
            source,
        }
    }

    /// Whether this is an ESP32-S3 strapping pin: GPIO0, GPIO3, GPIO45 or
    /// GPIO46 (`GPIO_STRAPPING` in the TRM).
    ///
    /// After boot it is an ordinary pin, but whatever drives it must not hold
    /// the wrong level as the chip leaves reset, and a watchdog reset can come
    /// at any moment, not only at power-on.
    ///
    /// | pin | strap |
    /// |---|---|
    /// | GPIO0 | low enters the ROM download loader |
    /// | GPIO3 | selects the JTAG source |
    /// | GPIO45 | selects `VDD_SPI`, the flash voltage |
    /// | GPIO46 | controls ROM message printing |
    ///
    /// GPIO45 is on both boards: LCD chip select on the Waveshare, camera
    /// pixel clock on the M5. A cold boot is safe (the camera is unpowered
    /// until firmware raises its rail, and chip select idles high). Across a
    /// watchdog reset the M5's AXP2101 keeps its state, so the sensor is still
    /// clocking when the strap is sampled. Espressif modules generally fix
    /// `VDD_SPI` by eFuse, which makes the strap moot: confirm it per module.
    pub const fn strapping(&self) -> bool {
        matches!(self.gpio, 0 | 3 | 45 | 46)
    }
}

/// A signal routed through the GPIO matrix rather than bound to a driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatrixRoute {
    /// Peripheral signal index, from the manual's signal table.
    pub signal: u16,
    /// The signal's name in that table.
    pub name: &'static str,
    /// The GPIO it is driven from, or `None` when tied to a constant.
    pub gpio: Option<u8>,
}

/// GPIO33 to GPIO37 (`SPIIO4` to `SPIIO7` and `SPIDQS` in the datasheet),
/// which a part with Octal SPI PSRAM takes for itself.
///
/// The Waveshare part is an `ESP32-S3R8` (8 MB octal PSRAM) and its schematic
/// leaves all five unconnected. The M5 uses all five for I2S and SPI, which
/// only a part without octal PSRAM on them allows. A constraint on the
/// module: an octal-PSRAM part on an M5-style board loses these pins with no
/// error, as the PSRAM controller wins.
pub const OCTAL_SPI_PINS: [u8; 5] = [33, 34, 35, 36, 37];

/// The GPIO matrix value that ties an input to a constant zero.
///
/// In the manual, `GPIO_FUNCy_IN_SEL = 0x3C` is always 0 and `0x38` always 1,
/// the opposite of what the numbers suggest; reading them backwards gives a
/// camera that never syncs.
pub const IN_SEL_CONST_ZERO: u8 = 0x3C;
/// The value that ties an input to a constant one.
pub const IN_SEL_CONST_ONE: u8 = 0x38;

// ── Waveshare ESP32-S3-Touch-LCD-2 ───────────────────────────────────────────

pub mod waveshare {
    use super::{MatrixRoute, Pin};

    /// The IMU's interrupt line, `IMU_INT1` on the schematic: wired, and read
    /// by nothing, as the IMU is polled. Listed because a device output
    /// drives a strapping pin: GPIO3 selects the JTAG source at boot.
    pub const IMU_INT: Pin = Pin::new(3, "IMU INT1, unused", "schematic / hw/imu_ws.rs:92");

    /// I2C0: touch and the IMU, at 400 kHz (`board.rs`'s touch bus).
    pub const I2C0: [Pin; 3] = [
        Pin::new(
            48,
            "I2C0 SDA (touch + IMU)",
            "main.rs:451,457 / board.rs:TP_SDA",
        ),
        Pin::new(
            47,
            "I2C0 SCL (touch + IMU)",
            "main.rs:451,458 / board.rs:TP_SCL",
        ),
        Pin::new(46, "touch INT, active low", "main.rs:471 / board.rs:TP_INT"),
    ];

    /// I2C0's bus speed, in kHz.
    pub const I2C0_KHZ: u32 = 400;

    /// I2C1: the camera's SCCB, at 100 kHz, a quarter of the touch bus's
    /// speed, so on a bus of its own (`board.rs`: `SEPARATE_I2C_BUSES`).
    pub const I2C1: [Pin; 2] = [
        Pin::new(
            21,
            "I2C1 SDA (camera SCCB)",
            "main.rs:459,465 / board.rs:CAM_SDA",
        ),
        Pin::new(
            16,
            "I2C1 SCL (camera SCCB)",
            "main.rs:459,466 / board.rs:CAM_SCL",
        ),
    ];

    /// I2C1's bus speed, in kHz.
    pub const I2C1_KHZ: u32 = 100;

    /// Devices on I2C0.
    pub const I2C0_DEVICES: [(u8, &str); 2] = [(0x15, "CST816D touch"), (0x6B, "QMI8658 IMU")];

    /// Devices on I2C1: the OV5640 only, as the driver accepts only its
    /// product ID. An OV2640 (0x30) needs a driver of its own first.
    pub const I2C1_DEVICES: [(u8, &str); 1] = [(0x3C, "OV5640 camera")];

    /// SPI2, shared by the display and the SD card. The card runs SDHOST in
    /// native mode, so the pins move between them through the GPIO matrix,
    /// not by chip select alone.
    pub const SPI2: [Pin; 2] = [
        Pin::new(
            39,
            "SPI2 SCK / SD CLK",
            "main.rs:524 / board.rs:LCD_SCLK,SD_CLK",
        ),
        Pin::new(
            38,
            "SPI2 MOSI / SD CMD",
            "main.rs:525 / board.rs:LCD_MOSI,SD_CMD",
        ),
    ];

    /// ST7789T3 display, 240x320. No MISO: the panel is write-only, so the SD
    /// card takes the bus back with no read line to contend for.
    ///
    /// CS (GPIO45) and GPIO0 are strapping pins. GPIO0 is the panel's reset
    /// on the schematic, but the board does not fit the link (R16): it is the
    /// BOOT button, which the firmware leaves alone, and the panel takes the
    /// software reset.
    pub const DISPLAY: [Pin; 4] = [
        Pin::new(45, "LCD CS", "main.rs:527 / board.rs:LCD_CS"),
        Pin::new(42, "LCD DC", "main.rs:528 / board.rs:LCD_DC"),
        Pin::new(0, "BOOT button, LCD RST unfitted", "board.rs:LCD_RST,BOOT"),
        Pin::new(
            1,
            "LCD backlight, active high",
            "main.rs:595 / board.rs:LCD_BL",
        ),
    ];

    /// SD card, in SDHOST native mode.
    pub const SD: [Pin; 2] = [
        Pin::new(40, "SD D0", "hw/sdcard_ws.rs:187 / board.rs:SD_D0"),
        Pin::new(
            41,
            "SD D3, card select",
            "hw/sdcard_ws.rs:186 / board.rs:SD_D3",
        ),
    ];

    /// Camera master clock: LEDC channel 0, 20 MHz, 50% duty. Not a buzzer:
    /// `board.rs` names it `CAM_XCLK`, and this board has no audio hardware.
    pub const CAMERA_XCLK: Pin =
        Pin::new(8, "camera XCLK, 20 MHz", "main.rs:572 / board.rs:CAM_XCLK");

    /// Camera power-down, active high (OV5640 datasheet): high powers the
    /// sensor down, low runs it, and an internal pull-down leaves it running
    /// on a floating GPIO, the safe default.
    pub const CAMERA_PWDN: Pin = Pin::new(
        17,
        "camera PWDN, active high",
        "main.rs:506 / board.rs:CAM_PWDN",
    );

    /// Battery sense, through a divider; this board has no PMU, so it reads
    /// the cell directly.
    ///
    /// `board.rs` says R19 200K over R20 100K, a third. Measured on the unit
    /// it is two thirds, so the resistors are the other way round: 100K in
    /// series, 200K to ground. With a cell the converter reads 2.60 V: 3.90 V
    /// at two thirds, an impossible 7.80 V at a third. With none it gives
    /// 4.40 V at two thirds, an unloaded charger output.
    pub const BATTERY_ADC: Pin = Pin::new(5, "battery ADC, 2/3 Vbat", "board.rs:BAT_ADC");

    /// Debug UART.
    pub const UART: [Pin; 2] = [
        Pin::new(43, "UART TX", "board.rs:UART_TX"),
        Pin::new(44, "UART RX", "board.rs:UART_RX"),
    ];

    /// USB.
    pub const USB: [Pin; 2] = [
        Pin::new(19, "USB D-", "board.rs:USB_DN"),
        Pin::new(20, "USB D+", "board.rs:USB_DP"),
    ];

    /// Camera DVP, routed through the GPIO matrix by hand: v1.0.7's
    /// `setup_cam_gpio_routing` writes `GPIO_FUNCy_IN_SEL_CFG` directly.
    ///
    /// Checked against the TRM: signals 133 to 140 are `CAM_DATA_in0` to
    /// `in7`, 149 `CAM_PCLK`, 150 `CAM_H_ENABLE`, 151 `CAM_H_SYNC`, 152
    /// `CAM_V_SYNC`. `CAM_H_SYNC` is tied to zero: in HREF mode
    /// `CAM_H_ENABLE` carries the line timing and HSYNC is unused.
    ///
    /// The data lines follow the sensor's numbering, Y2 to Y9, not pin order
    /// ([`CAMERA_SENSOR_PINS`]).
    pub const CAMERA: [MatrixRoute; 12] = [
        MatrixRoute {
            signal: 149,
            name: "CAM_PCLK",
            gpio: Some(9),
        },
        MatrixRoute {
            signal: 152,
            name: "CAM_V_SYNC",
            gpio: Some(6),
        },
        MatrixRoute {
            signal: 151,
            name: "CAM_H_SYNC",
            gpio: None,
        },
        MatrixRoute {
            signal: 150,
            name: "CAM_H_ENABLE",
            gpio: Some(4),
        },
        MatrixRoute {
            signal: 133,
            name: "CAM_DATA_in0",
            gpio: Some(12),
        },
        MatrixRoute {
            signal: 134,
            name: "CAM_DATA_in1",
            gpio: Some(13),
        },
        MatrixRoute {
            signal: 135,
            name: "CAM_DATA_in2",
            gpio: Some(15),
        },
        MatrixRoute {
            signal: 136,
            name: "CAM_DATA_in3",
            gpio: Some(11),
        },
        MatrixRoute {
            signal: 137,
            name: "CAM_DATA_in4",
            gpio: Some(14),
        },
        MatrixRoute {
            signal: 138,
            name: "CAM_DATA_in5",
            gpio: Some(10),
        },
        MatrixRoute {
            signal: 139,
            name: "CAM_DATA_in6",
            gpio: Some(7),
        },
        MatrixRoute {
            signal: 140,
            name: "CAM_DATA_in7",
            gpio: Some(2),
        },
    ];

    /// The sensor pin each data line comes from (`board.rs`): the OV5640's
    /// Y2 to Y9, so `CAM_DATA_in0` is Y2. Hold a schematic against this: the
    /// GPIO order looks arbitrary, the sensor order does not.
    pub const CAMERA_SENSOR_PINS: [(u8, &str); 8] = [
        (12, "Y2"),
        (13, "Y3"),
        (15, "Y4"),
        (11, "Y5"),
        (14, "Y6"),
        (10, "Y7"),
        (7, "Y8"),
        (2, "Y9"),
    ];

    /// No speaker. This flag and the three below are `board.rs`'s.
    pub const HAS_SPEAKER: bool = false;
    /// No AXP2101: power is direct.
    pub const HAS_PMU: bool = false;
    /// A battery, read through [`BATTERY_ADC`].
    pub const HAS_BATTERY: bool = true;
    /// Touch and the camera are on different buses.
    pub const SEPARATE_I2C_BUSES: bool = true;

    /// Every pin this board uses, for the checks in `tests/`.
    pub fn all() -> impl Iterator<Item = Pin> {
        I2C0.into_iter()
            .chain(I2C1)
            .chain(SPI2)
            .chain(DISPLAY)
            .chain(SD)
            .chain(UART)
            .chain(USB)
            .chain([CAMERA_XCLK, CAMERA_PWDN, BATTERY_ADC, IMU_INT])
            .chain(CAMERA.iter().filter_map(|r| {
                r.gpio
                    .map(|g| Pin::new(g, r.name, "hw/camera_ov5640.rs:184"))
            }))
    }
}

// ── M5Stack CoreS3 ───────────────────────────────────────────────────────────

pub mod m5stack {
    use super::Pin;

    /// The single I2C bus, with the AXP2101 and the AW9523B on it; most of
    /// what looks like a pin on this board is an expander line.
    pub const I2C: [Pin; 2] = [
        Pin::new(12, "I2C SDA", "main.rs:761"),
        Pin::new(11, "I2C SCL", "main.rs:762"),
    ];

    /// I2S to the AW88298 amplifier.
    pub const I2S: [Pin; 3] = [
        Pin::new(34, "I2S BCLK", "main.rs:827"),
        Pin::new(33, "I2S WS", "main.rs:828"),
        Pin::new(13, "I2S DOUT", "main.rs:829"),
    ];

    /// SPI, shared between the display and the SD card.
    pub const SPI: [Pin; 2] = [
        Pin::new(36, "SPI SCK (LCD + SD)", "main.rs:868"),
        Pin::new(37, "SPI MOSI (LCD + SD)", "main.rs:869"),
    ];

    /// ILI9342C display, two pins. `LCD DC` is also `SD MISO`, muxed at
    /// runtime around every card access, so the board has no `LCD_DC` net.
    ///
    /// No reset: `LCD_RST` runs from the panel connector to the AW9523B and
    /// reaches no ESP32 pin. GPIO14, which v1.0.7 drove as a reset, is the
    /// microphone's data line.
    pub const DISPLAY: [Pin; 2] = [
        // Strapping pin: GPIO3 selects the JTAG source at boot.
        Pin::new(3, "LCD CS", "main.rs:871 / schematic LCD_CS"),
        Pin::new(
            35,
            "LCD DC (shared with SD MISO)",
            "main.rs:872 / schematic SPI_MISO",
        ),
    ];

    /// SD card, sharing the bus with the display.
    pub const SD: [Pin; 2] = [
        Pin::new(4, "SD CS", "hw/sdcard_m5.rs:84"),
        Pin::new(35, "SD MISO (shared with LCD DC)", "hw/sdcard_m5.rs:85"),
    ];

    /// Camera DVP: bound through the HAL, unlike the Waveshare's, and then
    /// routed through the GPIO matrix as well.
    ///
    /// No master clock: `CAM_MCLK` comes from oscillator `X2` through a
    /// resistor and never reaches the ESP32. GPIO2, where v1.0.7 emits one,
    /// is the external Port A connector's I2C data line.
    ///
    /// The board names the data lines by the sensor's numbering, `CAM_D2` to
    /// `CAM_D9`; the Waveshare names them by bus bit, `CAM_D0` to `CAM_D7`.
    /// The sensor's Y2 is bus bit 0.
    pub const CAMERA: [Pin; 11] = [
        Pin::new(45, "CAM PCLK", "main.rs:910"),
        // Strapping pin: GPIO46 is driven by the sensor, not by us.
        Pin::new(46, "CAM VSYNC", "main.rs:911"),
        Pin::new(38, "CAM HREF", "main.rs:912"),
        Pin::new(39, "CAM D0", "main.rs:913"),
        Pin::new(40, "CAM D1", "main.rs:914"),
        Pin::new(41, "CAM D2", "main.rs:915"),
        Pin::new(42, "CAM D3", "main.rs:916"),
        Pin::new(15, "CAM D4", "main.rs:917"),
        Pin::new(16, "CAM D5", "main.rs:918"),
        Pin::new(48, "CAM D6", "main.rs:919"),
        Pin::new(47, "CAM D7", "main.rs:920"),
    ];

    /// Every pin this board uses, as the board wires it. `SD MISO` and
    /// `LCD DC` are one pin, listed twice on purpose. GPIO14 and GPIO2 are
    /// left out although `main.rs` drives them: on the board they are
    /// `I2S_DATI` and `BUS_PA_SDA`.
    pub fn all() -> impl Iterator<Item = Pin> {
        I2C.into_iter()
            .chain(I2S)
            .chain(SPI)
            .chain(DISPLAY)
            .chain(SD)
            .chain(CAMERA)
    }
}
