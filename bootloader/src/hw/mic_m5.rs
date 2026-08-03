// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 KasSigner contributors
//
// ES7210 four-channel audio ADC — IDENTIFICATION ONLY, no configuration yet.
//
// WHY THIS EXISTS
//
// M5Stack CoreS3 has exactly one non-SoC entropy source, the GC0308 camera,
// and that sensor returns BIT-IDENTICAL frames in darkness (measured: 0/1024
// bytes changed, MAD 0.00). So in a dark room the board cannot generate a seed
// at all, and worse, `crypto::entropy::fill` — which supplies BIP340 aux-rand
// for every signing nonce — has no non-SoC input on that platform, because the
// camera is not running during signing. Audit E-08 and E-13.
//
// Candidates considered and rejected:
//
//   BMI270 IMU        needs an ~8 KB opaque Bosch config blob uploaded on every
//                     power-up. `Cargo.toml` states "No vendor libraries in the
//                     signing path"; an undocumented binary feeding seed
//                     generation is exactly that.
//   AXP2101 VBAT ADC  MEASURED DEAD. On battery, USB unplugged, 32 samples
//                     20 ms apart: 1 distinct value, 0 mV spread. Internally
//                     averaged.
//
// The ES7210 is the remaining candidate and the best of the three. Two MEMS
// microphones on their own dies, an ADC on a third, 102 dB SNR across 24 bits
// — which means roughly the BOTTOM SEVEN BITS OF EVERY SAMPLE ARE NOISE FLOOR
// with no acoustic input whatsoever. It works in the dark and it works in
// silence, because thermal noise in the membrane and the converter is the
// signal, not sound. Plain register configuration, no blob.
//
// A LIVE MICROPHONE ON AN AIR-GAPPED SIGNER IS A LEGITIMATE OBJECTION and is
// not settled by this file. Nothing here powers a microphone, sets a bias
// voltage, or starts a conversion. This module reads two ID registers and
// stops. Whether the mic is ever enabled is a decision for the maintainer, and
// if the answer is no, this file is deleted and nothing else changes.
//
// HARDWARE, from Sch_M5_CoreS3_v1_0 (U9) and the ES7210 datasheet Rev 21.0:
//   AD0 (pin 1), AD1 (pin 2) -> GNDA          => address 0x40
//   CDATA (3), CCLK (4)      -> I2C_SYS_SDA/SCL, shared with PMU and touch
//   MCLK (5)                 -> ESP_BOOT net via R34 51R
//   SCLK (9), LRCK (10)      -> I2S_BCK, I2S_WCK   (slave mode: ESP32 drives)
//   SDOUT1 (11)              -> I2S_DATI
//   MIC1P/N (16,15)          -> U12 MSM381A3729H9BPC
//   MIC2P/N (19,20)          -> U13 MSM381A3729H9BPC
//   VDDP/VDDD/VDDA/VDDM      -> VDDA_3V3 = AXP2101 ALDO2 @ 3300 mV, enabled
//                               at boot by pmu::init_axp2101 (LDO_EN1 = 0xBF)

use esp_hal::i2c::master::I2c;

/// I2C address is `1000 0 AD1 AD0` (datasheet section 4). The board ties both
/// address pins to GNDA, giving 0x40, but all four are probed rather than
/// assumed — the QMI8658C cost an extra boot transaction to settle exactly
/// this question and the documentation lost.
const ADDR_CANDIDATES: [u8; 4] = [0x40, 0x41, 0x42, 0x43];

/// CHIP ID1, default 0x72. Datasheet register 0x3D.
const REG_CHIP_ID1: u8 = 0x3D;
/// CHIP ID0, default 0x10. Datasheet register 0x3E.
const REG_CHIP_ID0: u8 = 0x3E;
/// CHIP VERSION, default 0x00. Datasheet register 0x3F.
const REG_CHIP_VER: u8 = 0x3F;

const CHIP_ID1_VALUE: u8 = 0x72;
const CHIP_ID0_VALUE: u8 = 0x10;

fn read_reg(i2c: &mut I2c<'_, esp_hal::Blocking>, addr: u8, reg: u8) -> Option<u8> {
    let mut buf = [0u8; 1];
    if i2c.write_read(addr, &[reg], &mut buf).is_ok() {
        Some(buf[0])
    } else {
        None
    }
}

/// Identification result.
pub struct Ident {
    pub addr: u8,
    pub id1: u8,
    pub id0: u8,
    pub version: u8,
}

/// Probe for an ES7210 and read its identity. READ ONLY.
///
/// Writes nothing, so it cannot disturb the codec, the shared supply, or the
/// AW88298 amplifier on the same rails. Returns None if no candidate address
/// answers with 0x72/0x10.
///
/// Both ID bytes are required to match. A single byte would be a weak test on
/// a bus that also carries the AXP2101 (0x34), the AW9523B (0x58) and the
/// touch controller.
pub fn probe(i2c: &mut I2c<'_, esp_hal::Blocking>) -> Option<Ident> {
    for &addr in ADDR_CANDIDATES.iter() {
        let id1 = match read_reg(i2c, addr, REG_CHIP_ID1) {
            Some(v) => v,
            None => continue,
        };
        let id0 = match read_reg(i2c, addr, REG_CHIP_ID0) {
            Some(v) => v,
            None => continue,
        };
        if id1 == CHIP_ID1_VALUE && id0 == CHIP_ID0_VALUE {
            let version = read_reg(i2c, addr, REG_CHIP_VER).unwrap_or(0);
            return Some(Ident { addr, id1, id0, version });
        }
    }
    None
}
