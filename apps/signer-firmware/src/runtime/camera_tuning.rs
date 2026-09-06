// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Sensor-specific camera tuning adapters.

#[cfg(feature = "waveshare")]
pub(crate) fn cam_tune_apply_all<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use crate::hw::camera::write_reg;

    // AEC targets: H must be >= L for the control loop to converge.
    // If user drags them inverted, clamp L to H.
    let aec_h = vals[0];
    let aec_l = if vals[1] > vals[0] { vals[0] } else { vals[1] };

    // AEC stable range (enter) and (go out) — keep them paired
    write_reg(i2c, 0x3A0F, aec_h);   // WPT — stable high (enter)
    write_reg(i2c, 0x3A1B, aec_h);   // WPT2 — stable high (go out)
    write_reg(i2c, 0x3A10, aec_l);   // BPT — stable low (enter)
    write_reg(i2c, 0x3A1E, aec_l);   // BPT2 — stable low (go out)

    // SDE (Special Digital Effects) — enable contrast+brightness bits
    let sde = crate::hw::camera::read_reg(i2c, 0x5580).unwrap_or(0x06);
    write_reg(i2c, 0x5580, sde | 0x06);  // bit2 = contrast, bit1 = brightness
    write_reg(i2c, 0x5586, vals[2]);     // contrast
    write_reg(i2c, 0x5585, 0x00);        // brightness sign (0=positive)
    write_reg(i2c, 0x5587, vals[3]);     // brightness magnitude

    // AGC gain ceiling
    write_reg(i2c, 0x3A18, 0x00);
    write_reg(i2c, 0x3A19, vals[4]);

    // CIP sharpness — slider value IGNORED on OV5640.
    //
    // The OV5640's CIP edge-enhancement block (0x5302 with 0x5308[6]=1
    // manual mode) is documented to accept runtime writes, but in practice
    // changing 0x5302 during streaming produces no visible effect on the
    // Y8 output of this module. No production OV5640 driver (Linux, STM,
    // NXP) exposes sharpness as a user-adjustable control — they all set
    // good baseline values at init and leave the CIP block alone.
    //
    // The sharpness slider is kept in the UI for consistency across the
    // OV5640/OV2640/GC0308 camera zoo — the overlay should look the same
    // regardless of which sensor booted. For OV2640 the cam_tune_apply_ov2640
    // path DOES honor the slider. For OV5640 we lock 0x5302 to a fixed good
    // value (0x30, the LCD-QR-tuned baseline) so toggling the slider won't
    // accidentally degrade an already-working image.
    //
    // We still write 0x5308=0x40 each apply to ensure manual MT mode stays
    // asserted (some re-init paths may drop it).
    write_reg(i2c, 0x5308, 0x40);        // manual edge MT mode (bit 6)
    write_reg(i2c, 0x5302, 0x30);        // fixed sharpen (LCD baseline)
    // vals[5] (slider position) intentionally unused on OV5640 — logged
    // below as SHP=xx for diagnostic parity with the other cameras.

    #[cfg(not(feature = "silent"))]
    {
        let avg = crate::hw::camera::read_reg(i2c, 0x56A1).unwrap_or(0);
        crate::log!("[CAM-TUNE] AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X} AVG={:02X}",
            aec_h, aec_l, vals[2], vals[3], vals[4], vals[5], avg);
    }
}

#[cfg(feature = "waveshare")]
pub(crate) fn cam_tune_apply_ov2640<I2C: embedded_hal::i2c::I2c>(i2c: &mut I2C, vals: &[u8; 6]) {
    use crate::hw::camera_ov2640::{write_reg, read_reg, select_bank};

    // ── Sensor bank: AEC + AGC ──
    select_bank(i2c, 0x01);

    // AEC targets: AEW / AEB
    let aec_h = vals[0];
    let aec_l = if vals[1] > vals[0] { vals[0] } else { vals[1] };
    write_reg(i2c, 0x24, aec_h); // AEW
    write_reg(i2c, 0x25, aec_l); // AEB
    // VV: fast/slow zone thresholds — link to AEC range
    let vv = ((aec_h >> 1) & 0xF0) | ((aec_l >> 5) & 0x0F);
    write_reg(i2c, 0x26, vv);

    // AGC gain ceiling: COM9 bits[7:5]
    let agc_idx = (vals[4] >> 5) & 0x07;
    let com9 = read_reg(i2c, 0x14).unwrap_or(0x48);
    write_reg(i2c, 0x14, (com9 & 0x1F) | (agc_idx << 5));

    // ── DSP bank: SDE indirect (contrast + brightness) ──
    // Key: write all SDE data FIRST, then enable bitmask LAST.
    // Otherwise each BPADDR=0 write resets other effects.
    select_bank(i2c, 0x00);

    // Contrast: BPADDR=3 = contrast center, BPADDR=4 = contrast gain
    write_reg(i2c, 0x7C, 0x03); // BPADDR = 3
    write_reg(i2c, 0x7D, 0x40); // contrast center = 0x40
    write_reg(i2c, 0x7D, vals[2]); // auto-inc → BPADDR=4: contrast gain

    // Brightness: BPADDR=5 = brightness, BPADDR=6 = brightness sign
    write_reg(i2c, 0x7C, 0x05); // BPADDR = 5
    write_reg(i2c, 0x7D, vals[3]); // brightness value
    write_reg(i2c, 0x7D, 0x00); // auto-inc → BPADDR=6: sign (0=positive)

    // Enable bitmask LAST: bit[2] = contrast+brightness enable
    write_reg(i2c, 0x7C, 0x00); // BPADDR = 0 (SDE control)
    write_reg(i2c, 0x7D, 0x04); // enable contrast+brightness

    // Sharpness: DSP reg 0x92/0x93
    write_reg(i2c, 0x92, 0x01); // manual sharpness mode
    write_reg(i2c, 0x93, vals[5]); // sharpness level

    #[cfg(not(feature = "silent"))]
    {
        select_bank(i2c, 0x01);
        let avg = read_reg(i2c, 0x2F).unwrap_or(0); // YAVG
        crate::log!("[CAM-TUNE-2640] AEC={:02X}/{:02X} CTR={:02X} BRT={:02X} AGC={:02X} SHP={:02X} AVG={:02X}",
            aec_h, aec_l, vals[2], vals[3], vals[4], vals[5], avg);
    }
}
