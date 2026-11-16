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

//! What differs unit by unit: bring-up, halt reasons, what the console
//! says of the board, the tuner, the card session, Home's battery.

use super::*;

/// Home's battery, through the PMU on the M5Stack and the P4.
#[cfg(any(feature = "m5stack", feature = "p4"))]
pub(super) fn home_battery<L, C, D, T>(unit: &unit::Unit<L, C, D, T>) -> Option<Gauge> {
    Gauge::of(unit.battery())
}

/// The empty outline on the Waveshare, which runs without a cell: its
/// battery pin is on ADC1, which the random generator keeps for its
/// noise (`kassigner_hal_esp32s3::entropy`).
#[cfg(feature = "waveshare")]
pub(super) fn home_battery<L, C, D, T>(_: &unit::Unit<L, C, D, T>) -> Option<Gauge> {
    Some(Gauge::Empty)
}

#[cfg(feature = "waveshare")]
pub(super) fn bring_up(
    p: esp_hal::peripherals::Peripherals,
    heap: fn(esp_hal::peripherals::PSRAM<'static>) -> usize,
) -> Result<
    (
        unit::Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    unit::Failed<impl Display>,
> {
    use kassigner_hal_esp32s3::waveshare::sensor;
    let (u, c) = unit::bring_up(p, sensor::Module::AutoFocus, heap)?;
    out!(
        "sensor product id {:04X}, expected {:04X}",
        c.sensor_id,
        sensor::PRODUCT_ID
    );
    if !c.core1 {
        out!("core 1 would not start: nothing will decode");
    }
    if c.imu {
        out!("IMU running");
    }
    say_imu(c.imu, c.imu_failure);
    say_radio(c.radio_off);
    say_brownout(c.brownout);
    say_adc(c.adc);
    Ok((
        u,
        Checks {
            // Core 1 is the only decoder, as on every unit.
            ok: c.core1
                && c.sensor_id == sensor::PRODUCT_ID
                && c.rng
                && c.adc
                && c.radio_off
                && c.brownout.analog_reset,
            imu: c.imu,
        },
    ))
}

#[cfg(feature = "m5stack")]
pub(super) fn bring_up(
    p: esp_hal::peripherals::Peripherals,
    heap: fn(esp_hal::peripherals::PSRAM<'static>) -> usize,
) -> Result<
    (
        unit::Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    unit::Failed<impl Display>,
> {
    let (u, c) = unit::bring_up(p, heap)?;
    if !c.core1 {
        out!("core 1 would not start: nothing will decode");
    }
    if c.imu {
        out!(
            "IMU running; answered {} us after its reset",
            c.imu_reset_wait_us
        );
    }
    say_imu(c.imu, c.imu_failure);
    say_radio(c.radio_off);
    say_brownout(c.brownout);
    say_adc(c.adc);
    Ok((
        u,
        Checks {
            // Core 1 is the only decoder, as on every unit.
            ok: c.core1 && c.rng && c.adc && c.radio_off && c.brownout.analog_reset,
            imu: c.imu,
        },
    ))
}

#[cfg(feature = "p4")]
pub(super) fn bring_up(
    p: esp_hal::peripherals::Peripherals,
    heap: fn(esp_hal::peripherals::PSRAM<'static>) -> usize,
) -> Result<
    (
        unit::Unit<impl Display, impl Camera, impl Decoder, impl Touch>,
        Checks,
    ),
    unit::Failed<impl Display>,
> {
    let (u, c) = unit::bring_up(p, heap)?;
    if !c.core1 {
        out!("core 1 would not start: nothing will decode");
    }
    match c.touch {
        Some(t) => out!("touch controller {t:?}"),
        None => out!("touch controller not found"),
    }
    if !c.rom_table {
        out!("ROM routine table does not match this ROM");
    }
    say_radio(c.radio_off);
    say_brownout(c.brownout);
    // No IMU on this board.
    Ok((
        u,
        Checks {
            ok: c.core1
                && c.touch.is_some()
                && c.rng
                && c.rom_table
                && c.radio_off
                && c.brownout.mode1_reset,
            imu: false,
        },
    ))
}

/// The PANIC screen's reason for a board that failed after its panel came
/// up; the console names the error.
#[cfg(feature = "waveshare")]
pub(super) fn halt_reason(error: &unit::Error) -> &'static str {
    match error {
        unit::Error::Sensor | unit::Error::Camera => refusal::CAMERA_FAILED,
        unit::Error::Decoder => refusal::DECODER_FAILED,
        unit::Error::Generator(_) => refusal::GENERATOR_FAILED,
        _ => refusal::SELF_TEST,
    }
}

/// As the Waveshare's; `Camera` (the DMA and DVP set-up) is named on the
/// console.
#[cfg(feature = "m5stack")]
pub(super) fn halt_reason(error: &unit::Error) -> &'static str {
    match error {
        unit::Error::Sensor | unit::Error::Camera(_) => refusal::CAMERA_FAILED,
        unit::Error::Decoder => refusal::DECODER_FAILED,
        unit::Error::Generator(_) => refusal::GENERATOR_FAILED,
        _ => refusal::SELF_TEST,
    }
}

/// As the Waveshare's.
#[cfg(feature = "p4")]
pub(super) fn halt_reason(error: &unit::Error) -> &'static str {
    match error {
        unit::Error::Camera(_) => refusal::CAMERA_FAILED,
        unit::Error::Decoder => refusal::DECODER_FAILED,
        unit::Error::Entropy => refusal::GENERATOR_FAILED,
        _ => refusal::SELF_TEST,
    }
}

#[cfg(any(feature = "m5stack", feature = "waveshare"))]
pub(super) fn say_imu<F: core::fmt::Debug>(up: bool, failure: Option<F>) {
    if !up {
        out!("IMU did not start ({failure:?}); the camera and the touch screen carry the seed");
    }
}

/// Whether the radio is off (the S3's radio domain, the P4 board's
/// ESP32-C6), said on every boot: nothing else shows this check passed.
pub(super) fn say_radio(off: bool) {
    if off {
        out!("radio powered down");
    } else {
        out!("radio did not power down");
    }
}

/// The brown-out detector as the bootloader left it, said on every boot.
/// Its analog reset, which Espressif's bootloader sets, is in the
/// verdict: a unit without it fails the self-test. The adjustable
/// detector is reported and left alone.
#[cfg(any(feature = "m5stack", feature = "waveshare"))]
pub(super) fn say_brownout(b: kassigner_hal_esp32s3::brownout::State) {
    out!(
        "brown-out: detector {}, reset {}, analog reset {}{} (0x{:08x})",
        on_off(b.enabled),
        on_off(b.reset),
        on_off(b.analog_reset),
        if b.detected { ", low supply now" } else { "" },
        b.raw
    );
    if !b.analog_reset {
        out!("brown-out analog reset off: the self-test fails");
    }
}

/// As the S3 units'; of the P4's two modes, mode 1's (analog) reset is
/// in the verdict.
#[cfg(feature = "p4")]
pub(super) fn say_brownout(b: kassigner_hal_esp32p4::brownout::State) {
    out!(
        "brown-out: mode 0 reset {}, interrupt {}; mode 1 reset {} (0x{:08x}, 0x{:08x})",
        on_off(b.mode0_reset),
        on_off(b.mode0_interrupt),
        on_off(b.mode1_reset),
        b.raw.0,
        b.raw.1
    );
    if !b.mode1_reset {
        out!("brown-out mode 1 reset off: the self-test fails");
    }
}

/// A setting, as a boot line says it.
pub(super) fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// Whether the S3's SAR ADC was converting for the generator when it
/// seeded; if not, the self-test fails.
#[cfg(any(feature = "m5stack", feature = "waveshare"))]
pub(super) fn say_adc(sampling: bool) {
    if sampling {
        out!("generator: SAR ADC sampling");
    } else {
        out!("generator: SAR ADC not sampling");
    }
}

/// This unit's camera settings, for Settings' Camera: the M5's sensor
/// over a handle of its own on the shared bus.
#[cfg(feature = "m5stack")]
pub(super) fn tuner<L, C, D, T>(unit: &mut unit::Unit<L, C, D, T>) -> Option<impl Tune> {
    Some(kassigner_hal_esp32s3::m5stack::sensor::Tuner::new(
        unit.device(),
    ))
}

/// The Waveshare's, over the camera's own bus.
#[cfg(feature = "waveshare")]
pub(super) fn tuner<L, C, D, T>(unit: &mut unit::Unit<L, C, D, T>) -> Option<impl Tune + '_> {
    Some(kassigner_hal_esp32s3::waveshare::sensor::Tuner::new(
        &mut unit.cam_i2c,
    ))
}

/// The P4's, over the unit's shared bus.
#[cfg(feature = "p4")]
pub(super) fn tuner<L, C, D, T>(unit: &mut unit::Unit<L, C, D, T>) -> Option<impl Tune> {
    Some(kassigner_hal_esp32p4::cam::Tuner::new(unit.bus()))
}

/// A card session on the M5: the slot's power cycled and the bus taken
/// from the display, then given back. A session that cannot start is
/// no card.
#[cfg(feature = "m5stack")]
pub(super) fn card_session<L, C, D, T>(
    unit: &mut unit::Unit<L, C, D, T>,
    alive: &mut dyn FnMut(),
    job: Job,
    request: &mut Request<'_>,
) -> card::Outcome {
    use kassigner_hal_esp32s3::m5stack::storage;
    let mut i2c = unit.device();
    let session = storage::with_card(&mut i2c, |dev| {
        let kind = dev.card_type();
        card::run(job, kind, &mut card::Alive::new(dev, alive), request)
    });
    session.unwrap_or_else(|e| {
        out!("card: {e:?}");
        card::Outcome::Absent
    })
}

/// The Waveshare's: the pins it shares with the display routed to the
/// card for the session, then back.
#[cfg(feature = "waveshare")]
pub(super) fn card_session<L, C, D, T>(
    unit: &mut unit::Unit<L, C, D, T>,
    alive: &mut dyn FnMut(),
    job: Job,
    request: &mut Request<'_>,
) -> card::Outcome {
    use kassigner_hal_esp32s3::waveshare::sdhost;
    use kassigner_hal_esp32s3::waveshare::storage::WaveshareStorage;
    let mut i2c = unit.device();
    let session = sdhost::with_sd_card(&mut i2c, &mut SysTimer, |found| {
        let mut dev = WaveshareStorage::new(found).ok_or("No SD card")?;
        let kind = dev.card_type();
        Ok(card::run(
            job,
            kind,
            &mut card::Alive::new(&mut dev, alive),
            request,
        ))
    });
    session.unwrap_or_else(|e| {
        out!("card: {e}");
        card::Outcome::Absent
    })
}

/// The P4's: its slot is its own, so nothing is borrowed from the
/// display. A unit whose host would not set up has no card.
#[cfg(feature = "p4")]
pub(super) fn card_session<L, C, D, T>(
    unit: &mut unit::Unit<L, C, D, T>,
    alive: &mut dyn FnMut(),
    job: Job,
    request: &mut Request<'_>,
) -> card::Outcome {
    use kassigner_hal_esp32p4::storage;
    let Some(sd) = unit.card.as_mut() else {
        out!("card: no SD host");
        return card::Outcome::Absent;
    };
    let session = storage::with_card(sd, |dev| {
        let kind = dev.card_type();
        card::run(job, kind, &mut card::Alive::new(dev, alive), request)
    });
    session.unwrap_or_else(|e| {
        out!("card: {e:?}");
        card::Outcome::Absent
    })
}
