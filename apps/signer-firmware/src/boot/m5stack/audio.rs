//! CoreS3 speaker initialization phase.
//!
//! Boot temporarily runs a silent circular transfer so AW88298 sees I2S clocks.
//! After amplifier setup the transfer is stopped and ownership of I2S TX plus
//! its DMA work buffer moves into `RuntimeAudio`, which remains local to the
//! application event loop.

use esp_hal::{Blocking, delay::Delay, i2c::master::I2c, i2s::master::I2sTx};

const SOUND_DMA_BYTES: usize = 4 * 4092;
type BootSoundTx = I2sTx<'static, Blocking>;
type BootSoundBuffer = [u8; SOUND_DMA_BYTES];

pub(crate) fn initialize(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
    mut tx: BootSoundTx,
    buffer: &'static mut BootSoundBuffer,
) -> Option<crate::hw::sound::RuntimeAudio> {
    crate::log!("   BOOT PHASE audio BEGIN");
    crate::log!("   I2S1 audio phase...");

    enable_amplifier_power(i2c, delay);
    buffer.fill(0);
    let clocks = match tx.write_dma_circular(&*buffer) {
        Ok(transfer) => transfer,
        Err(_) => {
            crate::log!("   I2S1 temporary clock DMA failed");
            crate::log!("   BOOT PHASE audio DONE (disabled)");
            return None;
        }
    };

    crate::log!("   AW88298 Speaker init...");
    let amplifier = crate::hw::sound::init_aw88298(i2c, delay);
    if clocks.stop().is_err() {
        crate::log!("   I2S1 temporary clock DMA stop reported an error");
    }
    if let Err(error) = amplifier {
        crate::log!("   AW88298 FAILED: {} (no sound)", error);
        crate::log!("   BOOT PHASE audio DONE (disabled)");
        return None;
    }

    let runtime_audio = crate::hw::sound::RuntimeAudio::new(tx, buffer);
    finish_audio_ready();
    crate::log!("   BOOT PHASE audio DONE");
    Some(runtime_audio)
}

fn enable_amplifier_power(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) {
    let _ = i2c.write(crate::hw::pmu::AW9523B_ADDR, &[0x02u8, 0x05u8]);
    delay.delay_millis(100);
}

fn finish_audio_ready() {
    crate::log!("   AW88298 OK — speaker enabled");
    crate::log!("   AW88298 owned runtime audio ready — preference pending");
}
