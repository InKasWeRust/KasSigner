// Entropy-source orchestration and final whitening.

use esp_hal::{Blocking, delay::Delay, dma::DmaRxBuf, i2c::master::I2c, lcd_cam::cam::Camera};
use sha2::{Digest, Sha256};

use super::{ambient, camera, health::EntropyError, imu, mixer, platform, seed, trng};
/// Collect a seed-generation pool. Camera entropy is mandatory.
pub fn collect<'a>(
    delay: &mut Delay, liveness: &mut dyn FnMut(),
    i2c: &mut I2c<'_, Blocking>,
    idle_ticks: u32,
    camera_device: &mut Option<Camera<'a>>,
    dma_buffer: &mut Option<DmaRxBuf>,
    sd_card_type: &Option<crate::hw::sdcard::SdCardType>,
) -> Result<[u8; 32], EntropyError> {
    trng::enable_hardware_rng()?;
    let imu_initialized = imu::initialize(i2c, delay);

    let mut pool = [0u8; 32];
    let initial = seed::mix_initial(&mut pool, idle_ticks)?;
    #[cfg(feature = "e12-capture")]
    let mut e12_capture = crate::diagnostics::e12_capture::Capture::new().ok();
    let mut imu_pre = [0u8; imu::SEED_SAMPLE_BYTES];
    let imu_pre_count = collect_imu_window(i2c, delay, imu_initialized, &mut imu_pre);

    power_camera();
    #[cfg(feature = "waveshare")]
    delay.delay_millis(100);
    log!(
        "   RNG health: stuck {}/32 counter {}",
        initial.report.repeated_words,
        initial.report.counter_pattern
    );
    let camera_report = camera::mix_frames(
        &mut pool,
        #[cfg(feature = "m5stack")]
        i2c,
        delay, liveness, idle_ticks,
        camera_device,
        dma_buffer,
        #[cfg(feature = "e12-capture")]
        e12_capture.as_mut(),
    );
    log!(
        "   Camera health: frames {} live {}/{} stale-run {}",
        camera_report.frames_captured,
        camera_report.live_deltas,
        camera_report.deltas_observed,
        camera_report.max_consecutive_stale_deltas
    );
    #[cfg(feature = "e12-capture")]
    if let Some(capture) = e12_capture.take() {
        if sd_card_type.is_some() {
            if let Err(error) = capture.write_sd(i2c, delay) {
                crate::log!("   [E12] capture write failed: {}", error);
            }
        } else {
            crate::log!("   [E12] no SD card detected; capture discarded");
        }
    }
    #[cfg(not(feature = "e12-capture"))]
    let _ = sd_card_type;
    let mut imu_post = [0u8; imu::SEED_SAMPLE_BYTES];
    let imu_post_count = collect_imu_window(i2c, delay, imu_initialized, &mut imu_post);
    let pre_healthy = imu::mix_seed_sample(&mut pool, &mut imu_pre, imu_pre_count, 0x01);
    let post_healthy = imu::mix_seed_sample(&mut pool, &mut imu_post, imu_post_count, 0x02);
    log!(
        "   IMU entropy: pre {} post {}",
        if pre_healthy { "healthy" } else { "rejected" },
        if post_healthy { "healthy" } else { "rejected" }
    );
    #[cfg(feature = "m5stack")]
    if !(pre_healthy || post_healthy) {
        mixer::zeroize(&mut pool);
        return Err(EntropyError::ImuUnavailable);
    }
    let entropy_evidence = signer_firmware_core::security::SeedEntropyEvidence {
        camera: camera_report,
        hardware_rng_healthy: true,
        device_identity_mixed: initial.device_identity_mixed,
        timing_mixed: initial.timing_mixed,
    };
    log!(
        "   Entropy evidence: identity {} timing {}",
        if entropy_evidence.device_identity_mixed { "OK" } else { "FAIL" },
        if entropy_evidence.timing_mixed { "OK" } else { "FAIL" },
    );
    if let Err(error) = signer_firmware_core::security::validate_seed_entropy(entropy_evidence) {
        mixer::zeroize(&mut pool);
        return Err(error.into());
    }
    seed::whiten(&mut pool, idle_ticks)?;
    Ok(pool)
}

fn collect_imu_window(
    i2c: &mut I2c<'_, Blocking>,
    delay: &mut Delay,
    initialized: bool,
    output: &mut [u8; imu::SEED_SAMPLE_BYTES],
) -> usize {
    if !initialized { return 0; }
    imu::collect_seed_sample(i2c, delay, output)
}

/// Fill cryptographic randomness without silently accepting a failed RNG.
pub fn fill(output: &mut [u8]) -> Result<(), EntropyError> {
    output.fill(0);
    trng::enable_hardware_rng()?;
    let mut raw = [0u8; 128];
    trng::fill_words(&mut raw)?;

    let mut hasher = Sha256::new();
    hasher.update(raw);
    platform::update_systimer(&mut hasher);
    platform::update_mac(&mut hasher);
    ambient::mix_staged(&mut hasher);
    imu::mix_staged(&mut hasher);
    #[cfg(feature = "waveshare")]
    {
        let mut pixels = crate::services::memory::zeroed_bytes(4096)
            .map_err(|_| EntropyError::CameraUnavailable)?;
        let captured = crate::hw::cam_dma::copy_entropy_sample(&mut pixels);
        hasher.update(&pixels[..captured]);
        shared_signer::bytes::zeroize_bytes(&mut pixels);
    }
    hasher.update([0xE7, 0x21]);
    let mut seed: [u8; 32] = hasher.finalize().into();
    mixer::zeroize(&mut raw);

    for (counter, chunk) in output.chunks_mut(32).enumerate() {
        let mut expansion = Sha256::new();
        expansion.update(seed);
        expansion.update((counter as u32).to_le_bytes());
        let block = expansion.finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    mixer::zeroize(&mut seed);
    Ok(())
}

#[cfg(feature = "waveshare")]
fn power_camera() {
    crate::hw::camera_power::wake();
}

#[cfg(not(feature = "waveshare"))]
fn power_camera() {}
