//! BMI270 gyroscope entropy adapter for M5Stack CoreS3.
//!
//! The exact-pinned `bmi2` crate performs Bosch's required configuration-file
//! upload. KasSigner owns normal-mode activation, startup/freshness timing,
//! sampling, diversity checks, zeroization, and the fail-closed seed policy.

use core::sync::atomic::{AtomicBool, Ordering};
use bmi2::{config, types::{Burst, PwrCtrl}, Bmi2, I2cAddr};
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

const BMI270_ADDR: u8 = 0x69;
const BMI270_CHIP_ID: u8 = 0x24;
const REG_ERROR: u8 = 0x02;
const REG_STATUS: u8 = 0x03;
const REG_GYR_X_LSB: u8 = 0x12;
const REG_INTERNAL_STATUS: u8 = 0x21;
const REG_ACC_CONF: u8 = 0x40;
const REG_GYR_CONF: u8 = 0x42;
const REG_GYR_RANGE: u8 = 0x43;
const REG_PWR_CONF: u8 = 0x7C;
const REG_PWR_CTRL: u8 = 0x7D;
const GYR_DATA_READY: u8 = 1 << 6;
const FATAL_ERROR: u8 = 1 << 0;
const INTERNAL_STATUS_INITIALIZED: u8 = 0x01;
// Bosch datasheet normal-mode example: 100 Hz accel and 200 Hz gyro with
// normal bandwidth/performance filtering. KasSigner samples only the gyro; the
// accel/temp enables are transient support state for the documented startup
// sequence and receive no entropy credit.
const ACC_CONF_NORMAL_100HZ: u8 = 0xA8;
const GYR_CONF_NORMAL_200HZ: u8 = 0xA9;
// Use ±250 dps for entropy sampling so the BMI270's documented normal-mode
// noise is observable at the raw low-byte resolution without relaxing the
// point-of-use diversity gate. This affects entropy acquisition only.
const GYR_RANGE_ENTROPY_250DPS: u8 = 0x03;
// Disable advanced power save while retaining FIFO self-wakeup, per the
// documented normal-mode example.
const PWR_CONF_NORMAL: u8 = 0x02;
const PWR_CTRL_NORMAL: u8 = 0x06;
const CONFIG_SETTLE_MS: u32 = 150;
const GYRO_STARTUP_MS: u32 = 350;
const GYRO_SAMPLE_INTERVAL_MS: u32 = 6;
const READY_POLLS: usize = 80;
const READY_POLL_US: u32 = 250;
const BOOT_HEALTH_BYTES: usize = 33;
const BMI270_DRIVER_BUFFER_BYTES: usize = 512;
static READY: AtomicBool = AtomicBool::new(false);

fn read_reg(i2c: &mut I2c<'_, Blocking>, register: u8) -> Option<u8> {
    let mut value = [0u8; 1];
    i2c.write_read(BMI270_ADDR, &[register], &mut value).ok()?;
    Some(value[0])
}

fn write_reg(i2c: &mut I2c<'_, Blocking>, register: u8, value: u8) -> bool {
    i2c.write(BMI270_ADDR, &[register, value]).is_ok()
}

pub fn axis_distinct(bytes: &[u8]) -> [u32; 3] {
    crate::hw::shared::imu_health::axis_distinct(bytes)
}

pub fn buffer_is_healthy(bytes: &[u8]) -> bool {
    crate::hw::shared::imu_health::buffer_is_healthy(bytes)
}
fn upload_config(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    // Reborrow the bus/delay so KasSigner can apply the documented runtime
    // configuration after the bmi2 configuration uploader is dropped.
    let mut bmi = Bmi2::<_, _, BMI270_DRIVER_BUFFER_BYTES>::new_i2c(
        &mut *i2c,
        &mut *delay,
        I2cAddr::Alternative,
        Burst::new(255),
    );
    if bmi.get_chip_id().ok() != Some(BMI270_CHIP_ID) { return false; }
    if bmi.init(&config::BMI270_CONFIG_FILE).is_err() { return false; }
    // Use the driver's typed power-control path while the BMI2 interface owns
    // the bus. This is the crate's documented post-init sequence and avoids
    // raw PWR_CTRL writes being ignored while BMI270 power-save handling is active.
    bmi.set_pwr_ctrl(PwrCtrl {
        aux_en: false,
        gyr_en: true,
        acc_en: true,
        temp_en: false,
    }).is_ok()
}

fn write_named_reg(
    i2c: &mut I2c<'_, Blocking>,
    register: u8,
    value: u8,
    name: &str,
) -> bool {
    if write_reg(i2c, register, value) { return true; }
    crate::log!("   [imu] BMI270 {} write failed", name);
    false
}

fn write_normal_mode(i2c: &mut I2c<'_, Blocking>) -> bool {
    // Follow Bosch's documented normal-mode register sequence exactly rather
    // than using the earlier unvalidated gyro-only variant.
    write_named_reg(i2c, REG_ACC_CONF, ACC_CONF_NORMAL_100HZ, "ACC_CONF")
        && write_named_reg(i2c, REG_GYR_CONF, GYR_CONF_NORMAL_200HZ, "GYR_CONF")
        && write_named_reg(i2c, REG_GYR_RANGE, GYR_RANGE_ENTROPY_250DPS, "GYR_RANGE")
        && write_named_reg(i2c, REG_PWR_CONF, PWR_CONF_NORMAL, "PWR_CONF")
}

fn mode_registers_match(
    pwr_ctrl: Option<u8>,
    acc_conf: Option<u8>,
    gyr_conf: Option<u8>,
    gyr_range: Option<u8>,
    pwr_conf: Option<u8>,
) -> bool {
    [pwr_ctrl, acc_conf, gyr_conf, gyr_range, pwr_conf]
        == [
            Some(PWR_CTRL_NORMAL),
            Some(ACC_CONF_NORMAL_100HZ),
            Some(GYR_CONF_NORMAL_200HZ),
            Some(GYR_RANGE_ENTROPY_250DPS),
            Some(PWR_CONF_NORMAL),
        ]
}

fn normal_mode_matches(i2c: &mut I2c<'_, Blocking>) -> bool {
    let pwr_ctrl = read_reg(i2c, REG_PWR_CTRL);
    let acc_conf = read_reg(i2c, REG_ACC_CONF);
    let gyr_conf = read_reg(i2c, REG_GYR_CONF);
    let gyr_range = read_reg(i2c, REG_GYR_RANGE);
    let pwr_conf = read_reg(i2c, REG_PWR_CONF);
    if mode_registers_match(pwr_ctrl, acc_conf, gyr_conf, gyr_range, pwr_conf) { return true; }
    crate::log!(
        "   [imu] BMI270 mode readback PWR_CTRL={:?} ACC_CONF={:?} GYR_CONF={:?} GYR_RANGE={:?} PWR_CONF={:?}",
        pwr_ctrl, acc_conf, gyr_conf, gyr_range, pwr_conf
    );
    false
}

fn initialized(i2c: &mut I2c<'_, Blocking>) -> bool {
    read_reg(i2c, REG_INTERNAL_STATUS)
        .map(|status| status & 0x0f == INTERNAL_STATUS_INITIALIZED)
        .unwrap_or(false)
}

fn fatal_error(i2c: &mut I2c<'_, Blocking>) -> bool {
    read_reg(i2c, REG_ERROR).unwrap_or(FATAL_ERROR) & FATAL_ERROR != 0
}

fn wait_ready(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    for _ in 0..READY_POLLS {
        if read_reg(i2c, REG_STATUS).unwrap_or(0) & GYR_DATA_READY != 0 { return true; }
        delay.delay_micros(READY_POLL_US);
    }
    false
}

fn read_fresh_triplet(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> Option<[u8; 3]> {
    if !wait_ready(i2c, delay) { return None; }
    let mut raw = [0u8; 6];
    i2c.write_read(BMI270_ADDR, &[REG_GYR_X_LSB], &mut raw).ok()?;
    // At 200 Hz a new gyro frame arrives every 5 ms. Waiting 6 ms before the
    // next read prevents one asserted DRDY level from being sampled repeatedly.
    delay.delay_millis(GYRO_SAMPLE_INTERVAL_MS);
    Some([raw[0], raw[2], raw[4]])
}

pub fn collect(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay, output: &mut [u8]) -> usize {
    if !READY.load(Ordering::Acquire) { return 0; }
    let mut written = 0usize;
    for chunk in output.chunks_mut(3) {
        let Some(sample) = read_fresh_triplet(i2c, delay) else { break; };
        for (destination, source) in chunk.iter_mut().zip(sample) {
            *destination = source;
            written += 1;
        }
    }
    written
}

fn boot_health(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> ([u32; 3], bool) {
    let mut sample = [0u8; BOOT_HEALTH_BYTES];
    let count = collect(i2c, delay, &mut sample);
    let healthy = count == sample.len() && buffer_is_healthy(&sample);
    let distinct = axis_distinct(&sample[..count]);
    shared_signer::bytes::zeroize_bytes(&mut sample);
    (distinct, healthy)
}

fn activate(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    if !write_normal_mode(i2c) || !normal_mode_matches(i2c) {
        crate::log!("   [imu] BMI270 normal-mode register setup failed");
        return false;
    }
    // Bosch documents a gyro startup drive test that can take up to ~320 ms.
    delay.delay_millis(GYRO_STARTUP_MS);
    if fatal_error(i2c) {
        crate::log!("   [imu] BMI270 reported fatal error after gyro startup");
        return false;
    }
    true
}

fn prepare(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    if !upload_config(i2c, delay) {
        crate::log!("   [imu] BMI270 config/chip-id check failed");
        return false;
    }
    delay.delay_millis(CONFIG_SETTLE_MS);
    if !initialized(i2c) {
        crate::log!("   [imu] BMI270 config upload did not reach initialized state");
        return false;
    }
    activate(i2c, delay)
}

/// Configure and point-of-use health-check the CoreS3 BMI270.
pub fn init(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    if READY.load(Ordering::Acquire) { return true; }
    if !prepare(i2c, delay) { return false; }
    READY.store(true, Ordering::Release);
    let (distinct, healthy) = boot_health(i2c, delay);
    if healthy {
        crate::log!("   [imu] BMI270 0x69 healthy: distinct X{} Y{} Z{} of {}",
            distinct[0], distinct[1], distinct[2], BOOT_HEALTH_BYTES / 3);
    } else {
        // A low-diversity diagnostic window does not mean the configured BMI270
        // disappeared. Keep the operational latch set so the mandatory pre/post
        // seed windows can collect fresh samples and enforce the same health gate.
        crate::log!("   [imu] BMI270 health sample rejected: distinct X{} Y{} Z{}; seed windows will retry",
            distinct[0], distinct[1], distinct[2]);
    }
    true
}
