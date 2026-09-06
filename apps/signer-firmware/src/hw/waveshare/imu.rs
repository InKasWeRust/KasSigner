//! QMI8658C gyroscope entropy source for the Waveshare board.
//!
//! The IMU is supplemental: its absence or degradation never substitutes for
//! the mandatory checked TRNG/camera gates. Only fresh low-byte gyro samples
//! that pass a point-of-use diversity check are credited by the entropy
//! service.

use core::sync::atomic::{AtomicU8, Ordering};
use esp_hal::{Blocking, delay::Delay, i2c::master::I2c};

const ADDR_CANDIDATES: [u8; 2] = [0x6B, 0x6A];
const REG_WHO_AM_I: u8 = 0x00;
const REG_CTRL1: u8 = 0x02;
const REG_CTRL3: u8 = 0x04;
const REG_CTRL5: u8 = 0x06;
const REG_CTRL7: u8 = 0x08;
const REG_STATUS0: u8 = 0x2E;
const REG_GX_L: u8 = 0x3B;
const REG_GY_L: u8 = 0x3D;
const REG_GZ_L: u8 = 0x3F;
const WHO_AM_I_VALUE: u8 = 0x05;
const CTRL1_ADDR_AUTO_INC: u8 = 1 << 6;
const CTRL3_GYRO_8KHZ_256DPS: u8 = 0x40;
const CTRL5_FILTER_OFF: u8 = 0x00;
const CTRL7_GYRO_ENABLE: u8 = 1 << 1;
const STATUS0_GYRO_DATA_READY: u8 = 1 << 1;
const GYRO_TURNON_MS: u32 = 70;
const BOOT_HEALTH_BYTES: usize = 33;
const ADDR_ABSENT: u8 = 1;

static IMU_ADDR: AtomicU8 = AtomicU8::new(0);

fn write_reg(i2c: &mut I2c<'_, Blocking>, addr: u8, reg: u8, value: u8) -> bool {
    i2c.write(addr, &[reg, value]).is_ok()
}

fn read_reg(i2c: &mut I2c<'_, Blocking>, addr: u8, reg: u8) -> Option<u8> {
    let mut value = [0u8; 1];
    i2c.write_read(addr, &[reg], &mut value).ok()?;
    Some(value[0])
}

pub fn axis_distinct(bytes: &[u8]) -> [u32; 3] {
    crate::hw::shared::imu_health::axis_distinct(bytes)
}

pub fn buffer_is_healthy(bytes: &[u8]) -> bool {
    crate::hw::shared::imu_health::buffer_is_healthy(bytes)
}
fn cached_status() -> Option<bool> {
    match IMU_ADDR.load(Ordering::Relaxed) {
        0 => None,
        ADDR_ABSENT => Some(false),
        _ => Some(true),
    }
}

fn probe_address(i2c: &mut I2c<'_, Blocking>) -> Option<u8> {
    ADDR_CANDIDATES
        .into_iter()
        .find(|address| read_reg(i2c, *address, REG_WHO_AM_I) == Some(WHO_AM_I_VALUE))
}

fn configure(i2c: &mut I2c<'_, Blocking>, address: u8) -> bool {
    write_reg(i2c, address, REG_CTRL1, CTRL1_ADDR_AUTO_INC)
        && write_reg(i2c, address, REG_CTRL3, CTRL3_GYRO_8KHZ_256DPS)
        && write_reg(i2c, address, REG_CTRL5, CTRL5_FILTER_OFF)
        && write_reg(i2c, address, REG_CTRL7, CTRL7_GYRO_ENABLE)
}

fn boot_health(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> ([u32; 3], bool) {
    let mut probe = [0u8; BOOT_HEALTH_BYTES];
    let mut count = collect(i2c, delay, &mut probe);
    if count != probe.len() || !buffer_is_healthy(&probe[..count]) {
        delay.delay_millis(50);
        probe.fill(0);
        count = collect(i2c, delay, &mut probe);
    }
    let healthy = count == probe.len() && buffer_is_healthy(&probe);
    let distinct = axis_distinct(&probe[..count]);
    shared_signer::bytes::zeroize_bytes(&mut probe);
    (distinct, healthy)
}

/// Probe, configure, and health-check the QMI8658C once at boot.
pub fn init(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> bool {
    if let Some(status) = cached_status() {
        return status;
    }
    let Some(address) = probe_address(i2c) else {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        crate::log!("   [imu] QMI8658C not found; supplemental entropy unavailable");
        return false;
    };
    if !configure(i2c, address) {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        crate::log!("   [imu] QMI8658C configuration failed; supplemental entropy unavailable");
        return false;
    }

    delay.delay_millis(GYRO_TURNON_MS);
    IMU_ADDR.store(address, Ordering::Relaxed);
    let (distinct, healthy) = boot_health(i2c, delay);
    if !healthy {
        IMU_ADDR.store(ADDR_ABSENT, Ordering::Relaxed);
        crate::log!(
            "   [imu] QMI8658C health rejected: distinct X{} Y{} Z{}",
            distinct[0], distinct[1], distinct[2]
        );
        return false;
    }
    crate::log!(
        "   [imu] QMI8658C 0x{:02X} healthy: distinct X{} Y{} Z{} of {}",
        address, distinct[0], distinct[1], distinct[2], BOOT_HEALTH_BYTES / 3
    );
    true
}

fn active_address() -> Option<u8> {
    let address = IMU_ADDR.load(Ordering::Relaxed);
    (address != 0 && address != ADDR_ABSENT).then_some(address)
}

fn gyro_ready(i2c: &mut I2c<'_, Blocking>, address: u8) -> Option<bool> {
    Some(read_reg(i2c, address, REG_STATUS0)? & STATUS0_GYRO_DATA_READY != 0)
}

fn wait_ready(i2c: &mut I2c<'_, Blocking>, address: u8, delay: &mut Delay) -> bool {
    for _ in 0..16 {
        if gyro_ready(i2c, address).unwrap_or(false) {
            return true;
        }
        delay.delay_micros(150);
    }
    false
}

fn read_triplet(i2c: &mut I2c<'_, Blocking>, address: u8) -> Option<[u8; 3]> {
    Some([
        read_reg(i2c, address, REG_GX_L)?,
        read_reg(i2c, address, REG_GY_L)?,
        read_reg(i2c, address, REG_GZ_L)?,
    ])
}

fn read_fresh_triplet(
    i2c: &mut I2c<'_, Blocking>,
    address: u8,
    delay: &mut Delay,
) -> Option<[u8; 3]> {
    if !wait_ready(i2c, address, delay) {
        return None;
    }
    read_triplet(i2c, address)
}

/// Collect fresh low-byte gyro noise. A short read is returned as a short read;
/// callers must health-check the exact bytes before assigning entropy credit.
pub fn collect(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay, output: &mut [u8]) -> usize {
    let Some(address) = active_address() else {
        return 0;
    };
    let mut written = 0usize;
    for chunk in output.chunks_mut(3) {
        let Some(sample) = read_fresh_triplet(i2c, address, delay) else {
            break;
        };
        for (destination, source) in chunk.iter_mut().zip(sample) {
            *destination = source;
            written += 1;
        }
    }
    written
}
