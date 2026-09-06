//! Waveshare QMI8658C raw-gyro diagnostic. Diagnostic samples are not credited here; production entropy integration lives behind `hw::imu` and `services::entropy`.

use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

const ADDRESSES: [u8; 2] = [0x6B, 0x6A];
const WHO_AM_I: u8 = 0x00;
const EXPECTED_ID: u8 = 0x05;
const REG_CTRL1: u8 = 0x02;
const REG_CTRL3: u8 = 0x04;
const REG_CTRL5: u8 = 0x06;
const REG_CTRL7: u8 = 0x08;
const REG_STATUS0: u8 = 0x2E;
const CTRL1_ADDR_AUTO_INC: u8 = 1 << 6;
const CTRL3_GYRO_CFG: u8 = 0x40;
const CTRL5_NO_FILTER: u8 = 0x00;
const CTRL7_GYRO_ENABLE: u8 = 1 << 1;
const STATUS0_GYRO_DATA_READY: u8 = 1 << 1;
const GYRO_TURNON_MS: u32 = 70;
const GYRO_REGS: [(u8, u8); 3] = [(0x3B, 0x3C), (0x3D, 0x3E), (0x3F, 0x40)];

pub(crate) fn run(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) {
    let Some(address) = probe(i2c) else {
        crate::log!("[imu-dump] QMI8658C not found");
        return;
    };
    if !configure(i2c, address, delay) {
        crate::log!("[imu-dump] QMI8658C configuration failed");
        return;
    }
    crate::log!("[imu-dump] QMI8658C at 0x{:02X}; raw diagnostic samples only", address);
    for sample in 0..16u8 {
        if !wait_ready(i2c, address) {
            crate::log!("[imu-dump] {:02}: data-ready timeout", sample);
            continue;
        }
        let x = read_axis(i2c, address, GYRO_REGS[0]);
        let y = read_axis(i2c, address, GYRO_REGS[1]);
        let z = read_axis(i2c, address, GYRO_REGS[2]);
        crate::log!("[imu-dump] {:02}: x={:?} y={:?} z={:?}", sample, x, y, z);
        delay.delay_millis(5);
    }
}


pub(crate) fn run_and_halt(i2c: &mut I2c<'_, Blocking>, delay: &mut Delay) -> ! {
    run(i2c, delay);
    crate::halt_forever(delay)
}

fn probe(i2c: &mut I2c<'_, Blocking>) -> Option<u8> {
    ADDRESSES.into_iter().find(|address| read_reg(i2c, *address, WHO_AM_I) == Some(EXPECTED_ID))
}

fn configure(i2c: &mut I2c<'_, Blocking>, address: u8, delay: &mut Delay) -> bool {
    let configured = write_reg(i2c, address, REG_CTRL1, CTRL1_ADDR_AUTO_INC)
        && write_reg(i2c, address, REG_CTRL3, CTRL3_GYRO_CFG)
        && write_reg(i2c, address, REG_CTRL5, CTRL5_NO_FILTER)
        && write_reg(i2c, address, REG_CTRL7, CTRL7_GYRO_ENABLE);
    if configured {
        delay.delay_millis(GYRO_TURNON_MS);
    }
    configured
}

fn wait_ready(i2c: &mut I2c<'_, Blocking>, address: u8) -> bool {
    (0..64).any(|_| read_reg(i2c, address, REG_STATUS0).is_some_and(|status| status & STATUS0_GYRO_DATA_READY != 0))
}

fn read_reg(i2c: &mut I2c<'_, Blocking>, address: u8, register: u8) -> Option<u8> {
    let mut out = [0u8; 1];
    i2c.write_read(address, &[register], &mut out).ok()?;
    Some(out[0])
}

fn write_reg(i2c: &mut I2c<'_, Blocking>, address: u8, register: u8, value: u8) -> bool {
    i2c.write(address, &[register, value]).is_ok()
}

fn read_axis(i2c: &mut I2c<'_, Blocking>, address: u8, registers: (u8, u8)) -> Option<i16> {
    let low = read_reg(i2c, address, registers.0)?;
    let high = read_reg(i2c, address, registers.1)?;
    Some(i16::from_le_bytes([low, high]))
}
