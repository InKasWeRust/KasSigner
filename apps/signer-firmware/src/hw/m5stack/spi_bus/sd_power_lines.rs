//! CoreS3 SD-line electrical quiesce/restore around the switched ALDO4 rail.
//!
//! The board pulls the microSD SPI lines up from the always-on 3.3 V domain.
//! Driving every card-facing line low while ALDO4 is off prevents IO-clamp
//! back-power from defeating a requested card cold reset.

use core::ptr;

use crate::hw::shared::registers::esp32s3::{
    GPIO_ENABLE1_W1TS, GPIO_FUNC_OUT_SEL_BASE, GPIO_OUT1_W1TC,
};

const GPIO_OUT_W1TS: u32 = 0x6000_4008;
const GPIO_OUT_W1TC: u32 = 0x6000_400C;
const GPIO_ENABLE_W1TS: u32 = 0x6000_4024;
const GPIO_ENABLE1_W1TC: u32 = 0x6000_4034;
const GPIO_MATRIX_GPIO_OUT: u32 = 256;
const FSPICLK_OUT_IDX: u32 = 101;
const FSPIQ_OUT_IDX: u32 = 102;
const FSPID_OUT_IDX: u32 = 103;
const SD_CS_BIT: u32 = 1 << 4;
const MISO_BIT: u32 = 1 << 3;
const SCK_BIT: u32 = 1 << 4;
const MOSI_BIT: u32 = 1 << 5;
const SHARED_SPI_BITS: u32 = MISO_BIT | SCK_BIT | MOSI_BIT;

pub(super) fn quiesce() {
    unsafe {
        write_register(GPIO_OUT_W1TC, SD_CS_BIT);
        write_register(GPIO_OUT1_W1TC, SHARED_SPI_BITS);
        for pin in [35, 36, 37] {
            write_register(output_selector(pin), GPIO_MATRIX_GPIO_OUT);
        }
        write_register(GPIO_ENABLE_W1TS, SD_CS_BIT);
        write_register(GPIO_ENABLE1_W1TS, SHARED_SPI_BITS);
    }
}

pub(super) fn restore() {
    unsafe {
        // Deselect the card before restoring peripheral-driven SCK/MOSI.
        write_register(GPIO_OUT_W1TS, SD_CS_BIT);
        write_register(output_selector(36), FSPICLK_OUT_IDX);
        write_register(output_selector(37), FSPID_OUT_IDX);
        write_register(output_selector(35), FSPIQ_OUT_IDX);
        write_register(GPIO_ENABLE1_W1TS, SCK_BIT | MOSI_BIT);
        write_register(GPIO_ENABLE1_W1TC, MISO_BIT);
    }
}

const fn output_selector(pin: u32) -> u32 {
    GPIO_FUNC_OUT_SEL_BASE + pin * 4
}

unsafe fn write_register(address: u32, value: u32) {
    unsafe { ptr::write_volatile(address as *mut u32, value) };
}
