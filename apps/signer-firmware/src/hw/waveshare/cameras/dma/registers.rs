use crate::hw::shared::mmio::{read, set_bits, write};

const GDMA_BASE: u32 = 0x6003_F000;
const LCD_CAM_BASE: u32 = 0x6004_1000;
const SYSTEM_BASE: u32 = 0x600C_0000;

const GDMA_IN_CONF0: u32 = GDMA_BASE;
const GDMA_IN_CONF1: u32 = GDMA_BASE + 0x0004;
const GDMA_IN_INT_RAW: u32 = GDMA_BASE + 0x0008;
const GDMA_IN_INT_ENA: u32 = GDMA_BASE + 0x0010;
const GDMA_IN_INT_CLR: u32 = GDMA_BASE + 0x0014;
const GDMA_IN_LINK: u32 = GDMA_BASE + 0x0020;
const GDMA_IN_PRI: u32 = GDMA_BASE + 0x0044;
const GDMA_IN_PERI_SEL: u32 = GDMA_BASE + 0x0048;

const LCD_CAM_LCD_CLOCK: u32 = LCD_CAM_BASE;
const LCD_CAM_CAM_CTRL: u32 = LCD_CAM_BASE + 0x0004;
const LCD_CAM_CAM_CTRL1: u32 = LCD_CAM_BASE + 0x0008;

const INT_IN_DONE: u32 = 1 << 0;
const INT_IN_SUC_EOF: u32 = 1 << 1;
const INT_IN_DSCR_ERR: u32 = 1 << 3;

pub(super) fn configure() {
    unsafe {
        set_bits(SYSTEM_BASE + 0x001C, (1 << 6) | (1 << 8));
        set_bits(LCD_CAM_LCD_CLOCK, 1 << 31);

        write(GDMA_IN_CONF0, 1);
        delay_cycles(20);
        write(GDMA_IN_CONF0, 0);
        delay_cycles(10);
        write(GDMA_IN_CONF0, (1 << 2) | (1 << 3));
        write(GDMA_IN_CONF1, 0);
        write(GDMA_IN_PERI_SEL, 5);
        write(GDMA_IN_PRI, 9);
        write(GDMA_IN_INT_ENA, 0);
        write(GDMA_IN_INT_CLR, u32::MAX);

        let control = (2 << 29) | (12 << 9) | (1 << 8) | (7 << 1) | 1;
        write(LCD_CAM_CAM_CTRL, control);
        write(LCD_CAM_CAM_CTRL, control | (1 << 4));
        let control1 = 1u32 << 23;
        write(LCD_CAM_CAM_CTRL1, control1);
        write(LCD_CAM_CAM_CTRL1, control1 | (1 << 30));
        delay_cycles(20);
        write(LCD_CAM_CAM_CTRL1, control1 | (1 << 31));
        delay_cycles(20);
    }
}

pub(super) fn start(descriptor_address: u32) {
    unsafe {
        write(GDMA_IN_INT_CLR, u32::MAX);
        write(GDMA_IN_CONF0, 1);
        delay_cycles(20);
        write(GDMA_IN_CONF0, 0);
        delay_cycles(10);
        write(GDMA_IN_CONF0, (1 << 2) | (1 << 3));
        write(GDMA_IN_CONF1, 0);
        write(GDMA_IN_PERI_SEL, 5);
        write(GDMA_IN_PRI, 9);
        write(
            GDMA_IN_LINK,
            (descriptor_address & 0x000F_FFFF) | (1 << 20),
        );
        let camera_control = 1u32 << 23;
        write(LCD_CAM_CAM_CTRL1, camera_control | (1 << 31));
        delay_cycles(20);
        write(GDMA_IN_LINK, read(GDMA_IN_LINK) | (1 << 22));
        delay_cycles(10);
        write(LCD_CAM_CAM_CTRL1, camera_control | (1 << 29));
    }
}

pub(super) fn poll_end_of_frame() -> bool {
    let raw = unsafe { read(GDMA_IN_INT_RAW) };
    if raw & INT_IN_DONE != 0 {
        unsafe { write(GDMA_IN_INT_CLR, INT_IN_DONE) };
    }
    if raw & INT_IN_DSCR_ERR != 0 {
        unsafe { write(GDMA_IN_INT_CLR, INT_IN_DSCR_ERR) };
    }
    if raw & INT_IN_SUC_EOF == 0 {
        return false;
    }
    unsafe { write(GDMA_IN_INT_CLR, INT_IN_SUC_EOF) };
    true
}

pub(super) fn stop() {
    unsafe {
        write(LCD_CAM_CAM_CTRL1, read(LCD_CAM_CAM_CTRL1) & !(1 << 29));
        write(GDMA_IN_LINK, read(GDMA_IN_LINK) | (1 << 21));
    }
}

pub(super) fn status() -> (u32, u32, u32) {
    unsafe {
        (
            read(GDMA_IN_INT_RAW),
            read(GDMA_IN_LINK),
            read(LCD_CAM_CAM_CTRL1),
        )
    }
}

#[inline(always)]
fn delay_cycles(cycles: u32) {
    for _ in 0..cycles {
        unsafe { core::ptr::read_volatile(&0u32) };
    }
}
