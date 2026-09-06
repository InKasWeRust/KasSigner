//! Shared volatile 32-bit ESP32-S3 MMIO operations.
//!
//! Callers remain responsible for using valid mapped peripheral addresses.

#[inline(always)]
pub(crate) unsafe fn read(address: u32) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

#[inline(always)]
pub(crate) unsafe fn write(address: u32, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) };
}

#[inline(always)]
pub(crate) unsafe fn set_bits(address: u32, mask: u32) {
    unsafe { write(address, read(address) | mask) };
}

#[inline(always)]
pub(crate) unsafe fn clear_bits(address: u32, mask: u32) {
    unsafe { write(address, read(address) & !mask) };
}
