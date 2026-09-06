//! ESP32-S3 hardware anti-rollback identity and runtime policy.
//!
//! The ESP-IDF second-stage bootloader consumes `secure_version` from the
//! 256-byte application descriptor and compares it with monotonic eFuse state.

#[cfg(not(feature = "qemu"))]
use esp_hal::efuse::{Efuse, SECURE_VERSION};

pub const APP_SECURITY_VERSION: u32 = if cfg!(feature = "production") {
    crate::release_policy::SECURITY_VERSION
} else {
    0
};
const APP_DESC_MAGIC: u32 = 0xABCD_5432;
const APP_DESC_BYTES: usize = 256;
const SECURE_VERSION_OFFSET: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AntiRollbackError {
    #[cfg(all(feature = "m5stack", feature = "production"))]
    Unprovisioned,
    ImageBelowDeviceFloor,
}

#[cfg(not(feature = "qemu"))]
pub fn device_security_version() -> u32 {
    Efuse::read_field_le::<u16>(SECURE_VERSION).count_ones()
}

#[cfg(feature = "qemu")]
pub fn device_security_version() -> u32 {
    0
}

pub fn verify_device_floor() -> Result<u32, AntiRollbackError> {
    let floor = device_security_version();
    #[cfg(all(feature = "m5stack", feature = "production"))]
    if floor == 0 && crate::services::verify::boot_security::secure_boot_enabled() {
        return Err(AntiRollbackError::Unprovisioned);
    }
    if descriptor_security_version() < floor {
        return Err(AntiRollbackError::ImageBelowDeviceFloor);
    }
    Ok(floor)
}

// The ESP-IDF application descriptor ABI is exactly 256 bytes and begins with
// magic:u32 then secure_version:u32. Using one aligned byte blob avoids a Rust
// field model whose only reader would be the external bootloader/tooling.
#[repr(C, align(4))]
struct AlignedAppDescriptor([u8; APP_DESC_BYTES]);

const fn descriptor_bytes() -> [u8; APP_DESC_BYTES] {
    let mut output = [0u8; APP_DESC_BYTES];
    write_u32(&mut output, 0, APP_DESC_MAGIC);
    write_u32(&mut output, SECURE_VERSION_OFFSET, APP_SECURITY_VERSION);
    write_cstr(&mut output, 16, 32, env!("CARGO_PKG_VERSION"));
    write_cstr(&mut output, 48, 32, env!("CARGO_PKG_NAME"));
    write_cstr(&mut output, 80, 16, esp_bootloader_esp_idf::BUILD_TIME);
    write_cstr(&mut output, 96, 16, esp_bootloader_esp_idf::BUILD_DATE);
    write_cstr(&mut output, 112, 32, esp_bootloader_esp_idf::ESP_IDF_COMPATIBLE_VERSION);
    write_u16(&mut output, 176, 0);
    write_u16(&mut output, 178, u16::MAX);
    output[180] = esp_bootloader_esp_idf::MMU_PAGE_SIZE.ilog2() as u8;
    output
}

const fn write_u32(output: &mut [u8; APP_DESC_BYTES], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    output[offset] = bytes[0];
    output[offset + 1] = bytes[1];
    output[offset + 2] = bytes[2];
    output[offset + 3] = bytes[3];
}

const fn write_u16(output: &mut [u8; APP_DESC_BYTES], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    output[offset] = bytes[0];
    output[offset + 1] = bytes[1];
}

const fn write_cstr(
    output: &mut [u8; APP_DESC_BYTES],
    offset: usize,
    capacity: usize,
    text: &str,
) {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && index + 1 < capacity {
        output[offset + index] = bytes[index];
        index += 1;
    }
}

#[cfg(not(feature = "qemu"))]
fn descriptor_security_version() -> u32 {
    u32::from_le_bytes([
        ESP_APP_DESC_WITH_SECURITY_VERSION.0[SECURE_VERSION_OFFSET],
        ESP_APP_DESC_WITH_SECURITY_VERSION.0[SECURE_VERSION_OFFSET + 1],
        ESP_APP_DESC_WITH_SECURITY_VERSION.0[SECURE_VERSION_OFFSET + 2],
        ESP_APP_DESC_WITH_SECURITY_VERSION.0[SECURE_VERSION_OFFSET + 3],
    ])
}

#[cfg(feature = "qemu")]
fn descriptor_security_version() -> u32 {
    APP_SECURITY_VERSION
}

// esp-bootloader-esp-idf 0.2 hard-codes secure_version=0 in its macro. Export
// the same 256-byte ESP-IDF ABI with the monotonic application version instead.
// QEMU keeps the dependency-provided descriptor from main.rs.
#[cfg(not(feature = "qemu"))]
#[used]
#[unsafe(export_name = "esp_app_desc")]
#[unsafe(link_section = ".rodata_desc.appdesc")]
static ESP_APP_DESC_WITH_SECURITY_VERSION: AlignedAppDescriptor =
    AlignedAppDescriptor(descriptor_bytes());
