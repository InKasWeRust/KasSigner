//! Firmware hardware-security policy generated from `release-policy.env`.
//!
//! The package version lives only in Cargo metadata. The security version is
//! the ESP32-S3 anti-rollback eFuse epoch and is intentionally independent.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
const fn parse_u32(value: &str) -> u32 {
    let bytes = value.as_bytes();
    assert!(!bytes.is_empty(), "release policy value is empty");
    let mut result = 0u32;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(byte >= b'0' && byte <= b'9', "release policy must be decimal");
        result = result * 10 + (byte - b'0') as u32;
        index += 1;
    }
    result
}

pub const SECURITY_VERSION: u32 = parse_u32(env!("KASSIGNER_SECURITY_VERSION"));
const _: () = assert!(
    SECURITY_VERSION > 0 && SECURITY_VERSION <= 16,
    "ESP32-S3 security version must be 1..=16"
);
