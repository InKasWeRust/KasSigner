//! USB-host firmware-update presentation helpers.
//!
//! Firmware authenticity and anti-rollback are enforced by `services::verify`
//! during boot. Runtime firmware-update QR/SD image verification was retired;
//! Settings only provides host-assisted USB flashing guidance.

mod metadata;

pub use metadata::{format_version, CURRENT_VERSION};
