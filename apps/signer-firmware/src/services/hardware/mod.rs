//! Controller-facing hardware effect facades.
//!
//! Controllers may render through `BootDisplay` and request operations through
//! these focused services, but board drivers, raw buses, DMA and PMU details stay
//! below this boundary.

pub(crate) mod audio;
pub(crate) mod camera_device;
#[cfg(feature = "waveshare")]
pub(crate) mod power;
pub(crate) mod storage_device;
pub(crate) mod timing;
pub(crate) mod touch_recovery;
