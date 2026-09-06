//! Waveshare camera hardware.

#[cfg(feature = "af")]
pub(crate) mod af_firmware;
pub(crate) mod decode_core;
pub(crate) mod dma;
pub(crate) mod ov2640;
pub(crate) mod ov5640;
pub(crate) mod power;
