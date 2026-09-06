//! Hardware primitives shared by every supported signer device.
//!
//! This module contains only chip-level or protocol-level code that is
//! independent of a concrete board layout. Board drivers consume these
//! primitives through `hw::waveshare` or `hw::m5stack`; application code uses
//! the board-neutral façade exported by `hw`.

pub(crate) mod core;
pub(crate) mod display;
pub(crate) mod dvp;
pub(crate) mod flash;
#[cfg(feature = "screenshot")]
pub(crate) mod display_support;
pub(crate) mod lockdown;
pub(crate) mod imu_health;
pub(crate) mod mmio;
pub(crate) mod registers;
#[cfg(feature = "screenshot")]
pub(crate) mod screenshot;
pub(crate) mod storage;
pub(crate) mod touch;
