pub(crate) mod allowance;
mod builder;
mod fee;
mod model;
pub(crate) mod payjoin;
mod selection;
pub(crate) mod shipping;
pub(crate) mod sweep;
pub(crate) mod vault;

pub(crate) use builder::{build, build_with_binding};
pub(crate) use fee::CovenantFeeShape;
pub(crate) use model::{CovenantBuildRequest, CovenantEncoding};

pub(crate) mod global_thread;
pub(crate) mod oracle_v1;
pub(crate) mod private_swap;
pub(crate) mod sweeps;
#[cfg(test)]
mod unit_tests;
