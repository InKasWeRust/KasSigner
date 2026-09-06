//! Oracle script constants.

use crate::contracts::zk::cost::RISC0_SIG_OP_COUNT;

pub(super) const OP_WITHIN: u8 = 0xa5;

pub const ORACLE_MB_HEARTBEAT_SIG_OP_COUNT: u8 = 0;
pub const ORACLE_MB_MAX_FEE_SOMPI: u64 = 1_000_000;
pub const ORACLE_MB_BODY_LEN: u64 = 288;
pub const ORACLE_MB_SIG_OP_COUNT: u8 = RISC0_SIG_OP_COUNT;
pub const ORACLE_MB_REDEEM_LEN: u64 = 308;
