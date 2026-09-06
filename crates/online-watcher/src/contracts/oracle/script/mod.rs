//! Oracle Model-B covenant script façade.

use crate::{
    contracts::zk::cost::RISC0_TAG,
    protocol::script::{opcode as covenant_ops, push_data, push_int},
};

mod constants;
mod consume;
mod heartbeat;
mod publish;

pub use constants::{
    ORACLE_MB_BODY_LEN, ORACLE_MB_HEARTBEAT_SIG_OP_COUNT, ORACLE_MB_MAX_FEE_SOMPI,
    ORACLE_MB_REDEEM_LEN, ORACLE_MB_SIG_OP_COUNT,
};
pub use consume::build_oracle_mb_consumer_sig_script;
pub use heartbeat::{build_oracle_mb_heartbeat_script, build_oracle_mb_heartbeat_sig_script};
pub use publish::{
    build_oracle_mb_genesis_redeem, build_oracle_mb_passthrough_sig_script,
    build_oracle_mb_publish_sig_script, build_oracle_mb_redeem,
};

use constants::OP_WITHIN;
