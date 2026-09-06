pub(crate) mod application;
mod encoder;
pub(crate) mod global_thread;
mod model;
mod preparation;
mod sweep;
mod thread_input;
mod thread_policy;
mod thread_request;

pub use encoder::{encode_pskt_value, encode_wire};
pub use model::{CovenantInputSettings, PskbGlobalPlan, PskbInputPlan, PskbOutputPlan, PskbPlan};
pub(crate) use preparation::{
    encode_prepared_sweep, prepare_selected_sweep, prepare_sweep_from_utxos, PreparedSweep,
};
pub use sweep::{plan_sweep, SweepInputPolicy};

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use thread_policy::topup_policy_for;
pub use thread_policy::GlobalThreadPolicy;
pub(crate) use thread_policy::{withdrawal_policy_for, GlobalThreadFamily};

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use thread_input::select_wallet_utxos;
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use thread_request::build_topup as build_global_thread_topup;
pub(crate) use thread_request::{
    build_withdrawal as build_global_thread_withdrawal, PreparedWithdrawal, WithdrawalBuildRequest,
};
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) use thread_request::{
    prepare_topup_material as prepare_global_thread_topup_material, PreparedTopup,
};
