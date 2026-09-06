mod address_index;
mod descriptor;
mod redeem_script;

pub use address_index::{resolve_address_path, ResolvedMultisigPath};
pub use descriptor::MultisigDescriptor;
pub use redeem_script::build_redeem_script;

#[cfg(test)]
mod unit_tests;
