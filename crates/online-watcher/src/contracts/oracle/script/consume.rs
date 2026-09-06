//! Oracle consumer signature scripts.

use super::push_data;

/// Keyless consumer signature script: push only the revealed redeem script.
/// The covenant read executes on the empty stack left after the P2SH redeem pop.
pub fn build_oracle_mb_consumer_sig_script(redeem: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(redeem.len() + 4);
    push_data(&mut script, redeem);
    script
}
