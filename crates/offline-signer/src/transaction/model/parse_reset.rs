//! Bounded parser reset for dynamically sized transaction models.

use crate::address::KaspaNetwork;

use super::{Transaction, SUBNETWORK_ID_NATIVE};

impl Transaction {
    /// Prepare the transaction model for an untrusted parser without walking
    /// every retained dynamic input slot. Parsers reinitialize each slot before
    /// they populate it, so malformed input cannot turn a previously grown
    /// input vector into an unbounded clear-time denial of service.
    ///
    /// `clear()` remains the explicit full-wipe operation. This parser reset
    /// still wipes bounded sensitive/transient fields and makes all previous
    /// inputs/outputs logically unreachable.
    pub(crate) fn prepare_for_parse(&mut self) {
        self.version = 0;
        self.num_inputs = 0;
        self.num_outputs = 0;
        self.network = KaspaNetwork::Unknown;
        self.locktime = 0;
        self.subnetwork_id = SUBNETWORK_ID_NATIVE;
        self.gas = 0;
        self.payload.fill(0);
        self.payload_len = 0;
        self.stealth_tweak.fill(0);
        self.has_stealth_tweak = false;
        self.redeem_pool.fill(0);
        self.redeem_pool_used = 0;
    }
}
