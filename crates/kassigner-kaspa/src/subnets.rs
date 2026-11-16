// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Subnetwork identifiers (upstream: `consensus/core/src/subnets.rs`): 20
//! bytes, all zeros for the native one ordinary transactions use. Beyond
//! display, a signer needs it because the sighash skips the payload digest
//! only when the subnetwork is native *and* the payload empty.

/// Length of a subnetwork identifier, fixed by the format.
pub const SUBNETWORK_ID_SIZE: usize = 20;

/// A subnetwork identifier.
pub type SubnetworkId = [u8; SUBNETWORK_ID_SIZE];

/// The native subnetwork, every ordinary transaction's.
pub const SUBNETWORK_ID_NATIVE: SubnetworkId = [0u8; SUBNETWORK_ID_SIZE];

/// The coinbase subnetwork. A signer never produces one.
pub const SUBNETWORK_ID_COINBASE: SubnetworkId = {
    let mut id = [0u8; SUBNETWORK_ID_SIZE];
    id[0] = 1;
    id
};

/// The registry subnetwork.
pub const SUBNETWORK_ID_REGISTRY: SubnetworkId = {
    let mut id = [0u8; SUBNETWORK_ID_SIZE];
    id[0] = 2;
    id
};

/// True for the native subnetwork.
pub const fn is_native(id: &SubnetworkId) -> bool {
    let mut i = 0;
    while i < SUBNETWORK_ID_SIZE {
        if id[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// True for the coinbase and registry subnetworks, which a signer refuses
/// to build for: miners make coinbases, not wallets.
pub const fn is_builtin(id: &SubnetworkId) -> bool {
    let mut i = 1;
    while i < SUBNETWORK_ID_SIZE {
        if id[i] != 0 {
            return false;
        }
        i += 1;
    }
    id[0] == 1 || id[0] == 2
}
