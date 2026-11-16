// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Kaspa's fork-invariant constants (upstream:
//! `consensus/core/src/constants.rs`): values independent of chain state, a
//! plain `const` upstream too.
//!
//! Kaspa's limits are absent by design: script size, element size,
//! operations per script, block mass and signature script length live in
//! `Params`, which a node builds for its network. An air-gapped device has no
//! chain tip or network handle; a DAA score or network name to pick a limit
//! by would arrive in the payload, so the attacker would choose the limit,
//! and the next fork would reopen that. The limits belong where the chain
//! tip is real, the integrator's side.
//!
//! These are consensus, not device policy, and must not mix with it: a
//! maximum input count is a memory budget, a supply cap a network rule. A
//! device's own ceiling is stated in its profile.

/// Sompi in one KAS.
pub const SOMPI_PER_KASPA: u64 = 100_000_000;

/// Maximum transaction amount in sompi: total supply. Upstream's
/// `check_transaction_output_value_ranges` refuses a value and a running
/// total above it.
pub const MAX_SOMPI: u64 = 29_000_000_000 * SOMPI_PER_KASPA;

/// Below this a lock time is a DAA score; at or above, a UNIX time in ms.
pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// Scales inverse KAS value into mass units. KIP-9.
pub const STORAGE_MASS_PARAMETER: u64 = SOMPI_PER_KASPA * 10_000;

/// Mass charged per byte of transient storage. KIP-13.
pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;

/// The transaction version in use before covenants.
pub const TX_VERSION: u16 = 0;

/// The transaction version with covenant output bindings, input compute
/// budgets, non-native subnetworks and gas: the one the signature hash
/// branches on.
pub const TX_VERSION_COVENANTS: u16 = 1;

/// Highest supported script public key version.
pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 0;

/// Largest sequence number an input can carry.
pub const MAX_TX_IN_SEQUENCE_NUM: u64 = u64::MAX;

/// Extracts the relative lock time from a sequence number.
pub const SEQUENCE_LOCK_TIME_MASK: u64 = 0x0000_0000_ffff_ffff;

/// Set on a sequence number, this disables relative lock time.
pub const SEQUENCE_LOCK_TIME_DISABLED: u64 = 1 << 63;

/// How a lock time is read (upstream: `get_lock_time_type`): zero is none,
/// below [`LOCK_TIME_THRESHOLD`] a DAA score, at or above it a timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockTime {
    /// No lock time.
    None,
    /// A DAA score the DAG must reach.
    DaaScore(u64),
    /// A UNIX timestamp in milliseconds.
    Timestamp(u64),
}

/// Classify a lock time against the threshold.
pub const fn classify_lock_time(lock_time: u64) -> LockTime {
    if lock_time == 0 {
        LockTime::None
    } else if lock_time < LOCK_TIME_THRESHOLD {
        LockTime::DaaScore(lock_time)
    } else {
        LockTime::Timestamp(lock_time)
    }
}

/// Whether a single value is within the supply cap. Values each legal can
/// still sum past it: see [`checked_add_value`].
pub const fn is_value_in_range(value: u64) -> bool {
    value <= MAX_SOMPI
}

/// Add to a running total; `None` for overflow or past the cap, never
/// clamped, as a clamped total is not the network's.
pub const fn checked_add_value(total: u64, value: u64) -> Option<u64> {
    if !is_value_in_range(value) {
        return None;
    }
    match total.checked_add(value) {
        Some(t) if t <= MAX_SOMPI => Some(t),
        _ => None,
    }
}
