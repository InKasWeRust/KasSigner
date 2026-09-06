// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::{input::Ms45Hint, script::ScriptPublicKey};

// ─── Transaction Output ───────────────────────────────────────────────

/// Transaction output
#[derive(Debug, Clone)]
/// A transaction output: amount + destination script.
pub struct TransactionOutput {
    pub value: u64, // sompi
    pub script_public_key: ScriptPublicKey,
    /// Covenant binding (KIP-20, tx version >= 1)
    pub has_covenant: bool,
    pub covenant_auth_input: u16,
    pub covenant_id: [u8; 32],
    /// Optional non-authoritative wallet derivation hint supplied by the watcher.
    /// The signer must independently derive and match the actual output before
    /// classifying it as wallet-owned or change. Branch 0=receive, 1=change.
    pub derivation_branch: u8,
    pub derivation_index: u32,
    pub has_derivation_hint: bool,
    /// Coordinated-multisig derivation claim from an output
    /// `bip32Derivations` map. It is advisory until a loaded descriptor
    /// reproduces the actual output script hash.
    pub ms45_hint: Ms45Hint,
}

impl TransactionOutput {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            value: 0,
            script_public_key: ScriptPublicKey::new(),
            has_covenant: false,
            covenant_auth_input: 0,
            covenant_id: [0u8; 32],
            derivation_branch: 0,
            derivation_index: 0,
            has_derivation_hint: false,
            ms45_hint: Ms45Hint::none(),
        }
    }
}
