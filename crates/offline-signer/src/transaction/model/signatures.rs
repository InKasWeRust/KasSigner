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

// ─── Transaction Input ────────────────────────────────────────────────

/// Single signature slot within an input
#[derive(Debug, Clone)]
/// Signature attached to a transaction input.
pub struct InputSig {
    pub signature: [u8; 64],
    pub sighash_type: u8,
    pub pubkey_pos: u8, // position in multisig pubkey list (0-based), 0 for P2PK
    pub present: bool,
    /// 33-byte compressed secp256k1 pubkey that produced this signature.
    /// Populated by `sign_transaction_multisig` and `sign_transaction_multi_addr`
    /// in `transaction/kspt/signing/`. Needed only by the standard PSKT
    /// serializer (`std_pskt.rs`);
    /// KSPT emission ignores this field because KSPT identifies signers by
    /// `pubkey_pos` alone. Zero-initialized otherwise.
    pub pubkey_compressed: [u8; 33],
}

impl InputSig {
    pub const fn empty() -> Self {
        Self {
            signature: [0u8; 64],
            sighash_type: 0,
            pubkey_pos: 0,
            present: false,
            pubkey_compressed: [0u8; 33],
        }
    }
}

/// A partial signature received in an incoming PSKT, keyed by full pubkey.
///
/// Unlike `InputSig` (which is positional in the multisig redeem script),
/// `IncomingPartialSig` carries the full 33-byte compressed pubkey so the
/// signer can identify its own contribution and round-trip foreign partial
/// sigs without losing them.
///
/// Only populated when the input came from a PSKT payload; unused
/// (all slots `present=false`) before compact KSPT signatures are populated.
#[derive(Debug, Clone, Copy)]
pub struct IncomingPartialSig {
    /// 33-byte compressed secp256k1 public key.
    /// PSKT `partialSigs` is keyed by this.
    pub pubkey: [u8; 33],
    /// 64-byte Schnorr signature.
    pub signature: [u8; 64],
    /// False means this slot is unused.
    pub present: bool,
}

impl IncomingPartialSig {
    pub const fn empty() -> Self {
        Self {
            pubkey: [0u8; 33],
            signature: [0u8; 64],
            present: false,
        }
    }
}
