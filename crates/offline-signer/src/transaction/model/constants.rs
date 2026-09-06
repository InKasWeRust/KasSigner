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

/// Initial input allocation used for ordinary transactions. This is a capacity
/// hint below the explicit `MAX_INPUTS` hardware resource ceiling.
pub const DEFAULT_INPUT_CAPACITY: usize = 8;

/// Maximum transaction inputs supported by the hardware signer.
/// Canonicalized through the public KasSigner capability contract so host
/// wallets cannot drift above or below the physical signer limit.
pub const MAX_INPUTS: usize = kassigner_protocol::SIGNER_CAPABILITIES.max_inputs as usize;

/// Maximum supported outputs (bumped from 4 to 8 for beacon-style multi-output TXs).
/// RAM cost: +1.2 KB in Transaction struct (heap-allocated via Box).
/// The signed TX size check (1024-byte buffer) uses actual counts,
/// so normal TXs are unaffected.
pub const MAX_OUTPUTS: usize = kassigner_protocol::SIGNER_CAPABILITIES.max_outputs as usize;

/// Maximum script size (P2PK=34, 2-of-3 multisig=102, 5-of-5=168)
pub const MAX_SCRIPT_SIZE: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_script_bytes as usize;

/// Maximum redeem script size (covenant scripts can exceed 255 bytes).
/// SPK arrays stay at MAX_SCRIPT_SIZE. Only the P2SH redeem buffer
/// uses this larger ceiling. RAM cost: +6 KB (8 inputs x 768 extra).
pub const MAX_REDEEM_SIZE: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_redeem_script_bytes as usize;

/// Maximum supported transaction payload size.
pub const MAX_PAYLOAD_SIZE: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_payload_bytes as usize;

/// Hash de 32 bytes (Blake2b / transaction ID)
pub type Hash256 = [u8; 32];

/// Subnetwork ID (20 bytes)
pub type SubnetworkId = [u8; 20];

/// Native subnetwork (all zeros)
pub const SUBNETWORK_ID_NATIVE: SubnetworkId = [0u8; 20];

// ─── Multisig Constants ──────────────────────────────────────────────

/// Maximum signatures per input (supports up to 5-of-5 multisig)
pub const MAX_SIGS_PER_INPUT: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_signatures_per_input as usize;

/// Maximum public keys in a multisig script
pub const MAX_MULTISIG_KEYS: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_multisig_keys as usize;

// ─── Kaspa Script Opcodes (subset for multisig parsing) ─────────────

/// Kaspa script opcodes used in P2PK and multisig scripts.
pub const OP_DATA_32: u8 = 0x20; // push 32 bytes
pub const OP_1: u8 = 0x51; // push value 1
pub const OP_2: u8 = 0x52; // push value 2
pub const OP_3: u8 = 0x53; // push value 3
pub const OP_4: u8 = 0x54; // push value 4
pub const OP_5: u8 = 0x55; // push value 5
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_CHECKMULTISIG: u8 = 0xAE;
pub const OP_BLAKE2B: u8 = 0xAA;
pub const OP_EQUAL: u8 = 0x87;

// ─── Transaction ──────────────────────────────────────────────────────

/// Shared pool size for redeem scripts that exceed MAX_SCRIPT_SIZE.
/// Covers worst case: one 1024-byte covenant + margin, or several
/// smaller scripts. Total RAM cost: 2048 bytes (in Box on heap).
pub const REDEEM_POOL_SIZE: usize = 2048;

// ═══════════════════════════════════════════════════════════════════
// Multisig Wallet Configuration (RAM-only, wiped on shutdown)
// ═══════════════════════════════════════════════════════════════════

/// Maximum multisig wallet configs stored simultaneously
pub const MAX_MULTISIG_WALLETS: usize =
    kassigner_protocol::SIGNER_CAPABILITIES.max_multisig_wallets as usize;
