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

// wallet/transaction.rs — Kaspa transaction structures, script parsing, multisig

// KasSigner — Kaspa Transaction Types
// 100% Rust, no-std, no-alloc
//
// Types representing Kaspa transactions as received by
// KasSigner from the companion app (via QR/KSPT).
//
// Note: we use fixed arrays and maximum limits because we have no allocator.
// A typical Kaspa transaction has 1-5 inputs and 1-2 outputs.
// We support up to MAX_INPUTS=32 and MAX_OUTPUTS=8.

/// Maximum supported inputs.
///
/// Raised 8 -> 16 once the QR transport stopped being the constraint:
/// a 16-in/1-out consolidation KSPT is 1,533 bytes = 8 frames at 210 B,
/// ~3.6s at the 450ms sender period (it was 15 frames x 1.6s = 24s under
/// the old transport). Cost of the raise: the per-input slots live inside
/// the Box<Transaction> on the PSRAM heap (~2 KB each, so ~16 KB more),
/// the signed response (~2.6 KB for 16 inputs) still fits the 4 KB
/// signed_qr_buf, and signing time scales linearly with input count.
/// The multiframe wire ceiling (40 frames x 210 B = 8.4 KB) allows far
/// more; 16 doubles capability while staying trivially inside every
/// buffer. The [.; 8] arrays in pskt.rs sign paths are seed-slot
/// (account) indexed, not input indexed — unaffected.
pub const MAX_INPUTS: usize = 32;

/// Maximum supported outputs (bumped from 4 to 8 for beacon-style multi-output TXs).
/// RAM cost: +1.2 KB in Transaction struct (heap-allocated via Box).
/// The signed TX size check (1024-byte buffer) uses actual counts,
/// so normal TXs are unaffected.
pub const MAX_OUTPUTS: usize = 8;

/// Maximum script size (P2PK=34, 2-of-3 multisig=102, 5-of-5=168)
pub const MAX_SCRIPT_SIZE: usize = 512;

/// Maximum redeem script size (covenant scripts can exceed 255 bytes).
/// SPK arrays stay at MAX_SCRIPT_SIZE. Only the P2SH redeem buffer
/// uses this larger ceiling. RAM cost: +6 KB (8 inputs x 768 extra).
pub const MAX_REDEEM_SIZE: usize = 1024;

/// Maximum payload size (768 bytes supports adaptor-swap full recovery data)
pub const MAX_PAYLOAD_SIZE: usize = 768;

/// Hash de 32 bytes (Blake2b / transaction ID)
pub type Hash256 = [u8; 32];

/// Subnetwork ID (20 bytes)
pub type SubnetworkId = [u8; 20];

/// Native subnetwork (all zeros)
pub const SUBNETWORK_ID_NATIVE: SubnetworkId = [0u8; 20];

// ─── SigHash Types ────────────────────────────────────────────────────

/// Tipos de SigHash (Kaspa usa bitfield, diferente a Bitcoin)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
/// Kaspa sighash type — determines which parts of the transaction are signed.
pub enum SigHashType {
    All         = 0b0000_0001,
    None        = 0b0000_0010,
    Single      = 0b0000_0100,
    AnyOneCanPay = 0b1000_0000,
    // Combinaciones
    AllAnyOneCanPay    = 0b1000_0001,
    NoneAnyOneCanPay   = 0b1000_0010,
    SingleAnyOneCanPay = 0b1000_0100,
}

impl SigHashType {
    /// Parse a sighash type from its byte representation.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0b0000_0001 => Some(Self::All),
            0b0000_0010 => Some(Self::None),
            0b0000_0100 => Some(Self::Single),
            0b1000_0001 => Some(Self::AllAnyOneCanPay),
            0b1000_0010 => Some(Self::NoneAnyOneCanPay),
            0b1000_0100 => Some(Self::SingleAnyOneCanPay),
            _ => Option::None,
        }
    }

    /// Convert to the wire byte representation.
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Returns true if this is an ANYONE_CAN_PAY variant.
    pub fn is_anyone_can_pay(self) -> bool {
        (self.to_byte() & 0b1000_0000) != 0
    }

    /// Returns true if this is a SIGHASH_NONE variant.
    pub fn is_sighash_none(self) -> bool {
        (self.to_byte() & 0b0000_0010) != 0
    }

    /// Returns true if this is a SIGHASH_SINGLE variant.
    pub fn is_sighash_single(self) -> bool {
        (self.to_byte() & 0b0000_0100) != 0
    }
}

// ─── Outpoint ─────────────────────────────────────────────────────────

/// Reference to a previous output (transaction ID + index)
#[derive(Debug, Clone)]
/// A transaction outpoint: previous tx ID + output index.
pub struct Outpoint {
    pub transaction_id: Hash256,
    pub index: u32,
}

// ─── Script Public Key ────────────────────────────────────────────────

/// ScriptPubKey with version (Kaspa versions its scripts)
#[derive(Debug, Clone)]
/// Script public key with version byte (Kaspa uses version 0).
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
}

impl Default for ScriptPublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptPublicKey {
    pub fn new() -> Self {
        Self {
            version: 0,
            script: [0u8; MAX_SCRIPT_SIZE],
            script_len: 0,
        }
    }

        /// Get the raw script bytes.
pub fn script_bytes(&self) -> &[u8] {
        &self.script[..self.script_len]
    }
}

// ─── UTXO Entry (previous output being spent) ──────────────────

/// UTXO entry being spent (provided by companion app)
#[derive(Debug, Clone)]
/// Unspent transaction output entry (amount + script + metadata).
pub struct UtxoEntry {
    pub amount: u64,                  // sompi (1 KAS = 100_000_000 sompi)
    pub script_public_key: ScriptPublicKey,
    /// Whether this coin belongs to a covenant, and which.
    ///
    /// Upstream carries it as `covenant_id: Option<Hash>` on `UtxoEntry`, and
    /// the engine groups inputs by it (`crypto/txscript/src/covenants.rs`) to
    /// decide whether an output binding continues the same covenant or begins
    /// a new one: equal to the authorizing input's id means continuation,
    /// otherwise genesis, which is then validated by recomputing the id.
    ///
    /// The device needs it to say anything true about the covenant id it
    /// displays. Everything else on the confirm screen, the amount and the
    /// destination, the user verifies directly, and a genesis id is a pure
    /// function of those, so recomputing one proves nothing new. Whether a
    /// spend stays inside the covenant it is spending from is the one fact on
    /// that screen the device cannot otherwise check.
    ///
    /// A flag plus a plain array rather than `Option`, matching `TxOutput` and
    /// safe under the `core::mem::zeroed()` in `Transaction::new`.
    pub has_covenant: bool,
    pub covenant_id: [u8; 32],
}

// ─── Multisig Constants ──────────────────────────────────────────────

/// Maximum signatures per input (supports up to 5-of-5 multisig)
pub const MAX_SIGS_PER_INPUT: usize = 5;

/// Maximum public keys in a multisig script
pub const MAX_MULTISIG_KEYS: usize = 5;

// ─── Kaspa Script Opcodes (subset for multisig parsing) ─────────────

/// Kaspa script opcodes used in P2PK and multisig scripts.
pub const OP_DATA_32: u8 = 0x20; // push 32 bytes
pub const OP_1: u8 = 0x51;       // push value 1
pub const OP_2: u8 = 0x52;       // push value 2
pub const OP_3: u8 = 0x53;       // push value 3
pub const OP_4: u8 = 0x54;       // push value 4
pub const OP_5: u8 = 0x55;       // push value 5
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_CHECKMULTISIG: u8 = 0xAE;
pub const OP_BLAKE2B: u8 = 0xAA;
pub const OP_EQUAL: u8 = 0x87;

// ─── Multisig Script Info ────────────────────────────────────────────

/// Parsed multisig script: M-of-N with extracted pubkeys
#[derive(Debug, Clone)]
/// Detected M-of-N multisig parameters from a script.
pub struct MultisigInfo {
    pub m: u8,  // required signatures
    pub n: u8,  // total pubkeys
    pub pubkeys: [[u8; 32]; MAX_MULTISIG_KEYS],
}

impl Default for MultisigInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigInfo {
    pub fn new() -> Self {
        Self { m: 0, n: 0, pubkeys: [[0u8; 32]; MAX_MULTISIG_KEYS] }
    }
}

/// Script type detected from scriptPublicKey
#[derive(Debug, Clone, Copy, PartialEq)]
/// Detected script type (P2PK, P2SH, multisig, or unknown).
pub enum ScriptType {
    /// Standard P2PK Schnorr: OP_DATA_32 <pubkey> OP_CHECKSIG
    P2PK,
    /// P2SH: OP_BLAKE2B OP_DATA_32 <script_hash> OP_EQUAL
    P2SH,
    /// M-of-N multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    Multisig,
    /// Unknown/unsupported script
    Unknown,
}

/// Can the review screen render this OUTPUT script as an address?
///
/// E21. `draw_tx_page` decodes an output to an address only for these two
/// shapes; anything else fell through to a `Script: ` line showing the first
/// EIGHT bytes and `...`, while SigHashAll committed all of it, up to
/// MAX_SCRIPT_SIZE of 512. The user approved a destination having seen eight
/// bytes of it, and script prefixes are shared, so the visible part can look
/// ordinary while everything that matters sits past it.
///
/// Both parsers refuse an output that fails this, so such a transaction never
/// reaches review. Refusing what cannot be described is the defensible default
/// for a signer, and every Kaspa address is one of these two forms, so any
/// output an ordinary wallet produces passes.
///
/// Deliberately NOT `detect_script_type(..) != Unknown`. That also accepts bare
/// multisig, which the screen cannot render either: `encode_address_str` takes a
/// 32-byte key or hash and a bare multisig script is neither, so it landed in
/// the same eight-byte fallback. The rule has to match the display, not the
/// parser.
///
/// INPUTS ARE NOT SUBJECT TO THIS. A P2SH input's scriptPublicKey is P2SH, but
/// what matters there is the redeem script behind it, which is how every
/// covenant and every multisig is spent. Restricting inputs would break the
/// product.
pub fn is_displayable_output_script(script: &[u8], len: usize) -> bool {
    // P2PK: OP_DATA_32 <pubkey> OP_CHECKSIG
    if len == 34 && script[0] == OP_DATA_32 && script[33] == OP_CHECKSIG {
        return true;
    }
    // P2SH: OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL
    if len == 35 && script[0] == OP_BLAKE2B && script[1] == OP_DATA_32 && script[34] == OP_EQUAL {
        return true;
    }
    false
}

/// Parse a scriptPublicKey and detect its type
pub fn detect_script_type(script: &[u8], len: usize) -> ScriptType {
    if len == 34 && script[0] == OP_DATA_32 && script[33] == OP_CHECKSIG {
        return ScriptType::P2PK;
    }
    // P2SH: OP_BLAKE2B(0xAA) OP_DATA_32(0x20) <32-byte hash> OP_EQUAL(0x87) = 35 bytes
    if len == 35 && script[0] == OP_BLAKE2B && script[1] == OP_DATA_32 && script[34] == OP_EQUAL {
        return ScriptType::P2SH;
    }
    // Multisig: OP_m [OP_DATA_32 <32 bytes>]xN OP_n OP_CHECKMULTISIG
    //
    // The bound is the N=1 length: 1 + 1*33 + 1 + 1. It exists only to make the
    // two trailing indexes below safe; `len == expected_len` further down is
    // what actually validates the length, per N. It read 37 until v1.0.8, which
    // matched neither the N=1 minimum of 36 nor the N=2 minimum of 69, and its
    // only effect was to reject a 1-of-1 by one byte.
    if len >= 36 && script[len - 1] == OP_CHECKMULTISIG {
        let n_byte = script[len - 2];
        let m_byte = script[0];
        if (OP_1..=OP_5).contains(&m_byte) && (OP_1..=OP_5).contains(&n_byte) {
            let m = (m_byte - OP_1 + 1) as usize;
            let n = (n_byte - OP_1 + 1) as usize;
            if m <= n && n <= MAX_MULTISIG_KEYS {
                // Expected length: 1 (OP_m) + N*(1+32) (OP_DATA_32 + pubkey) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
                let expected_len = 1 + n * 33 + 1 + 1;
                if len == expected_len {
                    // Verify each pubkey push is OP_DATA_32
                    let mut valid = true;
                    for i in 0..n {
                        if script[1 + i * 33] != OP_DATA_32 {
                            valid = false;
                            break;
                        }
                    }
                    if valid {
                        return ScriptType::Multisig;
                    }
                }
            }
        }
    }
    ScriptType::Unknown
}

/// Parse a multisig scriptPublicKey, extracting M, N, and pubkeys.
/// Returns None if not a valid multisig script.
pub fn parse_multisig_script(script: &[u8], len: usize) -> Option<MultisigInfo> {
    if detect_script_type(script, len) != ScriptType::Multisig {
        return None;
    }
    let m = script[0] - OP_1 + 1;
    let n = script[len - 2] - OP_1 + 1;
    let mut info = MultisigInfo::new();
    info.m = m;
    info.n = n;
    for i in 0..n as usize {
        let start = 1 + i * 33 + 1; // skip OP_m + i*(OP_DATA_32+pubkey) + OP_DATA_32
        info.pubkeys[i].copy_from_slice(&script[start..start + 32]);
    }
    Some(info)
}

// ─── Transaction Input ────────────────────────────────────────────────

/// Single signature slot within an input
#[derive(Debug, Clone)]
/// Signature attached to a transaction input.
pub struct InputSig {
    pub signature: [u8; 64],
    pub sighash_type: u8,
    pub pubkey_pos: u8,  // position in multisig pubkey list (0-based), 0 for P2PK
    pub present: bool,
    /// 33-byte compressed secp256k1 pubkey that produced this signature.
    /// Populated by `sign_transaction_multisig` and `sign_transaction_multi_addr`
    /// in wallet/pskt.rs. Needed only by the PSKT serializer (std_pskt.rs);
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
/// (all slots `present=false`) for the legacy KSPT flow.
#[derive(Debug, Clone, Copy)]
pub struct IncomingPartialSig {
    /// 33-byte compressed secp256k1 public key.
    /// PSKT `partialSigs` is keyed by this.
    pub pubkey:    [u8; 33],
    /// 64-byte Schnorr signature.
    pub signature: [u8; 64],
    /// False means this slot is unused.
    pub present:   bool,
}

impl IncomingPartialSig {
    pub const fn empty() -> Self {
        Self { pubkey: [0u8; 33], signature: [0u8; 64], present: false }
    }
}

/// Transaction input with support for multiple signatures (multisig)
#[derive(Debug, Clone)]
/// A transaction input: references a UTXO and provides a signature.
pub struct TransactionInput {
    pub previous_outpoint: Outpoint,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub utxo_entry: UtxoEntry,
    /// Signatures — up to MAX_SIGS_PER_INPUT for multisig
    pub sigs: [InputSig; MAX_SIGS_PER_INPUT],
    pub sig_count: u8,
    // Legacy single-sig aliases (first slot) for backward compat
    pub signature: [u8; 64],
    pub sig_len: u8,
    pub sighash_type: u8,
    /// P2SH redeem script (the actual multisig script inside the P2SH wrapper).
    /// For scripts <= 256 bytes, stored inline here.
    /// For scripts > 256 bytes (covenants), stored in Transaction::redeem_pool
    /// and redeem_script_offset points into that pool.
    pub redeem_script: [u8; MAX_SCRIPT_SIZE],
    pub redeem_script_len: usize,
    /// If true, this input's redeem script lives in Transaction::redeem_pool
    /// at byte offset redeem_script_offset, not in the inline redeem_script array.
    pub redeem_in_pool: bool,
    pub redeem_script_offset: u16,
    /// Partial signatures carried in an incoming PSKT, keyed by full pubkey.
    /// Preserved byte-for-byte on re-serialization so counterparty signers
    /// see the same PSKT they sent, plus our additions. Empty for KSPT flow.
    pub incoming_partial_sigs: [IncomingPartialSig; MAX_SIGS_PER_INPUT],
    pub incoming_partial_sigs_count: u8,
    /// 45' derivation hint from the PSKB's `bip32_derivations`, if present.
    ///
    /// The path of the ADDRESS BEING SPENT, not of any particular signer: every
    /// cosigner of a 45' input derives at the same
    /// `m/45'/111111'/account'/cosigner/chain/index`, so one path serves all of
    /// them and this device's own cosigner index is irrelevant here.
    ///
    /// **UNTRUSTED.** It arrives in the same PSKB an attacker could craft, so it
    /// says where to LOOK and never what to trust. The signing path must derive
    /// at this path and then verify the resulting pubkey actually appears in
    /// this input's redeem script, which is what the P2SH address hashes to and
    /// what the user approved on screen. Signing on the strength of the hint
    /// alone would let a crafted PSKB walk the device down any path it likes.
    pub ms45_hint: Ms45Hint,
}

/// A 45' derivation hint for one input.
///
/// `present` false means no usable hint arrived and the signer must search.
#[derive(Debug, Clone, Copy)]
pub struct Ms45Hint {
    pub present: bool,
    pub cosigner: u32,
    pub chain: u32,
    pub index: u32,
}

impl Ms45Hint {
    pub const fn none() -> Self {
        Self { present: false, cosigner: 0, chain: 0, index: 0 }
    }
}

// ─── Transaction Output ───────────────────────────────────────────────

/// Transaction output
#[derive(Debug, Clone)]
/// A transaction output: amount + destination script.
pub struct TransactionOutput {
    pub value: u64,                    // sompi
    pub script_public_key: ScriptPublicKey,
    /// Covenant binding (KIP-20, tx version >= 1)
    pub has_covenant: bool,
    pub covenant_auth_input: u16,
    pub covenant_id: [u8; 32],
    /// The 45' derivation path this output CLAIMS to belong to, from its own
    /// `bip32Derivations` map.
    ///
    /// A claim, not a fact. It is what makes change verifiable at all: an output
    /// paying back to this wallet is a P2SH address that only the FULL cosigner
    /// set can reproduce, so one seed cannot check it. With a matching
    /// descriptor loaded the device rebuilds the address at this path and either
    /// confirms it as change or catches the claim as false.
    ///
    /// Without a descriptor the claim is unverifiable and the output must be
    /// shown as outgoing, with the user told why - the device cannot save you
    /// from a payload it cannot check, but it can refuse to pretend.
    pub ms45_hint: Ms45Hint,
}

// ─── Transaction ──────────────────────────────────────────────────────

/// Does any output make a change claim that a TRUSTED descriptor contradicts?
///
/// Returns the output index of the first forgery found.
///
/// "Trusted" is doing the work. A descriptor is trusted for this transaction
/// when it reproduces one of the transaction's own INPUTS at that input's hinted
/// path - that proves it is this wallet's key set, not merely some descriptor
/// the user happens to have loaded. Only then does its failure on an OUTPUT mean
/// anything.
///
/// Three outcomes, and only this one is an attack:
///   - no trusted descriptor        -> unknown, the user's risk to take
///   - trusted, output reproduces   -> genuine change
///   - trusted, output does NOT     -> the claim is FALSE
///
/// A forged claim cannot be constructed without the whole cosigner set, and
/// anyone holding that already knows the real addresses. So a mismatch here is
/// someone trying to have change approved for an address that is not ours.
pub fn find_forged_change(
    tx: &Transaction,
    configs: &[MultisigConfig],
) -> Option<usize> {
    // Is any loaded descriptor trusted for this transaction?
    let mut trusted: Option<&MultisigConfig> = None;
    'outer: for c in configs.iter() {
        if !c.active {
            continue;
        }
        for i in 0..tx.num_inputs {
            let ispk = &tx.inputs[i].utxo_entry.script_public_key;
            if ispk.script_len != 35 {
                continue;
            }
            let mut ish = [0u8; 32];
            ish.copy_from_slice(&ispk.script[2..34]);
            if c.matches_at(&tx.inputs[i].ms45_hint, &ish) {
                trusted = Some(c);
                break 'outer;
            }
        }
    }
    let c = trusted?;

    for o in 0..tx.num_outputs {
        let out = &tx.outputs[o];
        if !out.ms45_hint.present {
            continue;
        }
        let spk = &out.script_public_key;
        if spk.script_len != 35 || spk.script[0] != 0xAA || spk.script[34] != 0x87 {
            continue;
        }
        // An output that pays back to an input's own script is change by byte
        // equality and needs no derivation - not a forgery, whatever it claims.
        let mut same_as_input = false;
        for i in 0..tx.num_inputs {
            let ispk = &tx.inputs[i].utxo_entry.script_public_key;
            if ispk.script_len == spk.script_len
                && ispk.script[..ispk.script_len] == spk.script[..spk.script_len]
            {
                same_as_input = true;
                break;
            }
        }
        if same_as_input {
            continue;
        }
        let mut sh = [0u8; 32];
        sh.copy_from_slice(&spk.script[2..34]);
        if !c.matches_at(&out.ms45_hint, &sh) {
            return Some(o);
        }
    }
    None
}

/// Shared pool size for redeem scripts that exceed MAX_SCRIPT_SIZE.
/// Covers worst case: one 1024-byte covenant + margin, or several
/// smaller scripts. Total RAM cost: 2048 bytes (in Box on heap).
pub const REDEEM_POOL_SIZE: usize = 4096; // 32 inputs x 128-byte redeems

/// `store_redeem` refused the script: it exceeds `MAX_REDEEM_SIZE`, or the
/// shared redeem pool has no room left for it.
///
/// A named type rather than `()`: the two call sites in `pskt.rs` map it to
/// `PsktError::ScriptTooLong`, and a bare `Err(())` says nothing about why
/// a signing input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemTooLong;

/// Complete Kaspa transaction (for signing)
#[derive(Debug)]
/// A complete Kaspa transaction with inputs, outputs, and metadata.
pub struct Transaction {
    pub version: u16,
    pub inputs: [TransactionInput; MAX_INPUTS],
    pub num_inputs: usize,
    pub outputs: [TransactionOutput; MAX_OUTPUTS],
    pub num_outputs: usize,
    pub locktime: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: [u8; MAX_PAYLOAD_SIZE],
    pub payload_len: usize,
    /// Stealth address tweak: if non-zero, the signing key is
    /// account_privkey + stealth_tweak (scalar addition mod n).
    /// Set by KasSee when spending a stealth UTXO.
    pub stealth_tweak: [u8; 32],
    pub has_stealth_tweak: bool,
    /// Shared pool for redeem scripts > MAX_SCRIPT_SIZE bytes.
    /// Inputs with `redeem_in_pool == true` store their redeem data here
    /// at `redeem_script_offset..redeem_script_offset + redeem_script_len`.
    pub redeem_pool: [u8; REDEEM_POOL_SIZE],
    /// Next free byte in redeem_pool.
    pub redeem_pool_used: usize,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Create an empty transaction.
    ///
    /// Uses `zeroed()` instead of field-by-field init to avoid a 20KB+
    /// stack temporary. All fields default to zero/false except
    /// `sig_op_count` which defaults to 1 per input.
    ///
    /// SAFETY: Transaction is composed entirely of primitive types
    /// (integers, booleans, fixed-size byte arrays) with no pointers,
    /// references, enums with non-zero discriminants, or types where
    /// all-zeros is invalid. Zero is a valid bit pattern for every field.
    pub fn new() -> Self {
        let mut tx: Self = unsafe { core::mem::zeroed() };
        // sig_op_count defaults to 1 (standard P2PK/P2SH)
        for i in 0..MAX_INPUTS {
            tx.inputs[i].sig_op_count = 1;
        }
        tx
    }

    /// Allocate an empty `Transaction` directly on the heap.
    ///
    /// `Box::new(Transaction::new())` does NOT do this. `Box::new` takes its
    /// argument by value, so `Transaction::new()` must produce the whole ~79 KB
    /// value before the box exists, and that value lands in a slot in the
    /// caller's stack frame. The box is then filled by copying from that slot.
    ///
    /// The copy is dead immediately, but the slot is not. A frame is reserved
    /// in full on entry, and `AppData::new()` is inlined into `main`, which
    /// never returns. So the temporary reserved 79 KB of stack for the entire
    /// life of the device, holding a value that stopped being needed
    /// microseconds after boot. Measured: it was 96,512 of the 112,884 bytes of
    /// usable stack, which left the QR decoder 1,092 bytes and tripped the
    /// stack guard inside rqrr.
    ///
    /// This allocates zeroed heap first and writes the non-zero defaults
    /// through the pointer, so the value is born at its final address and
    /// never exists in a frame. Same technique as `clear()` below, which was
    /// added for the same reason on the same type.
    ///
    /// SAFETY: identical to `new()`. Every field is a primitive, a bool or a
    /// fixed-size byte array, and all-zeros is a valid bit pattern for each.
    /// There are no references, pointers, or enums with non-zero
    /// discriminants. `alloc_zeroed` therefore yields a valid `Transaction`,
    /// and the only fixup needed is `sig_op_count`, which `new()` also sets.
    ///
    /// Returns `None` if the allocation fails, so the caller decides what a
    /// 79 KB allocation failure means rather than aborting here.
    pub fn new_boxed() -> Option<alloc::boxed::Box<Self>> {
        use core::alloc::Layout;
        let layout = Layout::new::<Self>();
        // SAFETY: Layout::new::<Self>() has non-zero size, and all-zeros is a
        // valid bit pattern for every field (see above).
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) } as *mut Self;
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr is a valid, uniquely-owned, correctly-aligned allocation
        // of exactly Layout::new::<Self>(), zero-initialised, which is a valid
        // Transaction. Ownership transfers to the Box.
        let mut boxed = unsafe { alloc::boxed::Box::from_raw(ptr) };
        // The one non-zero default, matching `new()`.
        for i in 0..MAX_INPUTS {
            boxed.inputs[i].sig_op_count = 1;
        }
        Some(boxed)
    }

    /// Reset this transaction to its empty state, in place.
    ///
    /// Avoids the 20KB+ stack temporary that `*self = Transaction::new()`
    /// would create on Xtensa (LLVM does not elide the by-value return
    /// into the destination). Instead, zeroes the memory through a raw
    /// pointer write and patches up the non-zero defaults.
    ///
    /// SAFETY: same as `new()` -- all-zeros is a valid bit pattern.
    pub fn clear(&mut self) {
        unsafe {
            core::ptr::write_bytes(self as *mut Self, 0, 1);
        }
        for i in 0..MAX_INPUTS {
            self.inputs[i].sig_op_count = 1;
        }
    }

    /// Get the redeem script bytes for input `idx`.
    /// Returns the inline buffer if the script fits, or the pool slice
    /// if `redeem_in_pool` is set.
    pub fn redeem_bytes(&self, idx: usize) -> &[u8] {
        let inp = &self.inputs[idx];
        if inp.redeem_script_len == 0 {
            return &[];
        }
        if inp.redeem_in_pool {
            let off = inp.redeem_script_offset as usize;
            // Read-side bounds check. `store_redeem` is the only writer of
            // these three fields and rejects both `len > MAX_REDEEM_SIZE` and
            // `off + len > REDEEM_POOL_SIZE`, so this cannot trip on any
            // payload the parser accepts. It is here for the case that
            // invariant is ever broken by an edit elsewhere.
            //
            // Empty, not clamped to what fits. A short read would be worse
            // than the panic it replaces: the redeem script is what gets
            // hashed to the P2SH address and what the signature commits to,
            // so a truncated one yields a valid-looking signature over the
            // wrong script. `&[]` is the same thing a zero-length script
            // returns above, and every caller already refuses on it.
            let end = off.saturating_add(inp.redeem_script_len);
            if end > REDEEM_POOL_SIZE {
                return &[];
            }
            &self.redeem_pool[off..end]
        } else {
            &inp.redeem_script[..inp.redeem_script_len]
        }
    }

    /// Store a redeem script for input `idx`. Scripts <= MAX_SCRIPT_SIZE
    /// go inline; larger ones go into the shared pool.
    /// Returns `Err(RedeemTooLong)` if the script exceeds `MAX_REDEEM_SIZE`
    /// or the shared pool has no room left.
    pub fn store_redeem(&mut self, idx: usize, data: &[u8]) -> Result<(), RedeemTooLong> {
        let len = data.len();
        if len == 0 {
            self.inputs[idx].redeem_script_len = 0;
            self.inputs[idx].redeem_in_pool = false;
            return Ok(());
        }
        if len <= MAX_SCRIPT_SIZE {
            self.inputs[idx].redeem_script[..len].copy_from_slice(data);
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = false;
        } else {
            if len > MAX_REDEEM_SIZE {
                return Err(RedeemTooLong);
            }
            let off = self.redeem_pool_used;
            if off + len > REDEEM_POOL_SIZE {
                return Err(RedeemTooLong);
            }
            self.redeem_pool[off..off + len].copy_from_slice(data);
            self.inputs[idx].redeem_script_offset = off as u16;
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = true;
            self.redeem_pool_used = off + len;
        }
        Ok(())
    }

    /// Get the transaction inputs slice.
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs[..self.num_inputs]
    }

    /// Get the transaction outputs slice.
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs[..self.num_outputs]
    }

    /// Returns true if the transaction subnetwork is native (not a registry tx).
    pub fn is_native(&self) -> bool {
        self.subnetwork_id == SUBNETWORK_ID_NATIVE
    }

    /// Calculate total sompi across inputs
    pub fn total_input_value(&self) -> u64 {
        self.inputs().iter().map(|i| i.utxo_entry.amount).sum()
    }

    /// Calculate total sompi across outputs
    pub fn total_output_value(&self) -> u64 {
        self.outputs().iter().map(|o| o.value).sum()
    }

    /// Implicit fee = inputs - outputs
    pub fn fee(&self) -> u64 {
        self.total_input_value().saturating_sub(self.total_output_value())
    }

    /// Format a sompi value as KAS (no-alloc, returns in buffer)
    /// Example: 123_456_789 sompi -> "1.23456789"
    pub fn format_kas(sompi: u64, buf: &mut [u8]) -> usize {
        let kas = sompi / 100_000_000;
        let frac = sompi % 100_000_000;
        let mut pos = 0;

        // Integer part
        pos += Self::write_u64(kas, &mut buf[pos..]);

        // Decimal point
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }

        // Fractional part (8 digits with leading zeros)
        let mut frac_buf = [b'0'; 8];
        let mut f = frac;
        for i in (0..8).rev() {
            frac_buf[i] = b'0' + (f % 10) as u8;
            f /= 10;
        }

        // Write fraction (trim unnecessary trailing zeros)
        let mut last_nonzero = 0;
        for i in 0..8 {
            if frac_buf[i] != b'0' {
                last_nonzero = i;
            }
        }
        let frac_digits = if frac == 0 { 2 } else { last_nonzero + 1 };
        for i in 0..frac_digits {
            if pos < buf.len() {
                buf[pos] = frac_buf[i];
                pos += 1;
            }
        }

        pos
    }

    fn write_u64(mut val: u64, buf: &mut [u8]) -> usize {
        if val == 0 {
            if !buf.is_empty() {
                buf[0] = b'0';
            }
            return 1;
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while val > 0 {
            digits[count] = b'0' + (val % 10) as u8;
            val /= 10;
            count += 1;
        }
        let written = count.min(buf.len());
        for i in 0..written {
            buf[i] = digits[count - 1 - i];
        }
        written
    }
}

// ═══════════════════════════════════════════════════════════════════
// Multisig Wallet Configuration (RAM-only, wiped on shutdown)
// ═══════════════════════════════════════════════════════════════════

/// Maximum multisig wallet configs stored simultaneously
pub const MAX_MULTISIG_WALLETS: usize = 2;

/// A multisig wallet configuration: M-of-N with pubkeys and derived script
#[derive(Clone)]
/// Runtime multisig configuration — HD-aware.
///
/// Each cosigner contributes an ACCOUNT-LEVEL xpub (parent compressed
/// pubkey + chain code). For each address index `addr_index`, the
/// script is built from the CHILDREN at the canonical Kaspa receive
/// path `/0/addr_index` from each parent, lex-sorted and assembled.
///
/// Incrementing `addr_index` yields a fresh, uncorrelated P2SH address
/// that the same cosigners can jointly spend — matching the standard
/// HD multisig behaviour of Coldcard, Ledger, Trezor, etc.
///
/// Signing works unchanged: the pubkeys in the built script are at
/// m/44'/111111'/0'/0/addr_index (exact singlesig receive path), so
/// `find_address_index_for_pubkey()` in the signing path matches them
/// directly without a special multisig signing code path.
pub struct MultisigConfig {
    pub m: u8,
    pub n: u8,
    /// Cosigner account-level xpub parents — compressed (33 bytes, with
    /// 0x02/0x03 parity prefix). Y-parity matters: x-only loses it and
    /// would break deterministic child derivation.
    pub cosigner_pubkeys: [[u8; 33]; MAX_MULTISIG_KEYS],
    /// Cosigner account-level chain codes. Pair by index with `cosigner_pubkeys`.
    pub cosigner_chain_codes: [[u8; 32]; MAX_MULTISIG_KEYS],
    /// Current derivation index. Each value 0..2^31-1 yields a distinct
    /// multisig address. `build_script()` reads this to know which
    /// per-cosigner child to derive.
    pub addr_index: u32,

    // ── 45' scheme. All four fields are meaningless when `v45` is false. ──
    /// Which scheme built this config. Never inferred: the descriptor says so
    /// (`multi_hd45(` versus `multi_hd(`), and `MultisigConfig::new()` leaves
    /// it false so a legacy descriptor loads as 44' by default.
    ///
    /// 45' is the rusty-kaspa standard: cosigner keys are account xpubs at
    /// `m/45'/111111'/account'`, an address is built from children at
    /// `/cosigner_index/chain/addr_index` with the SAME index applied to every
    /// key, and the keys are ordered by their serialized xpub. 44' is ours:
    /// keys at `m/44'/111111'/0'`, children at `/0/addr_index`, and the DERIVED
    /// children lex-sorted. The two produce different addresses from the same
    /// cosigners and neither converts to the other.
    pub v45: bool,
    /// Which address family this device hands out, i.e. our own slot in the
    /// sorted key list. Derived at load, never stored in the descriptor.
    ///
    /// It selects the addresses we DISPLAY. It plays no part in signing: the
    /// path there comes from the PSKB's `bip32_derivations` hint and belongs to
    /// the address being spent, which every cosigner derives at alike.
    pub cosigner_index: u8,
    /// Which chain to derive: 0 receive, 1 change. 45' only.
    ///
    /// Separate from `cosigner_index` because they are different levels of the
    /// path: `/cosigner/chain/index`. 44' has no cosigner level and its chain is
    /// always 0, so this is ignored there.
    ///
    /// Zero by default, which `mem::zeroed()` gives for free and which is the
    /// receive chain - the only one anything funded until now.
    pub chain: u8,
    /// Per-entry depth, parent fingerprint and child number, paired by index
    /// with `cosigner_pubkeys`.
    ///
    /// Kept because an entry must re-serialize byte-identically on export: a
    /// kpub string encodes all three, and the sort that fixes every address is
    /// a byte comparison over those strings. Reconstructing an entry from
    /// pubkey and chain code alone would produce a different string, a
    /// different sort position, and a different wallet.
    pub cosigner_depth: [u8; MAX_MULTISIG_KEYS],
    pub cosigner_parent_fp: [[u8; 4]; MAX_MULTISIG_KEYS],
    pub cosigner_child_num: [[u8; 4]; MAX_MULTISIG_KEYS],
    /// The built scriptPublicKey (OP_m <child_pks> OP_n OP_CHECKMULTISIG)
    /// where each child_pk = (cosigner_parent / 0 / addr_index).x_only().
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
    /// Whether this config has been fully set up
    pub active: bool,
}

impl Default for MultisigConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigConfig {
    pub const fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            cosigner_pubkeys: [[0u8; 33]; MAX_MULTISIG_KEYS],
            cosigner_chain_codes: [[0u8; 32]; MAX_MULTISIG_KEYS],
            addr_index: 0,
            v45: false,
            cosigner_index: 0,
            chain: 0,
            cosigner_depth: [0u8; MAX_MULTISIG_KEYS],
            cosigner_parent_fp: [[0u8; 4]; MAX_MULTISIG_KEYS],
            cosigner_child_num: [[0u8; 4]; MAX_MULTISIG_KEYS],
            script: [0u8; MAX_SCRIPT_SIZE],
            script_len: 0,
            active: false,
        }
    }

    /// Store one cosigner entry from decoded kpub parts.
    ///
    /// One setter for both entry points, the scanned QR and our own key, so a
    /// 45' entry can never be half-populated: pubkey and chain code without the
    /// depth, fingerprint and child number would round-trip to a DIFFERENT kpub
    /// string, sort to a different slot, and describe a different wallet.
    ///
    /// The three metadata fields are written unconditionally, including for
    /// 44'. They are unused there, and writing them costs nothing, but it means
    /// a config never carries a partly-filled entry whose validity depends on
    /// which scheme happens to be set.
    pub fn set_cosigner(&mut self, i: usize, parts: &super::xpub::KpubParts) -> bool {
        if i >= MAX_MULTISIG_KEYS {
            return false;
        }
        self.cosigner_pubkeys[i] = parts.pubkey;
        self.cosigner_chain_codes[i] = parts.chain_code;
        self.cosigner_depth[i] = parts.depth;
        self.cosigner_parent_fp[i] = parts.parent_fp;
        self.cosigner_child_num[i] = parts.child_num;
        true
    }

    /// Is this cosigner already in a filled slot?
    ///
    /// E1-fw, creation side. The QR flow fills the next empty slot with no
    /// comparison against what is already stored, so scanning the same kpub
    /// twice builds a 2-of-2 with one key in both slots. That is not a hostile
    /// descriptor, it is a slip during a key ceremony, and it produces a P2SH
    /// address that looks entirely ordinary and needs one signature.
    ///
    /// Compares the pubkey and chain code, the two fields derivation actually
    /// uses. Depth, parent fingerprint and child number are deliberately NOT
    /// compared: `derive_child` ignores them, so two kpubs differing only there
    /// derive to identical children and must still be caught. That is the same
    /// gap K1 describes on the KasSee side, where the 45' dedup compares whole
    /// kpub strings and misses exactly this pair.
    ///
    /// Only filled slots count, so an empty slot never matches an empty probe.
    pub fn has_cosigner(&self, pubkey: &[u8; 33], chain_code: &[u8; 32]) -> bool {
        for i in 0..MAX_MULTISIG_KEYS {
            if !self.slot_empty(i)
                && self.cosigner_pubkeys[i] == *pubkey
                && self.cosigner_chain_codes[i] == *chain_code
            {
                return true;
            }
        }
        false
    }

    /// Is the cosigner slot `i` empty (no pubkey collected yet)?
    /// Used during creation to find the next empty slot.
    pub fn slot_empty(&self, i: usize) -> bool {
        i < MAX_MULTISIG_KEYS && self.cosigner_pubkeys[i] == [0u8; 33]
    }

    /// Build the multisig scriptPublicKey for the current `addr_index`.
    ///
    /// Emits, in both schemes:
    ///
    ///   OP_m OP_DATA_32 <pk0> OP_DATA_32 <pk1> ... OP_n OP_CHECKMULTISIG
    ///
    /// What differs is which key goes where, and the difference is not just
    /// the path. It is WHEN the ordering is decided:
    ///
    /// **44'** derives each cosigner's child at `/0/addr_index`, then lex-sorts
    /// the DERIVED children. The order is therefore recomputed for every
    /// address index and may come out different each time, since children at
    /// index 5 and index 6 are unrelated 32-byte values. That is why 44' has no
    /// stable notion of "which cosigner is number 2" and no address families.
    ///
    /// **45'** derives at `/cosigner_index/0/addr_index` with the SAME
    /// `cosigner_index` applied to every cosigner's key, and does NOT sort
    /// here. The order was fixed once, at descriptor load, by sorting the
    /// parent kpub STRINGS — which is what rusty-kaspa sorts
    /// (`wallet/core/src/wallet/mod.rs:733`). Sorting the children again would
    /// reorder the script and produce an address no other implementation
    /// computes.
    ///
    /// Chain is 0 (receive) in both. Multisig change returns to the address
    /// being spent rather than to a fresh change address, so chain 1 is never
    /// built here.
    ///
    /// Returns script length, or 0 on error (invalid M/N, derivation failure).
    pub fn build_script(&mut self) -> usize {
        if self.m == 0 || self.n == 0 || self.m > self.n || self.n as usize > MAX_MULTISIG_KEYS {
            return 0;
        }

        // ── Step 1: derive each cosigner's x-only child ──
        // 44': parent → /0 (receive chain) → /addr_index. Matches the Kaspa
        //      singlesig receive path, so signing's existing address matcher
        //      (m/44'/111111'/0'/0/N) works unchanged.
        // 45': parent → /cosigner_index → /0 → /addr_index. One level more, and
        //      the cosigner level is NOT hardened, which is what makes a
        //      public-only derivation possible from an account xpub at all.
        let mut child_xonly = [[0u8; 32]; MAX_MULTISIG_KEYS];
        for i in 0..self.n as usize {
            let parent = super::bip32::ExtendedPubKey {
                pubkey: self.cosigner_pubkeys[i],
                chain_code: self.cosigner_chain_codes[i],
                depth: 3, // account level in both schemes
            };
            let base = if self.v45 {
                match super::bip32::derive_child_pub(&parent, self.cosigner_index as u32) {
                    Ok(x) => x,
                    Err(_) => return 0,
                }
            } else {
                parent
            };
            // Chain from the config for 45', still hardcoded 0 for 44': that
            // scheme has no cosigner level and its receive path is fixed.
            let chain_step = if self.v45 { self.chain as u32 } else { 0 };
            let receive_chain = match super::bip32::derive_child_pub(&base, chain_step) {
                Ok(x) => x,
                Err(_) => return 0,
            };
            let addr_xpub = match super::bip32::derive_child_pub(&receive_chain, self.addr_index) {
                Ok(x) => x,
                Err(_) => return 0,
            };
            child_xonly[i] = addr_xpub.x_only();
        }

        // ── Step 1b: reject a keyset with a repeated cosigner ──
        //
        // E1-fw. The descriptor parsers in KasSee do not catch this: the 44'
        // and legacy `multi(` branches never dedup, and the 45' branch dedups
        // by comparing parent kpub STRINGS while `from_raw_payload` discards
        // the parent fingerprint and child number, so two kpubs differing only
        // in those eight bytes are distinct strings that derive to identical
        // children (K1). Both paths converge here, on the DERIVED children,
        // which is the only place the question can be settled: it is these
        // bytes that go into the script.
        //
        // Why it matters, verified against `op_check_multisig_schnorr_or_ecdsa`
        // in rusty-kaspa: the pubkey iterator advances monotonically and each
        // check consumes a key, so a redeem script of [A, A, B] with M=2 is
        // satisfied by one participant supplying sig_A twice. A purported
        // two-party threshold that one party clears alone.
        //
        // This device is the trust root for a multisig wallet, because the
        // security argument is that you compare the P2SH address on this
        // screen against what the coordinator claims. Without this check the
        // device reproduces and displays the address for a weakened keyset,
        // so the step meant to catch a bad descriptor confirms it instead.
        //
        // Before the 44' sort deliberately, so it applies to both schemes: 45'
        // skips that sort to preserve descriptor order. n is at most
        // MAX_MULTISIG_KEYS, so the pairwise scan is ten comparisons at worst.
        //
        // Returns 0, the same failure this function already uses for an
        // out-of-range m/n and for a derivation error.
        for i in 0..self.n as usize {
            for j in (i + 1)..self.n as usize {
                if child_xonly[i] == child_xonly[j] {
                    return 0;
                }
            }
        }

        // ── Step 2: 44' ONLY — lex-sort the x-only children so both devices
        //           produce the byte-identical script regardless of cosigner
        //           insertion order.
        //
        // 45' skips this deliberately. Its order was fixed at descriptor load
        // by sorting the parent kpub strings, and the entries were stored in
        // that order. Re-sorting the derived children here would discard it and
        // yield an address no other implementation agrees with.
        let n = self.n as usize;
        if !self.v45 {
            for i in 1..n {
                let mut j = i;
                while j > 0 {
                    let mut cmp = core::cmp::Ordering::Equal;
                    for b in 0..32 {
                        cmp = child_xonly[j - 1][b].cmp(&child_xonly[j][b]);
                        if cmp != core::cmp::Ordering::Equal { break; }
                    }
                    if cmp == core::cmp::Ordering::Greater {
                        child_xonly.swap(j - 1, j);
                        j -= 1;
                    } else {
                        break;
                    }
                }
            }

        }

        // ── Step 3: assemble the script ──
        let len = 1 + (self.n as usize) * 33 + 1 + 1;
        if len > MAX_SCRIPT_SIZE { return 0; }

        let mut pos = 0;
        self.script[pos] = OP_1 + self.m - 1;
        pos += 1;
        for i in 0..self.n as usize {
            self.script[pos] = OP_DATA_32;
            pos += 1;
            self.script[pos..pos + 32].copy_from_slice(&child_xonly[i]);
            pos += 32;
        }
        self.script[pos] = OP_1 + self.n - 1;
        pos += 1;
        self.script[pos] = OP_CHECKMULTISIG;
        pos += 1;

        self.script_len = pos;
        pos
    }

    /// Does this config reproduce `script` at the given path?
    ///
    /// Used two ways on the review screen. Against an INPUT's redeem script it
    /// answers "is this the descriptor for this transaction", which is what
    /// selects the right stored config without asking the user. Against an
    /// OUTPUT's script it answers "is this output really our change".
    ///
    /// Derives from the cosigner PARENTS at `/cosigner/chain/index`, which is
    /// the same walk `build_script` does, then compares the P2SH script hash.
    /// Does not disturb the config: `build_script` writes into `self.script`,
    /// so this rebuilds into a local instead.
    pub fn matches_at(&self, hint: &Ms45Hint, script_hash: &[u8; 32]) -> bool {
        if !self.v45 || !hint.present {
            return false;
        }
        let n = self.n as usize;
        if n == 0 || n > MAX_MULTISIG_KEYS {
            return false;
        }
        let mut redeem = [0u8; 3 + MAX_MULTISIG_KEYS * 33];
        let mut pos = 0usize;
        redeem[pos] = 0x50 + self.m; pos += 1;
        for i in 0..n {
            let parent = super::bip32::ExtendedPubKey {
                pubkey: self.cosigner_pubkeys[i],
                chain_code: self.cosigner_chain_codes[i],
                // Depth of the ACCOUNT key these parents are: m/45'/coin'/acct'
                // is depth 3. Not used by `derive_child_pub`, which needs only
                // the pubkey and chain code, but the struct carries it.
                depth: self.cosigner_depth[i],
            };
            let a = match super::bip32::derive_child_pub(&parent, hint.cosigner) {
                Ok(k) => k, Err(_) => return false,
            };
            let b = match super::bip32::derive_child_pub(&a, hint.chain) {
                Ok(k) => k, Err(_) => return false,
            };
            let c = match super::bip32::derive_child_pub(&b, hint.index) {
                Ok(k) => k, Err(_) => return false,
            };
            redeem[pos] = 0x20; pos += 1;
            redeem[pos..pos + 32].copy_from_slice(&c.pubkey[1..33]);
            pos += 32;
        }
        redeem[pos] = 0x50 + self.n; pos += 1;
        redeem[pos] = 0xae; pos += 1;
        let h = super::sighash::blake2b_hash(&redeem[..pos]);
        h == *script_hash
    }

    /// Sort the cosigner entries into canonical order, 45' only.
    ///
    /// **Must be called once the last entry is in, before `build_script`.**
    ///
    /// A LOADED descriptor arrives sorted, because `parse_descriptor_45` sorts
    /// it. A CREATED one does not: entries arrive one at a time via
    /// `set_cosigner`, in the order the user scanned them, and nothing else
    /// orders them. `build_script` deliberately does not sort children for 45',
    /// so without this the redeem script follows scan order and the wallet gets
    /// an address no other implementation computes - including this same device
    /// after re-importing its own descriptor.
    ///
    /// Observed on hardware 2026-08-15: a 2-of-2 created from the two abandon
    /// seeds produced an address matching scan order, not sorted order. The
    /// keys were right; only the order was wrong.
    ///
    /// Sorts on the SERIALIZED kpub, exactly what `parse_descriptor_45` and
    /// rusty-kaspa sort: version, depth, parent fingerprint, child number,
    /// chain code, pubkey. Comparing the pubkey alone would order differently.
    ///
    /// 44' is left untouched: it sorts derived children per address inside
    /// `build_script` and has no notion of a fixed parent order.
    pub fn sort_cosigners(&mut self) {
        if !self.v45 {
            return;
        }
        let n = self.n as usize;
        // Insertion sort over the serialized form, same shape as the 44' child
        // sort below and as `parse_descriptor_45`.
        for i in 1..n {
            let mut j = i;
            while j > 0 {
                let a = self.serialized_entry(j - 1);
                let b = self.serialized_entry(j);
                if a > b {
                    self.cosigner_pubkeys.swap(j - 1, j);
                    self.cosigner_chain_codes.swap(j - 1, j);
                    self.cosigner_depth.swap(j - 1, j);
                    self.cosigner_parent_fp.swap(j - 1, j);
                    self.cosigner_child_num.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
    }

    /// The serialized form of cosigner `i`, for ordering.
    ///
    /// Field order matches the kpub payload so a byte comparison here gives the
    /// same result as comparing the base58 strings, which is what rusty-kaspa
    /// sorts. Base58 preserves the order of the underlying bytes for equal
    /// lengths, and every kpub is the same length.
    fn serialized_entry(&self, i: usize) -> [u8; 74] {
        // The 4-byte version prefix is omitted: it is identical for every kpub,
        // so it cannot affect an ordering and including it would mean widening
        // a private constant in `xpub.rs` for nothing.
        let mut out = [0u8; 74];
        out[0] = self.cosigner_depth[i];
        out[1..5].copy_from_slice(&self.cosigner_parent_fp[i]);
        out[5..9].copy_from_slice(&self.cosigner_child_num[i]);
        out[9..41].copy_from_slice(&self.cosigner_chain_codes[i]);
        out[41..74].copy_from_slice(&self.cosigner_pubkeys[i]);
        out
    }

    /// Do these two configs describe the SAME wallet?
    ///
    /// Same threshold, same cosigner set, and — the part that was missing —
    /// the same SCHEME. A 44' and a 45' config built from identical cosigners
    /// and an identical M-of-N are different wallets with different addresses,
    /// because 44' sorts the derived children while 45' sorts the parent keys
    /// and inserts a cosigner level. Treating them as one overwrites a stored
    /// wallet with another wallet's config, and the addresses silently change.
    ///
    /// `cosigner_index` is deliberately NOT compared. It is per-device, not per
    /// wallet: two cosigners of the same wallet hold the same config with
    /// different indices, and each still recognises it as theirs.
    pub fn same_wallet_as(&self, other: &Self) -> bool {
        self.v45 == other.v45
            && self.m == other.m
            && self.n == other.n
            && self.cosigner_pubkeys == other.cosigner_pubkeys
    }

    /// Human-readable label: `2-of-3` for 44', `2-of-3 45'#1` for 45'.
    ///
    /// The scheme and family are shown because neither is recoverable from the
    /// address, and both are needed to reproduce it. A user holding one wallet
    /// of each scheme otherwise sees two identical `2-of-3` entries with
    /// different addresses and nothing on screen explaining why.
    ///
    /// `#N` is `cosigner_index`, the family THIS device hands out. Two
    /// cosigners of the same wallet see the same `2-of-3 45'` and different
    /// `#N`, which is correct and is the thing that stops them issuing
    /// colliding addresses.
    ///
    /// Callers pass an 8-byte buffer today; anything shorter simply truncates,
    /// as before, since every write is length-checked.
    pub fn label(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        if pos < buf.len() { buf[pos] = b'0' + self.m; pos += 1; }
        for &c in b"-of-" { if pos < buf.len() { buf[pos] = c; pos += 1; } }
        if pos < buf.len() { buf[pos] = b'0' + self.n; pos += 1; }
        if self.v45 {
            // " 45' S1/C0" — signer and chain, matching the nav band.
            for &c in b" 45' S" { if pos < buf.len() { buf[pos] = c; pos += 1; } }
            // Single digits: cosigner_index < n <= MAX_MULTISIG_KEYS = 5, chain is 0 or 1.
            if pos < buf.len() { buf[pos] = b'0' + self.cosigner_index; pos += 1; }
            for &c in b"/C" { if pos < buf.len() { buf[pos] = c; pos += 1; } }
            if pos < buf.len() { buf[pos] = b'0' + self.chain; pos += 1; }
        }
        pos
    }
}

/// Storage for multisig wallet configurations
pub struct MultisigStore {
    pub configs: [MultisigConfig; MAX_MULTISIG_WALLETS],
}

impl Default for MultisigStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigStore {
    pub const fn new() -> Self {
        Self {
            configs: [MultisigConfig::new(), MultisigConfig::new()],
        }
    }

    /// The slot the next config goes into. Always slot 0.
    ///
    /// One live multisig wallet at a time: the most recent one. `configs` is
    /// still an array because the readers iterate it and the type is used
    /// across four files, but slot 1 is never written and stays inactive.
    ///
    /// This replaced a `find_free` that returned `None` once both slots were
    /// taken, which both callers used as `if let Some(i) = ... {}` with no
    /// `else`: the user finished the whole creation flow and the config was
    /// silently not registered. Nothing ever set a slot back to inactive, so
    /// slots only filled, and the third wallet of a session was always the one
    /// that vanished.
    ///
    /// Overwriting is right for what this store is. It lives in RAM, is gone
    /// at power-off and at every wipe, and holds no secret; the durable
    /// artefacts are the descriptor and address the user writes to SD. What it
    /// feeds is per-transaction: `find_forged_change`, which refuses an output
    /// claiming to be change at a path the descriptor does not produce, and
    /// the review screen's labelling of multisig inputs. Both look at the
    /// wallet the transaction belongs to, so the one that must always be
    /// present is the one just created.
    pub fn slot_for_next(&self) -> usize {
        0
    }
}

// ─── 45' cross-implementation vector ─────────────────────────────────

/// Reproduce a multisig address that an INDEPENDENT implementation produced.
///
/// Source: `rusty-kaspa-2.0.1/wallet/core/src/compat/gen1.rs:134`, whose
/// expected value carries the comment "taken from golang impl". Five kpubs,
/// 2-of-5, `cosigner_index: 1`, receive address 0. The address is
/// `kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998`, and
/// the 32 bytes below are the P2SH script hash inside it.
///
/// This is the ONLY test here that can fail for a reason other than our own
/// arithmetic agreeing with itself. Four separate rules have to be right at
/// once or the hash differs completely:
///
///   1. sort the PARENT kpub strings, not the derived children. The five
///      below are listed unsorted on purpose: sorting permutes them
///      [3, 0, 2, 1, 4], so a build that skipped the sort, or sorted the
///      children the way 44' does, produces a different script.
///   2. apply the SAME `cosigner_index` to every cosigner's key.
///   3. derive `/cosigner/chain/index` under the account, three
///      non-hardened steps.
///   4. emit `OP_M`, each 32-byte x-only key in sorted-parent order, `OP_N`,
///      `OP_CHECKMULTISIG`.
///
/// Costs 5 x 111 bytes of static kpub text. That is DRAM, and DRAM raises the
/// stack floor (see `stack_probe`), so it is a deliberate purchase: an
/// interoperability guarantee that fails loudly on the bench rather than
/// quietly at a user's address.
#[cfg(any(test, not(feature = "skip-tests")))]
pub fn test_multisig_45_vector() -> bool {
    const VEC_KPUBS: [&[u8]; 5] = [
        b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        b"kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
        b"kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
        b"kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
        b"kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
    ];
    // The blake2b of the 2-of-5 redeem script these five kpubs produce.
    // Not ours: this is the Go implementation's answer, reached through
    // rusty-kaspa's golang multisig import test
    // (`wallet/core/src/compat/gen1.rs:134`), where the same five keys with
    // `required_signatures: 2, cosigner_index: 1` give the receive address
    // `kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998`.
    // Encoding the hash below as P2SH reproduces that string exactly, which
    // `reference_vectors_tests::golang_multisig_p2sh_address_validates`
    // asserts, so this constant is a cross-implementation vector rather than
    // a value this codebase chose.
    const EXPECT_SCRIPT_HASH: [u8; 32] = [
        0x18, 0x8b, 0x12, 0x59, 0xe1, 0xb6, 0xd3, 0xdb, 0xcf, 0xca, 0x06, 0x31, 0x05, 0xa2, 0xa0, 0xc1,
        0x27, 0xf7, 0x1b, 0x1e, 0x88, 0x5a, 0xed, 0xd0, 0xfa, 0xcc, 0x90, 0xea, 0x78, 0xa3, 0xfd, 0x55,
    ];

    let mut cfg = MultisigConfig::new();
    cfg.v45 = true;
    cfg.m = 2;
    cfg.n = 5;
    cfg.cosigner_index = 1;
    cfg.addr_index = 0;

    // Sort the strings, exactly as `parse_descriptor_45` does on load. Doing
    // it here rather than assuming the array is sorted keeps the test honest:
    // the constants above are in the wallet file's original order.
    let mut ordered: [&[u8]; 5] = VEC_KPUBS;
    for i in 1..5 {
        let mut j = i;
        while j > 0 {
            let mut greater = false;
            for b in 0..111 {
                if ordered[j - 1][b] != ordered[j][b] {
                    greater = ordered[j - 1][b] > ordered[j][b];
                    break;
                }
            }
            if greater {
                ordered.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }

    for (i, k) in ordered.iter().enumerate() {
        match super::xpub::parse_kpub_parts(k) {
            Some(p) => {
                if p.depth != 3 {
                    return false;
                }
                cfg.set_cosigner(i, &p);
            }
            None => return false,
        }
    }

    if cfg.build_script() == 0 {
        return false;
    }
    let hash = super::sighash::blake2b_hash(&cfg.script[..cfg.script_len]);
    hash == EXPECT_SCRIPT_HASH
}

/// Multisig known-answer tests. Returns (passed, total).
///
/// One test today, and it is the one that matters: an address produced by an
/// independent implementation. Grouped as a runner so `run_crypto_kats` can
/// treat it like every other KAT and halt on failure.
#[cfg(any(test, not(feature = "skip-tests")))]
pub fn run_multisig_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 1u32;
    if test_multisig_45_vector() { passed += 1; }
    (passed, total)
}
