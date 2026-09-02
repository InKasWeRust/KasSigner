// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// types.rs — plain data types shared between the PSKT parser/serializer
// and the firmware's application state. Moved verbatim from
// bootloader/src/app/data.rs; the firmware re-exports them from there.

/// Envelope format of the transaction payload currently loaded in AppData.
/// Determines which serializer to use for the signed-response QR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxInputFormat {
    /// Legacy KSPT v1 (our custom compact binary, unsigned).
    KsptV1,
    /// Legacy KSPT v2 (our custom compact binary, partially signed).
    KsptV2,
    /// Kaspa-standard PSKT, hex-wrapped bundle JSON, `PSKB` magic prefix.
    /// The only PSKT envelope; see `wallet::std_pskt::PSKB_MAGIC`.
    PsktPskb,
}

impl TxInputFormat {
    /// Returns true if this format is a Kaspa-standard PSKT variant.
    pub fn is_pskt(self) -> bool {
        matches!(self, Self::PsktPskb)
    }
}

/// Maximum byte-range regions the PSKT parser can capture from an
/// incoming JSON for verbatim pass-through on re-emission.
///
/// Used for opaque fields the signer doesn't interpret but must round-trip
/// (`xpubs`, `proprietaries`, `bip32Derivations` values carrying unknown
/// KeySource shapes, per-input/output unknown fields). Each region is a
/// `(start, end)` offset pair into the original JSON bytes.
///
/// RAISED 16 -> 32 on 2026-09-01 ([K12]), because [S5] made outputs cost one
/// region more each. Outputs used to contribute `bip32Derivations` and
/// `proprietaries`; [S5] added `redeemScript`, which the parser had been
/// skipping and the emitter replacing with a hardcoded `null`, silently
/// dropping an output's redeem script. Capturing it costs a slot.
///
/// At 4 global regions and 2 per input, a fully populated bundle needs 18 for
/// 4-in-2-out and 17 for 2-in-3-out. Both were over 16, so a real multi-input
/// consolidation would have failed to parse where it previously succeeded.
///
/// The old rationale read "16 slots covers: globals (3) + per-input (5 x 2
/// inputs = 10) + per-output (2 x 2 outputs = 4) with headroom", which sums to
/// SEVENTEEN against a constant of sixteen. The number was never derived from
/// a limit; it was "kept small since each pair is 4 bytes".
///
/// Three things were measured before changing it, so they need not be
/// measured again:
///
/// 1. SIZE. `PsktParsed` goes 86 -> 166 bytes, and the padding is nothing
///    because `[(u16, u16); N]` is already 2-aligned. It lives in `AppData`,
///    heap-boxed at `main.rs:985`, so this is 80 bytes of PSRAM, not stack.
///
/// 2. THE EMIT CEILING, which does not bind. Captured regions are DISJOINT
///    slices of the input JSON, so their total is bounded by an input that
///    already had to fit; the region COUNT does not drive output size. Both
///    device buffers are `SIGNED_QR_BUF_LEN`, 14,528. And the failure mode
///    stays clean either way: `HexWriter::bytes` checks
///    `pos + 2 * len > out.len()` and returns `OutputBufferTooSmall`, and
///    `scratch_range` bounds-checks before it. No truncation, no corruption.
///    The change is from "refuses at parse" to "parses, and refuses at
///    serialize only if the bundle genuinely will not fit".
///
/// 3. WHETHER 16 WAS DELIBERATE. It was not; see the arithmetic above.
pub const MAX_PSKT_UNKNOWN_REGIONS: usize = 32;

/// Which object a captured region came out of.
///
/// The capture table used to be flat, and the lookup that reads it matches on
/// the KEY NAME alone and takes the first hit. `proprietaries` is present at
/// all three levels, so an input's map was returned to the GLOBAL emitter
/// whenever the global one was empty and therefore uncaptured: the parser
/// stored it correctly and the serializer put it in the wrong object.
///
/// One byte per slot. `0` is global, `1..=MAX_INPUTS` is input `n - 1`, and
/// `SCOPE_OUTPUT_BASE..` is output `n - SCOPE_OUTPUT_BASE`. Encoded rather
/// than a two-field enum so `PsktParsed` stays `Copy` and 16 slots cost 16
/// bytes.
pub const SCOPE_GLOBAL: u8 = 0;
/// First input scope tag. Input `i` is `SCOPE_INPUT_BASE + i`.
pub const SCOPE_INPUT_BASE: u8 = 1;
/// First output scope tag, above every possible input tag (MAX_INPUTS is 32).
/// Output `i` is `SCOPE_OUTPUT_BASE + i`.
pub const SCOPE_OUTPUT_BASE: u8 = 64;

/// Byte-range capture state populated by the PSKT parser, consumed by the
/// PSKT serializer on re-emission. Empty/zeroed for KSPT flows.
#[derive(Debug, Clone, Copy)]
pub struct PsktParsed {
    /// `(start, end)` offsets into the original JSON bytes for regions
    /// the parser didn't interpret. `start == end` means unused slot.
    pub unknowns: [(u16, u16); MAX_PSKT_UNKNOWN_REGIONS],
    /// Scope tag per slot, parallel to `unknowns`. See `SCOPE_GLOBAL`.
    pub unknown_scopes: [u8; MAX_PSKT_UNKNOWN_REGIONS],
    pub unknowns_count: u8,
    /// Start/end offsets of the raw JSON fragment inside the original
    /// wire payload (after the magic prefix, after hex-decode). Used by
    /// the serializer to slice unknown regions out of the scratch buffer.
    pub json_start: u16,
    pub json_len: u16,
}

impl PsktParsed {
    pub const fn empty() -> Self {
        Self {
            unknowns: [(0u16, 0u16); MAX_PSKT_UNKNOWN_REGIONS],
            unknown_scopes: [SCOPE_GLOBAL; MAX_PSKT_UNKNOWN_REGIONS],
            unknowns_count: 0,
            json_start: 0,
            json_len: 0,
        }
    }
}
