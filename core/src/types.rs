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
/// 16 slots covers: globals (3) + per-input (5 × 2 inputs = 10) +
/// per-output (2 × 2 outputs = 4) with headroom. Kept small since each
/// pair is 4 bytes.
pub const MAX_PSKT_UNKNOWN_REGIONS: usize = 16;

/// Byte-range capture state populated by the PSKT parser, consumed by the
/// PSKT serializer on re-emission. Empty/zeroed for KSPT flows.
#[derive(Debug, Clone, Copy)]
pub struct PsktParsed {
    /// `(start, end)` offsets into the original JSON bytes for regions
    /// the parser didn't interpret. `start == end` means unused slot.
    pub unknowns: [(u16, u16); MAX_PSKT_UNKNOWN_REGIONS],
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
            unknowns_count: 0,
            json_start: 0,
            json_len: 0,
        }
    }
}
