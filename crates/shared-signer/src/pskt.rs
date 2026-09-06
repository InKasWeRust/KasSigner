/// Envelope format of a transaction payload exchanged with the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxInputFormat {
    /// Compact generation-4 KSPT relay envelope.
    KsptCompact,
    /// Kaspa-standard PSKB bundle.
    PsktPskb,
    /// Kaspa-standard single PSKT.
    PsktSingle,
}

impl TxInputFormat {
    #[must_use]
    pub const fn is_pskt(self) -> bool {
        matches!(self, Self::PsktPskb | Self::PsktSingle)
    }
}

pub const MAX_PSKT_UNKNOWN_REGIONS: usize = 16;

/// Logical owner of a captured PSKT field.
///
/// Captures are scoped so a field such as `proprietaries` on an input
/// cannot be confused with the same field name in the global or output
/// maps during re-serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsktUnknownScopeKind {
    TopLevel,
    Global,
    Input,
    InputUtxo,
    InputOutpoint,
    Output,
}

/// Scope metadata paired with one captured byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsktUnknownScope {
    pub kind: PsktUnknownScopeKind,
    pub index: u32,
}

impl PsktUnknownScope {
    #[must_use]
    pub const fn top_level() -> Self {
        Self {
            kind: PsktUnknownScopeKind::TopLevel,
            index: 0,
        }
    }

    #[must_use]
    pub const fn global() -> Self {
        Self {
            kind: PsktUnknownScopeKind::Global,
            index: 0,
        }
    }

    #[must_use]
    pub const fn input(index: u32) -> Self {
        Self {
            kind: PsktUnknownScopeKind::Input,
            index,
        }
    }

    #[must_use]
    pub const fn input_utxo(index: u32) -> Self {
        Self {
            kind: PsktUnknownScopeKind::InputUtxo,
            index,
        }
    }

    #[must_use]
    pub const fn input_outpoint(index: u32) -> Self {
        Self {
            kind: PsktUnknownScopeKind::InputOutpoint,
            index,
        }
    }

    #[must_use]
    pub const fn output(index: u32) -> Self {
        Self {
            kind: PsktUnknownScopeKind::Output,
            index,
        }
    }
}

/// Parser state retained alongside a PSKT transaction.
///
/// Each entry in `unknowns` is paired with the entry at the same index in
/// `unknown_scopes`. The ranges point into the decoded JSON scratch buffer.
#[derive(Debug, Clone, Copy)]
pub struct PsktParsed {
    pub unknowns: [(u16, u16); MAX_PSKT_UNKNOWN_REGIONS],
    pub unknown_scopes: [PsktUnknownScope; MAX_PSKT_UNKNOWN_REGIONS],
    pub unknowns_count: u8,
    pub json_start: u16,
    pub json_len: u16,
    /// Bit `n` is set when output `n` explicitly carried a
    /// `covenantBinding` field, including an explicit `null` value.
    pub output_covenant_binding_present: u16,
}

impl PsktParsed {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            unknowns: [(0, 0); MAX_PSKT_UNKNOWN_REGIONS],
            unknown_scopes: [PsktUnknownScope::top_level(); MAX_PSKT_UNKNOWN_REGIONS],
            unknowns_count: 0,
            json_start: 0,
            json_len: 0,
            output_covenant_binding_present: 0,
        }
    }

    #[must_use]
    pub const fn output_has_covenant_binding_field(&self, index: usize) -> bool {
        index < 16 && (self.output_covenant_binding_present & (1u16 << index)) != 0
    }

    pub fn mark_output_covenant_binding_field(&mut self, index: usize) {
        if index < 16 {
            self.output_covenant_binding_present |= 1u16 << index;
        }
    }
}

impl Default for PsktParsed {
    fn default() -> Self {
        Self::empty()
    }
}
