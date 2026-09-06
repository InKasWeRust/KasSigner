//! Canonical PSKT/PSKB outer-envelope discriminators.
//!
//! These four-byte values are part of the public KasSigner wire contract and
//! are available without the host feature so firmware classification and host
//! parsing cannot drift onto separate literals.

pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";
pub const PSKT_MAGIC: &[u8; 4] = b"PSKT";
