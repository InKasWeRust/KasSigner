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

// Stable Kaspa extended-key facade.

mod base58;
mod constants;
mod fingerprint;
mod kpub;
mod xprv;

pub use constants::{KPUB_MAX_LEN, KPUB_TEXT_PREFIX, XPRV_MAX_LEN, XPUB_PAYLOAD_LEN};
pub use kpub::{
    decode_kpub_compatible, decode_kpub_text, derive_account_raw_kpub_payload,
    derive_and_serialize_kpub, derive_and_serialize_multisig_kpub, derive_multisig_account_parts,
    encode_kpub_text, import_kpub, import_kpub_qr, import_kpub_raw, kpub_text_to_raw,
    normalize_kpub_text, parse_kpub_parts, serialize_account_kpub, serialize_kpub,
    serialize_legacy_kpub_parts, KpubParts, LEGACY_KPUB_LEN,
};
pub use xprv::{
    derive_and_serialize_xprv, import_xprv, import_xprv_with_metadata, serialize_account_key_xprv,
    serialize_imported_xprv, ImportedAccountXprv,
};

#[cfg(test)]
use base58::base58check_decode;
#[cfg(any(test, feature = "verbose-boot"))]
use base58::{base58_encode, base58check_encode, sha256d};
#[cfg(test)]
use kpub::parts_from_payload;

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "../unit_tests/xpub_tests.rs"]
pub mod unit_tests;
