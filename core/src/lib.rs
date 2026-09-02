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

// kassigner-core — the hardware-free half of the firmware.
//
// Module map (every file under wallet/, crypto/ and qr/ moved here from
// bootloader/src unchanged apart from the paths noted in each file):
//   wallet   bip39, bip32, bip85, schnorr, hmac, address, pskt, std_pskt,
//            sighash, transaction, xpub, storage, ecies, bip39_wordlist
//   crypto   constant_time, flow   (entropy stays in the firmware: hardware)
//   qr       payload               (the classifier; encoder stays: firmware)
//   types    TxInputFormat, PsktParsed, MAX_PSKT_UNKNOWN_REGIONS
//            (from bootloader app/data.rs)
//   ext      ExtBanksMut, ext_find_pubkey, ext_scan_find
//            (from bootloader app/signing.rs)
//   log      `log!` and set_logger
//   entropy  `fill` and set_source
//
// The firmware re-exports wallet, crypto::{constant_time, flow}, qr::payload,
// types and ext under the paths it always used, so nothing outside this
// crate changed its imports.

#![no_std]
// Same crate-level allows as bootloader/src/main.rs, verbatim, so the moved
// files compile under exactly the lints they were written against.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::manual_range_contains)]        // explicit range checks in SD filename parsing
#![allow(clippy::collapsible_else_if)]          // else { if } with trailing statements
#![allow(clippy::needless_lifetimes)]           // explicit lifetimes for documentation
#![allow(clippy::unnecessary_mut_passed)]       // mutable ref to DMA methods
#![allow(clippy::needless_range_loop)]          // index-based loops intentional in no_std crypto/DMA
#![allow(clippy::too_many_arguments)]           // handler functions need many params
#![allow(clippy::identity_op)]                  // 0 | HARDENED_BIT for BIP32 path clarity
#![allow(clippy::single_match)]                 // match with one arm often clearer than if-let
#![allow(clippy::nonminimal_bool)]              // expanded bool for readability in crypto
#![allow(clippy::manual_div_ceil)]              // (a + b - 1) / b — .div_ceil() not stable in no_std
#![allow(clippy::unnecessary_min_or_max)]       // explicit min/max for bounds documentation
#![allow(clippy::manual_clamp)]                 // explicit if/else clamp for clarity
#![allow(clippy::manual_find)]                  // manual loop find in no_std
#![allow(clippy::manual_is_multiple_of)]        // x % n == 0 — .is_multiple_of() not stable in no_std
#![allow(clippy::if_same_then_else)]            // platform-specific cfg blocks
#![allow(clippy::manual_memcpy)]                // manual slice copy in unsafe DMA blocks
#![allow(clippy::manual_saturating_arithmetic)] // explicit saturating in crypto
// [S2] 45 allows removed 2026-09-01, and the reason is that they never did
// anything. There is no `#![warn(clippy::pedantic)]`, no nursery, and no
// clippy.toml anywhere in the tree, and CI runs
// `cargo clippy --all-targets -- -D warnings`. So every allow naming a lint
// outside clippy's default groups suppressed a warning that could not fire.
//
// That is worse than harmless. `cast_possible_truncation` sat here with a
// comment reading "ubiquitous u32->u8, usize->u8 in byte manipulation", which
// reads as a considered decision about casts. Nobody had ever seen the
// warnings: turning the lint on with `--force-warn` produced 120, of which 29
// are in key-derivation or consensus code. Those 29 were audited on 2026-09-01
// and every one is sound, but the audit happened because the allow was
// questioned, not because it was there.
//
// The ones below are load-bearing: each suppresses a lint in a default group,
// so deleting one turns CI red. Kept verbatim identical between this file and
// its twin so the shared sources compile under the same lints in both crates.
//
// To revisit the removed set, add `#![warn(clippy::pedantic)]` rather than
// re-adding allows: that makes the suppressions mean something.
//
// FOUR of the removals were WRONG and clippy said so on 2026-09-01:
// `needless_lifetimes`, `unnecessary_mut_passed`, `manual_range_contains`
// and `collapsible_else_if` are default-group lints, not pedantic, so
// their allows were load-bearing. Restored below. The classification
// behind this cleanup was recalled rather than measured, which is why it
// was run against all four configurations before it was trusted.
//
// LIMIT OF THIS METHOD, worth knowing before trusting the survivors: a
// clippy run only exposes an allow whose lint has a violation somewhere
// in the code. An allow for a default-group lint that nothing currently
// violates was removed silently here and will only surface the day
// someone writes code that trips it.
#![allow(clippy::manual_range_patterns)]        // manual range patterns for touch zones
#![allow(clippy::implicit_saturating_sub)]      // manual arithmetic for saturating subtract
#![allow(clippy::manual_pattern_char_comparison)] // explicit case comparison
#![allow(clippy::doc_lazy_continuation)]        // doc comment formatting

extern crate alloc;

#[macro_use]
pub mod log;
pub mod entropy;
pub mod crypto;
pub mod wallet;
pub mod qr;
pub mod types;
pub mod ext;
pub mod fat32;
pub mod timefmt;

#[cfg(any(test, feature = "fuzz-api"))]
pub mod fuzz_api;
#[cfg(any(test, feature = "fuzz-api"))]
pub mod fuzz_smoke;
#[cfg(test)]
mod self_tests;
#[cfg(test)]
mod fat32_tests;
#[cfg(test)]
mod pskb_compat_tests;
#[cfg(test)]
mod reference_vectors_tests;
#[cfg(test)]
mod hint_vectors_tests;
