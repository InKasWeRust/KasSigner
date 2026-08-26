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
#![allow(clippy::bool_comparison)]              // explicit == true/false in some contexts
#![allow(clippy::manual_range_patterns)]        // manual range patterns for touch zones
#![allow(clippy::implicit_saturating_sub)]      // manual arithmetic for saturating subtract
#![allow(clippy::manual_pattern_char_comparison)] // explicit case comparison
#![allow(clippy::manual_ignore_case_cmp)]       // manual ASCII comparison
#![allow(clippy::unnecessary_mut_passed)]       // mutable ref to DMA methods
#![allow(clippy::bool_to_int_with_if)]          // if x { 1 } else { 0 } patterns
#![allow(clippy::collapsible_else_if)]          // else { if } with trailing statements
#![allow(clippy::manual_range_contains)]        // explicit range checks in SD filename parsing
#![allow(clippy::doc_lazy_continuation)]        // doc comment formatting
#![allow(clippy::cast_possible_truncation)]     // ubiquitous u32→u8, usize→u8 in byte manipulation
#![allow(clippy::cast_possible_wrap)]           // u32→i32 in display coordinates
#![allow(clippy::cast_sign_loss)]               // i32→u32 in display/touch coordinates
#![allow(clippy::cast_lossless)]                // u8 as u32 — explicit for clarity in packed structs
#![allow(clippy::items_after_statements)]       // local structs/consts near point of use in handlers
#![allow(clippy::doc_markdown)]                 // technical terms without backticks
#![allow(clippy::wildcard_imports)]             // embedded-graphics prelude pattern
#![allow(clippy::used_underscore_binding)]      // _var used intentionally then read
#![allow(clippy::ptr_as_ptr)]                   // raw pointer casts in DMA/register code
#![allow(clippy::similar_names)]                // pos/prev, bw/bh, x0/x1 etc
#![allow(clippy::unreadable_literal)]           // hex/binary constants (0x6a09e667f3bcc908, 0b01110)
#![allow(clippy::map_unwrap_or)]                // .map().unwrap_or() clearer than map_or in some contexts
#![allow(clippy::explicit_iter_loop)]           // .iter() explicit for clarity in no_std
#![allow(clippy::match_same_arms)]              // platform-specific cfg blocks with identical arms
#![allow(clippy::unnecessary_wraps)]            // consistent Result return in handler chains
#![allow(clippy::ref_option)]                   // &Option<T> in existing function signatures
#![allow(clippy::inline_always)]                // intentional for register read/write hot paths
#![allow(clippy::trivially_copy_pass_by_ref)]   // &u8 in trait-matching signatures
#![allow(clippy::single_char_lifetime_names)]   // standard Rust lifetime naming
#![allow(clippy::struct_excessive_bools)]        // hardware state structs
#![allow(clippy::manual_let_else)]              // explicit if/return pattern
#![allow(clippy::redundant_else)]               // explicit else after return for clarity
#![allow(clippy::if_not_else)]                   // !flag reads fine
#![allow(clippy::single_match_else)]            // match with else arm for clarity
#![allow(clippy::many_single_char_names)]       // x, y, w, h, r in geometry code
#![allow(clippy::borrow_as_ptr)]                // &mut x as *mut in DMA code
#![allow(clippy::manual_midpoint)]              // (a + b) / 2 — .midpoint() not stable in no_std
#![allow(clippy::ref_as_ptr)]                   // &x as *const in register/DMA code
#![allow(clippy::ptr_cast_constness)]           // *mut as *const in DMA
#![allow(clippy::unnecessary_operation)]        // explicit ops for clarity
#![allow(clippy::match_wildcard_for_single_variants)] // _ arm for future-proofing enums
#![allow(clippy::too_many_lines)]               // large embedded handler functions
#![allow(clippy::needless_lifetimes)]           // explicit lifetimes for documentation
#![allow(clippy::unused_self)]                  // trait conformance
#![allow(clippy::enum_glob_use)]                // use Enum::* for variant-heavy matches
#![allow(clippy::doc_link_with_quotes)]         // doc comment formatting
#![allow(clippy::verbose_bit_mask)]             // explicit bit mask for clarity in register code
#![allow(clippy::redundant_closure_for_method_calls)] // .map(|s| s.method()) in handler chains
#![allow(clippy::needless_continue)]            // explicit continue in match arms for clarity

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
