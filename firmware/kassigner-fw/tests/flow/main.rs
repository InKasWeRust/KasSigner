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

//! The device flow, arrow by arrow, on the host.
//!
//! A flow is driven with events as the binary's loop drives it, with a fake
//! entropy source, hand-built requests and a SeedQR of a known seed.
//! Checked: which state follows which event, what the screen names, what
//! the loop is told to do, and above all that only CONFIRM after every page
//! was drawn produces a signature.

use kassigner_crypto::bip39;
use kassigner_crypto::slot::{self, Slot};
use kassigner_crypto::wallet::Wallet;
use kassigner_fw::card::{self, Job, Kind, Outcome};
use kassigner_fw::flow::{
    card_done_us, Buffers, Check, Command, Config, Event, Flow, Halt, MenuId, Output, Refusal,
    Screen, State, Unshown, BACKLIGHT_FLOOR, CHECK_ROUNDS, ERROR_US, HOLD_US, IDLE_WIPE_US,
    OPEN_STEPS, REFUSED_US, SETTLE_US, VERIFIED_US, WIPED_US, WIPE_HOLD_US,
};
use kassigner_fw::review::Page;
use kassigner_fw::seed::Source;
use kassigner_fw::sizes::Sizes;
use kassigner_fw::text::Hidden;
use kassigner_fw::touch::Zone;
use kassigner_fw::ui::chrome::{self, Nav};
use kassigner_fw::ui::scale::Scale;
use kassigner_fw::ui::{brand, camtune, dialog, keyboard, menu, review, sd_card, seeds, settings};
use kassigner_fw::wipe::{Mark, Stack};
use kassigner_hal::display::Size;
use kassigner_hal::entropy::{self, Entropy};
use kassigner_hal::provisioning::{Holes, Verdict};
use kassigner_hal::tune::Knob;
use kassigner_kaspa::bip340;
use kassigner_kaspa::constants::SOMPI_PER_KASPA as KAS;
use kassigner_kaspa::derivation::Path;
use kassigner_kaspa::sighash::{schnorr_signature_hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_protocol::kspt::transaction as kspt_tx;
use kassigner_protocol::kspt::{self, InputSignature, MAGIC, VERSION};
use kassigner_protocol::profile::{Capacity, Profile};

#[path = "../../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex, unhex_array};
#[path = "../../../../testkit/kspt_bytes.rs"]
pub mod kspt_bytes;
use kspt_bytes::spk_len;
#[path = "../../../../testkit/transaction.rs"]
pub mod transaction;
use transaction::p2pk;
#[path = "../../../../testkit/v107.rs"]
pub mod v107;
use v107::{cosigner_key, redeem_keys};

// What every topic shares, then a module per topic, each taking these
// imports and `common` through `use super::*;`.
mod common;
use common::*;

mod addresses;
mod backup_check;
mod boot;
mod card_files;
mod corpus_v107;
mod fuzz;
mod home_menus;
mod kpubs;
mod messages;
mod multisig;
mod replies;
mod savings;
mod screens;
mod seed_slots;
mod seed_tools;
mod signing;
mod signing_keys;
mod stego;
mod wipes;

/// SIGNED TX QR's two cards.
use kassigner_fw::ui::kpub::Target as Card;
