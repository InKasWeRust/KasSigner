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

use crate::runtime::interactions::feedback::RedrawFlag;
use crate::runtime::interactions::TouchInput;
use crate::{runtime::data::AppData, hw::{display, touch}, services::{audio as sound, storage_device}};
mod transaction;
mod multisig_setup;
mod multisig_output;
mod message_source;
mod message_signing;
mod commit_reveal;
mod covenant_signing;
mod private_swap;
mod commit_results;

pub(crate) use transaction::{load_compact_transaction_with_checkpoint, load_standard_transaction_with_checkpoint};
#[cfg(feature = "workflow-test-auto")]
pub(crate) use transaction::{
    load_compact_transaction, load_standard_transaction, workflow_load_compact_transaction,
    workflow_load_standard_transaction, workflow_mark_standard_pskt_review_state_failure,
    workflow_replay_standard_pskt_failure_reason,
};
pub(crate) use multisig_setup::seed_picker::{advance_after_cosigner, resolve_loaded_cosigner_index};

pub struct TxTouchContext<'ctx, 'display, 'hal> {
    pub ad: &'ctx mut AppData,
    pub boot_display: &'ctx mut display::BootDisplay<'display>,
    pub delay: &'ctx mut esp_hal::delay::Delay,
    pub i2c: &'ctx mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    pub sd_card_type: &'ctx Option<storage_device::SdCardType>,
    pub liveness: &'ctx mut dyn FnMut(),
    pub list_zones: &'ctx [touch::TouchZone; 4],
    pub input: TouchInput,
}

#[inline(never)]
pub fn handle_tx_touch(context: TxTouchContext<'_, '_, '_>) -> Option<bool> {
    let TxTouchContext {
        ad,
        boot_display,
        delay,
        i2c,
        sd_card_type,
        liveness,
        list_zones,
        input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    if let Some(result) = transaction::handle(ad, boot_display, delay, liveness, x, y, is_back) {
        return Some(result);
    }
    if let Some(result) = multisig_setup::handle(ad, boot_display, delay, liveness, x, y, is_back) {
        return Some(result);
    }
    if let Some(result) = multisig_output::handle(ad, delay, i2c, x, y, is_back) {
        return Some(result);
    }
    if let Some(result) = message_source::handle(
        ad, boot_display, delay, i2c, list_zones, x, y, is_back,
    ) { return Some(result); }
    if let Some(result) = message_signing::handle(
        ad, boot_display, delay, liveness, i2c, sd_card_type, x, y, is_back,
    ) { return Some(result); }
    if let Some(result) = covenant_signing::handle(ad, boot_display, delay, liveness, x, y, is_back) { return Some(result); }
    if let Some(result) = private_swap::handle(ad, boot_display, delay, liveness, x, y, is_back) { return Some(result); }
    if let Some(result) = commit_reveal::handle(ad, boot_display, delay, liveness, x, y, is_back) {
        return Some(result);
    }
    if let Some(result) = commit_results::handle(ad, boot_display, delay, x, y, is_back) {
        return Some(result);
    }
    None
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) use message_signing::workflow_sign_preview as workflow_sign_message_preview;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use message_source::workflow_accept_file as workflow_accept_message_file;
#[cfg(feature = "workflow-test-auto")]
pub(crate) use commit_reveal::{
    workflow_encrypt_preimage as workflow_encrypt_commit_secret,
    workflow_store_secret as workflow_store_commit_secret,
};
