// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Export-menu handlers grouped behind the export controller façade.

pub(super) mod root;
pub(super) mod seed;
pub(super) mod signing_keys;


use crate::runtime::interactions::TouchInput;

/// Hardware-free pre-dispatch for export states that only change navigation
/// or in-memory presentation state. Hardware fallback remains for derivation,
/// SD access, and error feedback.
pub(crate) fn handle_navigation_touch(
    ad: &mut crate::runtime::data::AppData,
    list_zones: &[crate::hw::touch::TouchZone; 4],
    page_up_zone: &crate::hw::touch::TouchZone,
    page_down_zone: &crate::hw::touch::TouchZone,
    input: TouchInput,
) -> Option<bool> {
    if let Some(result) = super::seed_backup::handle(ad, input.is_back) { return Some(result); }
    if let Some(result) = super::seed_qr::handle(ad, input.x, input.y, input.is_back) { return Some(result); }
    if let Some(result) = super::address::handle_pure(ad, input.x, input.y, input.is_back) { return Some(result); }
    if let Some(result) = super::kpub::handle_pure(ad, input.x, input.is_back) { return Some(result); }
    if let Some(result) = super::private_key::handle_pure(ad) { return Some(result); }
    if let Some(result) = super::watch_only::handle_pure(ad, list_zones, input.x, input.y, input.is_back) { return Some(result); }
    if let Some(result) = super::xprv::handle_pure(ad, list_zones, page_up_zone, page_down_zone, input.x, input.y, input.is_back) { return Some(result); }
    if let Some(result) = root::handle_pure(ad, list_zones, page_up_zone, page_down_zone, input) { return Some(result); }
    if let Some(result) = seed::handle_pure(ad, list_zones, page_up_zone, page_down_zone, input) { return Some(result); }
    signing_keys::handle(ad, list_zones, input.x, input.y, input.is_back)
}
