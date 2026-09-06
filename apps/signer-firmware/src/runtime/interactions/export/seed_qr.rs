// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! SeedQR export and grid navigation.

use crate::{
    runtime::{data::AppData, input::AppState},
    wallet::seed_manager,
};
use signer_firmware_core::presentation::seed_qr_grid::{
    SeedQrGridEffect, SeedQrGridState, reduce_grid,
};

pub(super) fn handle(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> Option<bool> {
    let state = ad.navigation.app.state;
    match state {
        AppState::ExportSeedQR => {
            if is_back {
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
            } else {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedQrGrid {
                    pan_x: 0,
                    pan_y: 0,
                    compact: false,
                }));
            }
            Some(true)
        }
        AppState::ExportCompactSeedQR => {
            if is_back {
                crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
            } else {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedQrGrid {
                    pan_x: 0,
                    pan_y: 0,
                    compact: true,
                }));
            }
            Some(true)
        }
        AppState::SeedQrGrid { pan_x, pan_y, compact } => {
            let qr_size = if is_back {
                0
            } else {
                let Some(size) = active_qr_size(ad, compact) else {
                    return Some(false);
                };
                size
            };
            let effect = reduce_grid(
                SeedQrGridState { pan_x, pan_y, compact },
                qr_size,
                x,
                y,
                is_back,
            );
            Some(apply_grid_effect(ad, effect))
        }
        AppState::ExportPlainWordsQR => {
            crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
            Some(true)
        }
        _ => None,
    }
}

fn active_qr_size(ad: &AppData, compact: bool) -> Option<u8> {
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        return Some(21);
    };
    let word_count = slot.mnemonic_word_count()?;
    if compact {
        let mut buffer = [0u8; 32];
        let length = seed_manager::encode_compact_seedqr(&slot.indices, word_count, &mut buffer);
        Some(crate::qr::encoder::encode(&buffer[..length]).map_or(21, |qr| qr.size))
    } else {
        let mut buffer = [0u8; 96];
        let length = seed_manager::encode_seedqr(&slot.indices, word_count, &mut buffer);
        Some(crate::qr::encoder::encode(&buffer[..length]).map_or(29, |qr| qr.size))
    }
}

fn apply_grid_effect(ad: &mut AppData, effect: SeedQrGridEffect) -> bool {
    match effect {
        SeedQrGridEffect::None => false,
        SeedQrGridEffect::Exit => {
            crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SeedBackup);
            true
        }
        SeedQrGridEffect::Move(next) => {
            // Panning changes only the viewport of the same logical screen.
            // Replacing it in place preserves the ExportSeedQR/ExportCompactSeedQR
            // parent in bounded history no matter how far the user pans.
            crate::runtime::effects::replace(ad, crate::runtime::navigation::route!(SeedQrGrid {
                pan_x: next.pan_x,
                pan_y: next.pan_y,
                compact: next.compact,
            }));
            true
        }
    }
}
