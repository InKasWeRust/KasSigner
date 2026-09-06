// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Seed deletion controller. Destructive hardware/domain effects are owned by
//! the event-loop destructive service after a continuous hold confirmation.

use super::{AppData, RedrawFlag, sound};
use crate::{
    runtime::{destructive::{self, DestructiveAction, TouchRect}, input::AppState},
};

const DELETE_BUTTON: TouchRect = TouchRect::new(170, 180, 290, 230);

pub(super) fn handle(
    ad: &mut AppData,
    x: u16,
    y: u16,
    is_back: bool,
) -> Option<bool> {
    if ad.navigation.app.state != AppState::ConfirmDeleteSeed {
        return None;
    }
    let mut redraw = RedrawFlag::default();
    if is_back || ((30..=150).contains(&x) && (180..=230).contains(&y)) {
        ad.wallet.seeds.pending_delete_slot = 0xFF;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SeedList));
        if !is_back {
            sound::click();
        }
        redraw.set(true);
    } else if DELETE_BUTTON.contains(x, y) {
        destructive::begin(ad, DestructiveAction::DeleteSeed);
    }
    Some(redraw.value())
}
