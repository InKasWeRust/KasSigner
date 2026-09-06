// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// runtime/data/runtime.rs — RuntimeState

use crate::runtime::destructive::DestructiveAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestructiveHoldState {
    pub(crate) action: DestructiveAction,
    pub(crate) awaiting_release: bool,
    pub(crate) started_at_ms: u64,
    pub(crate) progress_step: u8,
    pub(crate) prompt_drawn: bool,
}


#[cfg(feature = "argon2-bench")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Argon2BenchmarkRequest {
    Idle,
    Requested,
}

impl DestructiveHoldState {
    pub(crate) const fn new() -> Self {
        Self {
            action: DestructiveAction::None,
            awaiting_release: false,
            started_at_ms: 0,
            progress_step: 0,
            prompt_drawn: false,
        }
    }
}

pub struct RuntimeState {
    pub needs_redraw: bool,
    pub idle_ticks: u32,
    pub display_asleep: bool,
    pub home_reached: bool,
    pub qr_brightness_override: Option<u8>,
    pub reauth_return_to: Option<crate::runtime::navigation::ContinuationRoute>,
    pending_wallet_activation: Option<u8>,
    pending_wallet_protection_update: Option<u8>,
    #[cfg(feature = "argon2-bench")]
    argon2_benchmark_request: Argon2BenchmarkRequest,
    pub(crate) destructive: DestructiveHoldState,
}

impl RuntimeState {
    pub(super) fn new() -> Self {
        Self {
            needs_redraw: true,
            idle_ticks: 0,
            display_asleep: false,
            home_reached: false,
            qr_brightness_override: None,
            reauth_return_to: None,
            pending_wallet_activation: None,
            pending_wallet_protection_update: None,
            #[cfg(feature = "argon2-bench")]
            argon2_benchmark_request: Argon2BenchmarkRequest::Idle,
            destructive: DestructiveHoldState::new(),
        }
    }
}

impl RuntimeState {
    pub(crate) fn begin_pin_reauth(
        &mut self,
        return_to: crate::runtime::navigation::ContinuationRoute,
    ) -> bool {
        if self.reauth_return_to.is_some() { return false; }
        self.reauth_return_to = Some(return_to);
        true
    }

    pub(crate) fn take_pin_reauth_return(
        &mut self,
    ) -> Option<crate::runtime::navigation::ContinuationRoute> {
        self.reauth_return_to.take()
    }
    pub(crate) fn begin_wallet_activation_reauth(&mut self, slot: usize) -> bool {
        let Ok(slot) = u8::try_from(slot) else { return false; };
        if self.pending_wallet_activation.is_some() { return false; }
        self.pending_wallet_activation = Some(slot);
        true
    }

    pub(crate) fn take_pending_wallet_activation(&mut self) -> Option<usize> {
        self.pending_wallet_activation.take().map(usize::from)
    }

    pub(crate) fn pending_wallet_activation(&self) -> Option<usize> {
        self.pending_wallet_activation.map(usize::from)
    }

    pub(crate) fn cancel_pending_wallet_activation(&mut self) -> bool {
        self.pending_wallet_activation.take().is_some()
    }

    pub(crate) fn begin_wallet_protection_update(&mut self, slot: usize) -> bool {
        let Ok(slot) = u8::try_from(slot) else { return false; };
        if self.pending_wallet_protection_update.is_some() { return false; }
        self.pending_wallet_protection_update = Some(slot);
        true
    }

    pub(crate) fn pending_wallet_protection_update(&self) -> Option<usize> {
        self.pending_wallet_protection_update.map(usize::from)
    }

    pub(crate) fn take_pending_wallet_protection_update(&mut self) -> Option<usize> {
        self.pending_wallet_protection_update.take().map(usize::from)
    }

    pub(crate) fn cancel_pending_wallet_protection_update(&mut self) -> bool {
        self.pending_wallet_protection_update.take().is_some()
    }
}

#[cfg(feature = "argon2-bench")]
impl RuntimeState {
    pub(crate) fn request_argon2_benchmark(&mut self) {
        self.argon2_benchmark_request = Argon2BenchmarkRequest::Requested;
    }

    pub(crate) fn take_argon2_benchmark_request(&mut self) -> bool {
        let requested = self.argon2_benchmark_request == Argon2BenchmarkRequest::Requested;
        self.argon2_benchmark_request = Argon2BenchmarkRequest::Idle;
        requested
    }
}
