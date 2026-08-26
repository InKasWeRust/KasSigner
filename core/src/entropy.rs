// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// entropy.rs — the one hardware input the signing path needs, injected.
//
// `schnorr::generate_rfc6979_nonce` hedges the deterministic nonce with 32
// bytes of hardware entropy (H-05) and refuses to sign when it cannot get
// them. In the firmware that call was `crate::crypto::entropy::fill`, which
// samples the SAR ADC, RC_FAST and the systimer, so it cannot live here. The
// firmware registers it once at boot; `fill` below forwards to it.
//
// Fail closed is preserved exactly: with no source registered `fill` returns
// `Err`, the nonce generator maps that to `SchnorrError::EntropyUnavailable`,
// and no signature is produced. A host test that forgets to register a
// source therefore refuses to sign rather than signing deterministically.

use core::sync::atomic::{AtomicPtr, Ordering};

/// The source signature: fill the whole slice or report failure.
pub type SourceFn = fn(&mut [u8]) -> Result<(), ()>;

/// Returned by `fill` when no source is registered or the source failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

// Same storage pattern as `log::LOGGER`; see the note there.
static SOURCE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the hardware entropy source. Called once by the firmware at
/// boot, before any signing path can run.
pub fn set_source(f: SourceFn) {
    SOURCE.store(f as *mut (), Ordering::Release);
}

/// Fill `out` from the registered source.
pub fn fill(out: &mut [u8]) -> Result<(), EntropyUnavailable> {
    let p = SOURCE.load(Ordering::Acquire);
    if p.is_null() {
        return Err(EntropyUnavailable);
    }
    // SAFETY: the only writer is `set_source`, which stores a `SourceFn`
    // cast to `*mut ()`; the non-null pointer read here is converted back
    // to the type it came from.
    let f: SourceFn = unsafe { core::mem::transmute::<*mut (), SourceFn>(p) };
    f(out).map_err(|_| EntropyUnavailable)
}
