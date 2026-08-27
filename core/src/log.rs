// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// log.rs — the crate's `log!` macro and the single registration point
// behind it.
//
// The wallet code has always logged through the firmware's `crate::log!`,
// which is `esp_println::println!` in non-silent builds and a no-op that
// consumes its arguments in `silent` builds. This crate cannot see esp_println
// and must not, so the macro here forwards `format_args!` to a function the
// firmware registers once at boot. With nothing registered `emit` returns
// before anything is formatted: a silent firmware registers nothing, and the
// wallet code is exactly as silent as before. A host test that wants the
// output registers a printer of its own.
//
// The `{{ }}` arms and the bare `log!()` arm mirror the firmware macro, for
// the same reasons recorded above its definition in main.rs: `log!` is used
// in expression position and as a blank line.

use core::sync::atomic::{AtomicPtr, Ordering};

/// The printer signature. A plain `fn`, not a closure, so a pointer to it
/// can live in an atomic and be set from a single place at boot.
pub type LogFn = fn(core::fmt::Arguments<'_>);

// Stored as a data pointer. Casting a `fn` pointer to `*mut ()` and back is
// the same pattern the `log` crate and esp-hal's own interrupt vectoring
// use; on Xtensa and every host target code and data pointers are the same
// width. A null pointer means "no logger", which is the default.
static LOGGER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the printer. Called once by the firmware before anything in
/// this crate runs; calling it again replaces the printer.
pub fn set_logger(f: LogFn) {
    LOGGER.store(f as *mut (), Ordering::Release);
}

/// Forward one `format_args!` to the registered printer, if any.
#[doc(hidden)]
pub fn emit(args: core::fmt::Arguments<'_>) {
    let p = LOGGER.load(Ordering::Acquire);
    if p.is_null() {
        return;
    }
    // SAFETY: the only writer is `set_logger`, which stores a `LogFn` cast
    // to `*mut ()`; the non-null pointer read here was produced by that
    // cast and is converted back to the type it came from.
    let f: LogFn = unsafe { core::mem::transmute::<*mut (), LogFn>(p) };
    f(args);
}

#[macro_export]
macro_rules! log {
    () => {{ $crate::log::emit(format_args!("")) }};
    ($($arg:tt)*) => {{ $crate::log::emit(format_args!($($arg)*)) }};
}
