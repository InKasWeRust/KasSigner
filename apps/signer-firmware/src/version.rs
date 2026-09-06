// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// version.rs — Single source of truth for the firmware version.
//
// The project version lives in **one** place: `apps/signer-firmware/Cargo.toml`
// (the `[package] version = "X.Y.Z"` line). Cargo injects it at compile
// time as the `CARGO_PKG_VERSION_{MAJOR,MINOR,PATCH}` environment
// variables, which this module parses into `u8` constants.
//
// Downstream consumers (`services::verify::FirmwareInfo`,
// `services::fw_update::CURRENT_VERSION`, boot-screen renderers,
// CHANGELOG references) should all read from here — never hardcode a
// version number anywhere else in the codebase.
//
// To cut a new release: edit `apps/signer-firmware/Cargo.toml` only. Rebuild.
// Every on-screen and on-serial version string updates automatically.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]

/// Parse an ASCII decimal string into a u8 at compile time.
///
/// Cargo guarantees CARGO_PKG_VERSION_* components are valid decimal
/// integers ≤ 255 for our use, so this is panic-free in practice.
/// Aborts at compile time if the string is empty, contains non-digits,
/// or overflows u8.
const fn parse_u8_const(s: &str) -> u8 {
    let bytes = s.as_bytes();
    let len = bytes.len();
    assert!(len > 0, "empty version component");
    let mut acc: u32 = 0;
    let mut i = 0;
    while i < len {
        let b = bytes[i];
        assert!(b >= b'0' && b <= b'9', "version component must be decimal digits");
        acc = acc * 10 + (b - b'0') as u32;
        i += 1;
    }
    assert!(acc <= 255, "version component > 255");
    acc as u8
}

/// Major version (e.g. `1` for 1.2.3).
pub const MAJOR: u8 = parse_u8_const(env!("CARGO_PKG_VERSION_MAJOR"));

/// Minor version (e.g. `2` for 1.2.3).
pub const MINOR: u8 = parse_u8_const(env!("CARGO_PKG_VERSION_MINOR"));

/// Patch version (e.g. `3` for 1.2.3).
pub const PATCH: u8 = parse_u8_const(env!("CARGO_PKG_VERSION_PATCH"));

// Firmware-update metadata has historically encoded versions as MMmmpp. Keep
// that wire format stable, but enforce its two-digit minor/patch precondition
// at compile time so the mapping remains unambiguous.
const _: () = assert!(MINOR < 100, "firmware minor version must be below 100");
const _: () = assert!(PATCH < 100, "firmware patch version must be below 100");

/// Stable numeric encoding: `major * 10_000 + minor * 100 + patch`.
///
/// The compile-time bounds above make the representation injective while
/// preserving the established firmware-update QR and rollback-protection encoding.
pub const NUMERIC: u32 =
    (MAJOR as u32) * 10_000 + (MINOR as u32) * 100 + PATCH as u32;
