// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Compile-time platform feature policy.

#![cfg_attr(feature = "hardware-tests", allow(dead_code))]
#![cfg_attr(feature = "workflow-test-auto", allow(dead_code))]
#[cfg(not(any(feature = "waveshare", feature = "m5stack", feature = "qemu")))]
compile_error!("select one platform feature: waveshare, m5stack, or qemu");

#[cfg(any(
    all(feature = "waveshare", feature = "m5stack"),
    all(feature = "waveshare", feature = "qemu"),
    all(feature = "m5stack", feature = "qemu")
))]
compile_error!(
    "platform features are mutually exclusive; QEMU requires --no-default-features --features qemu"
);

#[cfg(all(
    feature = "qemu",
    any(
        feature = "af",
        feature = "e12-capture",
        feature = "hardware-tests",
        feature = "mirror",
        feature = "ov2640-wide",
        feature = "screenshot",
        feature = "silent",
        feature = "skip-tests",
        feature = "test-psram",
        feature = "workflow-tests",
        feature = "workflow-test-auto",
        feature = "wdev-capture",
        feature = "argon2-bench",
        feature = "developer-ui"
    )
))]
compile_error!("qemu cannot be combined with non-QEMU firmware features");

#[cfg(all(
    feature = "qemu",
    feature = "verbose-boot",
    not(feature = "qemu-tests")
))]
compile_error!("qemu verbose boot tests require the qemu-tests feature");


#[cfg(all(
    feature = "silent",
    any(
        feature = "sentinel-scan",
        feature = "e12-capture",
        feature = "rng-probe",
        feature = "wdev-capture",
        feature = "sha-bench",
        feature = "argon2-bench",
        feature = "imu-dump",
        feature = "icon-browser",
        feature = "cam640",
        feature = "boot-kats-full",
        feature = "workflow-tests",
        feature = "workflow-test-auto",
        feature = "developer-ui"
    )
))]
compile_error!("developer/QA firmware features are forbidden in production/silent builds");

#[cfg(all(
    feature = "production",
    feature = "provisioning-ui",
    not(any(feature = "secure-provisioning", feature = "secure-owner-only"))
))]
compile_error!("production Pop It!/ownership UI requires a dedicated secure provisioning profile");

#[cfg(all(feature = "secure-provisioning", feature = "secure-owner-only"))]
compile_error!("secure-provisioning and secure-owner-only are mutually exclusive trust policies");

#[cfg(all(
    feature = "secure-provisioning-core",
    not(any(feature = "secure-provisioning", feature = "secure-owner-only"))
))]
compile_error!("secure-provisioning-core is internal; select secure-provisioning or secure-owner-only");

#[cfg(all(any(feature = "secure-provisioning", feature = "secure-owner-only"), not(feature = "m5stack")))]
compile_error!("secure provisioning profiles are supported only on M5Stack CoreS3");

#[cfg(all(
    feature = "owner-firmware",
    any(feature = "secure-provisioning", feature = "secure-owner-only")
))]
compile_error!("owner-firmware is a post-provisioning application profile and cannot be combined with a provisioning profile");

#[cfg(all(feature = "cam640", feature = "ov2640-wide"))]
compile_error!("cam640 is an OV5640-only diagnostic mode and cannot be combined with ov2640-wide");

