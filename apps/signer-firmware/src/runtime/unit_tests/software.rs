// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Verbose software self-tests run during the firmware boot validation.

use crate::wallet::{mnemonic, seed_manager};

/// Run software-domain self-tests and merge their result with prior hardware checks.
pub(super) fn run(initial_result: bool) -> bool {
    let mut all_passed = initial_result;
    log!("BIP39 Self-Tests");
    log!("─────────────────────────────");

    let (passed, total) = offline_signer::derivation::bip39::unit_tests::run_bip39_tests();
    all_passed &= passed == total;
    log!("   BIP39 tests: {}/{} passed", passed, total);

    if passed != total {
        log!("   CRITICAL: BIP39 implementation has failures!");
    } else {
        log!("   BIP39 module verified OK");
    }

    let (passed32, total32) = offline_signer::derivation::bip32::unit_tests::run_bip32_tests();
    all_passed &= passed32 == total32;
    log!("   BIP32 tests: {}/{} passed", passed32, total32);

    if passed32 != total32 {
        log!("   CRITICAL: BIP32 implementation has failures!");
    } else {
        log!("   BIP32 module verified OK");
    }

    let (passed_sc, total_sc) = offline_signer::crypto::schnorr::unit_tests::run_schnorr_tests();
    all_passed &= passed_sc == total_sc;
    log!("   Schnorr tests: {}/{} passed", passed_sc, total_sc);

    if passed_sc != total_sc {
        log!("   CRITICAL: Schnorr implementation has failures!");
    } else {
        log!("   Schnorr module verified OK");
    }

    let (passed_st, total_st) = offline_signer::crypto::legacy_pbkdf2::unit_tests::run_legacy_pbkdf2_tests();
    all_passed &= passed_st == total_st;
    log!("   Legacy PBKDF2 compatibility vectors: {}/{} passed", passed_st, total_st);

    if passed_st != total_st {
        log!("   CRITICAL: Legacy PBKDF2 compatibility vectors failed!");
    } else {
        log!("   Legacy PBKDF2 compatibility verified OK");
    }

    // The complete backup/steganographic compatibility suite repeatedly executes
    // the production memory-hard Argon2id profile and is intentionally host-only.
    // Ordinary interactive boot must remain bounded; physical Argon2/PSRAM coverage
    // belongs to the dedicated hardware-test benchmark instead of this software KAT.
    log!("   Backup compatibility tests: host QA (memory-hard batch not run at boot)");

    let (passed_sh, total_sh) = offline_signer::transaction::sighash::unit_tests::run_sighash_tests();
    all_passed &= passed_sh == total_sh;
    log!("   SigHash tests: {}/{} passed", passed_sh, total_sh);

    if passed_sh != total_sh {
        log!("   CRITICAL: SigHash implementation has failures!");
    } else {
        log!("   SigHash+Blake2b module verified OK");
    }

    let (passed_ps, total_ps) = offline_signer::transaction::kspt::unit_tests::run_kspt_tests();
    all_passed &= passed_ps == total_ps;
    log!("   KSPT tests: {}/{} passed", passed_ps, total_ps);

    if passed_ps != total_ps {
        log!("   CRITICAL: KSPT implementation has failures!");
    } else {
        log!("   KSPT module verified OK");
    }
    log!();

    // QR Encoder tests
    let (passed_qr, total_qr) = crate::qr::encoder::unit_tests::run_tests();
    all_passed &= passed_qr == total_qr;
    log!("   QR tests: {}/{} passed", passed_qr, total_qr);

    if passed_qr != total_qr {
        log!("   CRITICAL: QR encoder has failures!");
    } else {
        log!("   QR encoder verified OK");
    }

    // QR decoder: rqrr has no internal test suite — round-trip tests in run_boot_tests() cover this
    log!("   QR decoder: rqrr V1-V40 (round-trip tested at boot)");
    log!();

    // App Input / State Machine tests
    let (passed_app, total_app) = crate::runtime::input::unit_tests::run_tests();
    all_passed &= passed_app == total_app;
    log!("   App tests: {}/{} passed", passed_app, total_app);

    if passed_app != total_app {
        log!("   CRITICAL: App state machine has failures!");
    } else {
        log!("   App state machine verified OK");
    }


    // Firmware flow-integrity transcript tests.
    let (passed_flow, total_flow) = crate::crypto::unit_tests::flow_tests::run_flow_tests();
    all_passed &= passed_flow == total_flow;
    log!("   Flow integrity tests: {}/{} passed", passed_flow, total_flow);

    // Structural entropy health tests are deterministic and hardware-free.
    let (passed_entropy, total_entropy) =
        crate::services::unit_tests::entropy_tests::run_entropy_health_tests();
    all_passed &= passed_entropy == total_entropy;
    log!(
        "   Entropy health tests: {}/{} passed",
        passed_entropy,
        total_entropy
    );
    if passed_entropy != total_entropy {
        log!("   CRITICAL: Entropy health vectors have failures!");
    } else {
        log!("   Entropy health vectors verified OK");
    }

    // Mnemonic-domain tests
    let (passed_mnemonic, total_mnemonic) = mnemonic::unit_tests::run_mnemonic_tests();
    all_passed &= passed_mnemonic == total_mnemonic;
    log!("   Mnemonic tests: {}/{} passed", passed_mnemonic, total_mnemonic);
    if passed_mnemonic != total_mnemonic {
        log!("   CRITICAL: Mnemonic domain has failures!");
    } else {
        log!("   Mnemonic domain verified OK");
    }

    // Seed Manager tests (SeedQR, fingerprint, slot management)
    let (passed_sm, total_sm) = seed_manager::unit_tests::run_seed_manager_tests();
    all_passed &= passed_sm == total_sm;
    log!("   SeedManager tests: {}/{} passed", passed_sm, total_sm);
    if passed_sm != total_sm {
        log!("   CRITICAL: SeedManager has failures!");
    } else {
        log!("   SeedManager verified OK");
    }

    let (passed_wallet, total_wallet) =
        crate::runtime::unit_tests::wallet_session::run_tests();
    all_passed &= passed_wallet == total_wallet;
    log!(
        "   Wallet session tests: {}/{} passed",
        passed_wallet,
        total_wallet
    );
    if passed_wallet != total_wallet {
        log!("   CRITICAL: Wallet cache isolation has failures!");
    } else {
        log!("   Wallet cache isolation verified OK");
    }

    // Address encoding tests (verified against official rusty-kaspa vectors)
    let (passed_addr, total_addr) = offline_signer::address::unit_tests::run_address_tests();
    all_passed &= passed_addr == total_addr;
    log!("   Address tests: {}/{} passed", passed_addr, total_addr);
    if passed_addr != total_addr {
        log!("   CRITICAL: Address encoding has failures!");
    } else {
        log!("   Address encoding verified OK (matches rusty-kaspa)");
    }

    // xpub / kpub tests
    let (passed_xpub, total_xpub) = offline_signer::derivation::xpub::unit_tests::run_xpub_tests();
    all_passed &= passed_xpub == total_xpub;
    log!("   xpub tests: {}/{} passed", passed_xpub, total_xpub);
    if passed_xpub != total_xpub {
        log!("   CRITICAL: xpub/kpub encoding has failures!");
    } else {
        log!("   xpub/kpub encoding verified OK");
    }
    log!();
    all_passed
}
