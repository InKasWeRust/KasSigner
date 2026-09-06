// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Firmware known-answer suites executed on the emulated Xtensa target.

use super::report::Report;

pub(crate) fn run(report: &mut Report) {
    let (passed, total) = offline_signer::derivation::bip39::unit_tests::run_bip39_tests();
    report.counted("BIP39 vectors", passed, total);

    let (passed, total) = offline_signer::derivation::bip32::unit_tests::run_bip32_tests();
    report.counted("BIP32 vectors", passed, total);

    let (passed, total) = offline_signer::crypto::schnorr::unit_tests::run_schnorr_tests();
    report.counted("BIP340 Schnorr vectors", passed, total);

    let (passed, total) = offline_signer::crypto::legacy_pbkdf2::unit_tests::run_legacy_pbkdf2_tests();
    report.counted("Legacy PBKDF2 vectors", passed, total);

    let (passed, total) = offline_signer::transaction::sighash::unit_tests::run_sighash_tests();
    report.counted("transaction sighash vectors", passed, total);

    let (passed, total) = offline_signer::transaction::kspt::unit_tests::run_kspt_tests();
    report.counted("KSPT vectors", passed, total);

    let (passed, total) = offline_signer::address::unit_tests::run_address_tests();
    report.counted("Kaspa address vectors", passed as u32, total as u32);

    let (passed, total) = offline_signer::derivation::xpub::unit_tests::run_xpub_tests();
    report.counted("kpub/xpub vectors", passed, total);

    report.check(
        "BIP85 child mnemonic vector",
        offline_signer::derivation::bip85::unit_tests::test_bip85_12word_index0(),
    );

    let (passed, total) = crate::qr::encoder::unit_tests::run_tests();
    report.counted("QR encoder vectors", passed, total);

    report.check("firmware touch state machine", test_touch_state_machine());
    report.check("SeedQR grid reducer", test_seed_qr_reducer());
    report.check("transaction touch reducer", test_transaction_reducer());
    report.check("FAT32 LFN state machine", test_fat32_lfn());
    report.check("address render model", test_address_render_model());
}


fn test_touch_state_machine() -> bool {
    use signer_firmware_core::input::touch::{
        HwGesture, ImmediateTouchTracker, TouchAction, TouchEventType, TouchPoint, TouchState,
        TouchTracker,
    };
    let mut tracker = TouchTracker::new();
    let press = TouchState::One(TouchPoint { x: 20, y: 30, event: TouchEventType::PressDown });
    let contact = TouchState::One(TouchPoint { x: 20, y: 30, event: TouchEventType::Contact });
    let delayed_ok = tracker.update(press, HwGesture::None) == TouchAction::None
        && tracker.update(contact, HwGesture::None) == TouchAction::None
        && tracker.update(TouchState::NoTouch, HwGesture::None)
            == TouchAction::Tap { x: 20, y: 30 };
    let mut immediate = ImmediateTouchTracker::new();
    delayed_ok
        && immediate.update(press) == TouchAction::Tap { x: 20, y: 30 }
        && immediate.update(contact) == TouchAction::None
}

fn test_seed_qr_reducer() -> bool {
    use signer_firmware_core::presentation::seed_qr_grid::{
        SeedQrGridEffect, SeedQrGridState, reduce_grid,
    };
    let state = SeedQrGridState { pan_x: 0, pan_y: 0, compact: false };
    reduce_grid(state, 29, 10, 150, false)
        == SeedQrGridEffect::Move(SeedQrGridState { pan_x: 1, ..state })
        && reduce_grid(state, 29, 160, 120, false) == SeedQrGridEffect::None
        && reduce_grid(state, 29, 0, 0, true) == SeedQrGridEffect::Exit
}

fn test_transaction_reducer() -> bool {
    use signer_firmware_core::presentation::transaction::{
        TransactionEffect, TransactionScreen, reduce_touch,
    };

    fn effect_name(effect: TransactionEffect) -> &'static str {
        match effect {
            TransactionEffect::None => "None",
            TransactionEffect::GuideBack => "GuideBack",
            TransactionEffect::DeriveAccount => "DeriveAccount",
            TransactionEffect::BeginScan => "BeginScan",
            TransactionEffect::ScanBack(_) => "ScanBack",
            TransactionEffect::ReviewBack => "ReviewBack",
            TransactionEffect::ReviewAdvance => "ReviewAdvance",
            TransactionEffect::ConfirmBack => "ConfirmBack",
            TransactionEffect::ConfirmChoice(0) => "ConfirmChoice(0)",
            TransactionEffect::ConfirmChoice(1) => "ConfirmChoice(1)",
            TransactionEffect::ConfirmChoice(2) => "ConfirmChoice(2)",
            TransactionEffect::ConfirmChoice(_) => "ConfirmChoice(other)",
        }
    }

    fn expect_case(
        label: &str,
        actual: TransactionEffect,
        expected: TransactionEffect,
    ) -> bool {
        if actual == expected {
            true
        } else {
            crate::log!(
                "[QEMU TEST] DETAIL: transaction touch reducer {} expected={} actual={}",
                label,
                effect_name(expected),
                effect_name(actual)
            );
            false
        }
    }

    let guide = expect_case(
        "guide-derive",
        reduce_touch(TransactionScreen::Guide { seed_loaded: true }, 50, 200, false).effect,
        TransactionEffect::DeriveAccount,
    );
    let confirm = expect_case(
        "confirm-left",
        reduce_touch(TransactionScreen::Confirm, 60, 208, false).effect,
        TransactionEffect::ConfirmChoice(0),
    );
    let cancel = expect_case(
        "confirm-right",
        reduce_touch(TransactionScreen::Confirm, 260, 208, false).effect,
        TransactionEffect::ConfirmChoice(1),
    );
    let inspect = expect_case(
        "confirm-center",
        reduce_touch(TransactionScreen::Confirm, 160, 208, false).effect,
        TransactionEffect::ConfirmChoice(2),
    );
    let confirm_back = expect_case(
        "confirm-back",
        reduce_touch(TransactionScreen::Confirm, 0, 0, true).effect,
        TransactionEffect::ConfirmBack,
    );
    let review_back = expect_case(
        "review-back",
        reduce_touch(TransactionScreen::Review, 0, 0, true).effect,
        TransactionEffect::ReviewBack,
    );

    guide && confirm && cancel && inspect && confirm_back && review_back
}

fn test_fat32_lfn() -> bool {
    use signer_firmware_core::storage::fat32_lfn::{
        DirectoryEntryKind, LfnAccumulator, classify_directory_entry,
    };
    let mut raw = [0u8; 32];
    let end_ok = classify_directory_entry(&raw) == DirectoryEntryKind::End;
    raw[0] = b'A';
    raw[11] = 0x20;
    let regular_ok = classify_directory_entry(&raw) == DirectoryEntryKind::Regular;
    let mut accumulator = LfnAccumulator::new();
    let (display, length) = accumulator.display_name(b"README  TXT");
    end_ok && regular_ok && &display[..length] == b"README.TXT"
}

fn test_address_render_model() -> bool {
    use signer_firmware_core::presentation::render::{
        AddressRenderInput, CHANGE_CACHE_SIZE, RECEIVE_CACHE_SIZE, address_render_model,
    };
    let mut receive = [[0u8; 32]; RECEIVE_CACHE_SIZE];
    let change = [[0u8; 32]; CHANGE_CACHE_SIZE];
    receive[3] = [3; 32];
    let model = address_render_model(AddressRenderInput {
        receive_cache: &receive,
        change_cache: &change,
        extra_receive: [0; 32],
        extra_receive_index: 0,
        extra_change: [0; 32],
        extra_change_index: 0,
        current_index: 3,
        is_change: false,
        raw_key: false,
        partial_redraw: true,
    });
    matches!(model, Some(model) if model.public_key == [3; 32] && model.index == Some(3) && model.partial_update)
}
