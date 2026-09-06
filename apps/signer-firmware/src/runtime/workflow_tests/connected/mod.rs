//! Connected CoreS3 production-controller E2E scenarios.
//!
//! Keep scenarios restartable and focused. This layer may install explicit
//! public/test fixtures, but it must route through production controller and
//! navigation facades rather than mutating navigation state directly.

mod advanced_tools;
mod backup;
mod onboarding;
mod receive;
mod remaining;
mod remaining_status;
mod qr_protocol;
mod probe_status;
mod root;
mod settings;
mod multisig;
mod signing;
mod sd_workflows;
#[cfg(feature = "m5stack")]
mod sd_media;
mod stego;
mod security_policies;
mod wallet;
#[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
mod runtime_gui;

#[cfg(feature = "workflow-test-auto")]
const _: () = {
    let _ = crate::runtime::interactions::tx::load_standard_transaction;
    let _ = crate::runtime::signing::derive_active_account_key;
    let _ = crate::runtime::signing::derive_active_seed;
};

#[cfg(feature = "workflow-runtime-auto")]
const SCREEN_DWELL_MS: u32 = 350;

/// Connected E2E is a production-controller/state-machine test, not a display
/// burn-in test. Repeated physical redraws are reserved for workflow HIL so
/// the normal connected suite cannot corrupt/stall the shared CoreS3 SPI/LCD
/// path while rapidly traversing hundreds of states.
pub(super) fn redraw_step(
    ad: &mut crate::runtime::data::AppData,
    display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd: &Option<crate::hw::sdcard::SdCardType>,
) {
    #[cfg(feature = "workflow-runtime-auto")]
    crate::ui::redraw::redraw_screen(ad, display, i2c, sd);

    #[cfg(not(feature = "workflow-runtime-auto"))]
    {
        let _ = ad;
        let _ = display;
        let _ = i2c;
        let _ = sd;
    }
}

pub(super) fn show_step(delay: &mut esp_hal::delay::Delay) {
    #[cfg(feature = "workflow-runtime-auto")]
    delay.delay_millis(SCREEN_DWELL_MS);

    #[cfg(not(feature = "workflow-runtime-auto"))]
    let _ = delay;
}

type ConnectedTranche = for<'display, 'hal> fn(
    &mut crate::runtime::data::AppData,
    &mut crate::hw::display::BootDisplay<'display>,
    &mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    &Option<crate::hw::sdcard::SdCardType>,
    &mut esp_hal::delay::Delay,
) -> bool;

const CONNECTED_TRANCHES: [(&str, ConnectedTranche); 11] = [
    ("ROOT", root::exercise),
    ("REMAINING", remaining::exercise),
    ("ONBOARDING", onboarding::exercise),
    ("SIGNING", signing::exercise),
    ("QR-PROTOCOL", qr_protocol::exercise),
    ("SD-WORKFLOWS", sd_workflows::exercise),
    ("MULTISIG", multisig::exercise),
    ("STEGO", stego::exercise),
    ("SECURITY-POLICIES", security_policies::exercise),
    ("ADVANCED-TOOLS", advanced_tools::exercise),
    ("RECEIVE", receive::exercise),
];

#[inline(never)]
pub(super) fn run(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::hw::sdcard::SdCardType>,
    delay: &mut esp_hal::delay::Delay,
    dvp_camera_opt: &mut Option<esp_hal::lcd_cam::cam::Camera<'_>>,
    cam_dma_buf_opt: &mut Option<esp_hal::dma::DmaRxBuf>,
    cam_status: &mut crate::hw::camera::CameraStatus,
    persistent_wallet: &mut crate::services::persistent_wallet::PersistentWallet<'_>,
    watchdog_feed: &mut impl FnMut(),
) -> bool {
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED BUILD PACKAGE {}",
        env!("CARGO_PKG_VERSION"),
    );
    #[cfg(feature = "m5stack")]
    log!("KASSIGNER_WORKFLOW_TESTS: TOUCH PROBE BEGIN");
    #[cfg(feature = "m5stack")]
    if !crate::hw::touch::probe(i2c) {
        log!("KASSIGNER_WORKFLOW_TESTS: TOUCH PROBE FAIL");
        return false;
    }
    #[cfg(feature = "m5stack")]
    log!("KASSIGNER_WORKFLOW_TESTS: TOUCH PROBE OK");

    #[cfg(all(feature = "m5stack", feature = "workflow-hil-auto"))]
    if !sd_media::prepare_and_verify(i2c, sd_card_type, delay) {
        return false;
    }
    #[cfg(all(feature = "m5stack", not(feature = "workflow-hil-auto")))]
    if !sd_media::prepare_controller_e2e(sd_card_type) {
        return false;
    }
    // Plain integration builds compile neither the M5Stack SD probe nor the
    // workflow-HIL media path. Keep the uniform connected-runner signature
    // while making that single profile's intentionally unused handle explicit.
    #[cfg(all(not(feature = "m5stack"), not(feature = "workflow-hil-auto")))]
    let _ = sd_card_type;

    #[cfg(not(all(feature = "m5stack", feature = "workflow-runtime-auto")))]
    {
        let _ = dvp_camera_opt;
        let _ = cam_dma_buf_opt;
        let _ = cam_status;
    }

    #[cfg(not(feature = "workflow-runtime-auto"))]
    {
        crate::runtime::signing::install_workflow_receive_fixture(ad);
        log!("KASSIGNER_WORKFLOW_TESTS: RECEIVE PUBLIC FIXTURE READY");
    }
    #[cfg(feature = "workflow-runtime-auto")]
    log!("KASSIGNER_WORKFLOW_RUNTIME: RECEIVE PUBLIC FIXTURE DISABLED; REAL DERIVATION REQUIRED");

    #[cfg(feature = "workflow-hil-auto")]
    if !hil_entropy_probe() { return false; }

    // Controller E2E is intentionally media-independent.  Keep the real boot
    // probe above for hardware diagnostics, but do not let an inserted, flaky,
    // or half-initialized card redirect controller-only tests into physical I/O.
    // workflow-hil-auto keeps the real media handle and remains the authority
    // for scans, read/write/delete, format, lock recovery, and other SD HIL.
    #[cfg(feature = "workflow-hil-auto")]
    let controller_sd = sd_card_type;
    #[cfg(not(feature = "workflow-hil-auto"))]
    let no_controller_sd = None;
    #[cfg(not(feature = "workflow-hil-auto"))]
    let controller_sd = &no_controller_sd;
    #[cfg(not(feature = "workflow-hil-auto"))]
    log!("KASSIGNER_WORKFLOW_TESTS: CONTROLLER SD VIEW FORCED UNAVAILABLE; PHYSICAL SD REMAINS HIL-ONLY");

    if !run_all_connected_tranches(ad, boot_display, i2c, controller_sd, delay) {
        return false;
    }

    // Runtime-HIL deliberately arms the real production CoreS3 watchdog only
    // after the controller catalog has completed. The final probes then execute
    // real LCD/camera/derivation/KDF paths under the same 30-second watchdog
    // budget as production, without making destructive SD/eFuse changes.
    #[cfg(all(feature = "m5stack", feature = "workflow-runtime-auto"))]
    if !runtime_gui::exercise(
        ad, boot_display, i2c, sd_card_type, delay,
        dvp_camera_opt, cam_dma_buf_opt, cam_status, persistent_wallet, watchdog_feed,
    ) {
        return false;
    }
    #[cfg(not(all(feature = "m5stack", feature = "workflow-runtime-auto")))]
    {
        let _ = persistent_wallet;
        let _ = watchdog_feed;
    }

    true
}

fn run_all_connected_tranches(
    ad: &mut crate::runtime::data::AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    sd_card_type: &Option<crate::hw::sdcard::SdCardType>,
    delay: &mut esp_hal::delay::Delay,
) -> bool {
    let start_index = configured_start_index();
    let attempted = CONNECTED_TRANCHES.len().saturating_sub(start_index);
    if start_index > 0 {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: CONNECTED RESUME FROM {}/{} {}",
            start_index + 1,
            CONNECTED_TRANCHES.len(),
            CONNECTED_TRANCHES[start_index].0,
        );
    }
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut failed_tranches = [false; CONNECTED_TRANCHES.len()];
    let mut multisig_failure_snapshot = None;
    for (index, (name, tranche)) in CONNECTED_TRANCHES.iter().enumerate().skip(start_index) {
        if !reset_tranche_to_home(ad) {
            failed += 1;
            failed_tranches[index] = true;
            log!(
                "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {}/{} {} RESET FAILED; CONTINUING",
                index + 1,
                CONNECTED_TRANCHES.len(),
                name,
            );
            continue;
        }
        // Host supervision treats this as a per-tranche liveness checkpoint.
        // The full connected suite contains intentionally expensive embedded
        // cryptography; one global deadline must not expire merely because
        // earlier independent tranches legitimately consumed CPU time.
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE DEADLINE REFRESH");
        log!(
            "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {}/{} {} BEGIN",
            index + 1,
            CONNECTED_TRANCHES.len(),
            name,
        );
        let result = tranche(ad, boot_display, i2c, sd_card_type, delay);
        if result {
            passed += 1;
            log!(
                "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {}/{} {} PASS",
                index + 1,
                CONNECTED_TRANCHES.len(),
                name,
            );
        } else {
            failed += 1;
            failed_tranches[index] = true;
            log!(
                "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {}/{} {} FAILED; CONTINUING",
                index + 1,
                CONNECTED_TRANCHES.len(),
                name,
            );
            if index == 6 {
                let snapshot = multisig::snapshot_failures();
                multisig::replay_snapshot(snapshot);
                multisig_failure_snapshot = Some(snapshot);
            }
            if !reset_tranche_to_home(ad) {
                log!(
                    "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE {}/{} {} POST-FAIL RESET FAILED",
                    index + 1,
                    CONNECTED_TRANCHES.len(),
                    name,
                );
            }
        }
    }
    log!(
        "KASSIGNER_WORKFLOW_TESTS: CONNECTED TRANCHE SUMMARY attempted={} passed={} failed={}",
        attempted,
        passed,
        failed,
    );
    if failed != 0 {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILURE DETAILS BEGIN");
    }
    for (index, failed_tranche) in failed_tranches.iter().enumerate().skip(start_index) {
        if *failed_tranche {
            log!(
                "KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILED TRANCHE {}/{} {}",
                index + 1,
                CONNECTED_TRANCHES.len(),
                CONNECTED_TRANCHES[index].0,
            );
            match index {
                0 => {
                    probe_status::replay_mask(
                        "ROOT", &root::FAILURE_MASK, &["RECEIVE", "SCAN", "WALLET-BACKUP", "SETTINGS"],
                    );
                    if root::FAILURE_MASK.load(core::sync::atomic::Ordering::Relaxed) & (1u16 << 2) != 0 {
                        probe_status::replay_mask(
                            "ROOT-WALLET-BACKUP", &root::WALLET_BACKUP_FAILURE_MASK, &["WALLET", "BACKUP"],
                        );
                        if root::WALLET_BACKUP_FAILURE_MASK.load(core::sync::atomic::Ordering::Relaxed) & 1 != 0 {
                            wallet::replay_failure_detail();
                        }
                    }
                },
                2 => probe_status::replay_mask(
                    "ONBOARDING", &onboarding::FAILURE_MASK,
                    &["WELCOME", "CREATE-12", "CREATE-24", "CREDENTIAL-ROUTES", "FINISH-SESSION", "RESTORE-IMPORT"],
                ),
                3 => {
                    probe_status::replay_mask(
                        "SIGNING", &signing::FAILURE_MASK,
                        &["INVALID-KSPT", "COMPACT-REVIEW", "COMPACT-SIGN", "STANDARD-PSKT", "ANTI-KLEPTO", "FINISH-HOME"],
                    );
                    signing::replay_standard_failure_detail();
                },
                5 => {
                    probe_status::replay_mask(
                        "SD-WORKFLOWS", &sd_workflows::FAILURE_MASK,
                        &["BROWSER", "IMPORTS", "ENCRYPTED", "FINISH-HOME"],
                    );
                    sd_workflows::replay_import_failure_detail();
                },
                _ => {}
            }
            if index == 6 {
                if let Some(snapshot) = multisig_failure_snapshot {
                    multisig::replay_snapshot(snapshot);
                } else {
                    multisig::replay_failures();
                }
            }
        }
    }
    if failed != 0 {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILURE DETAILS END");
    }
    failed == 0 && passed == attempted
}


fn reset_tranche_to_home(ad: &mut crate::runtime::data::AppData) -> bool {
    let reset = crate::runtime::navigation::workflow_reset_to_home(ad);
    if !reset {
        log!(
            "KASSIGNER_WORKFLOW_TESTS: CONNECTED RESET HOME FAIL state={:?} committed={:?} owner={:?} intent={:?} operation={:?}",
            ad.navigation.app.state,
            ad.navigation.committed_state,
            ad.navigation.owner,
            ad.storage.persistence.device_storage_intent,
            crate::runtime::presentation::operation_kind(ad),
        );
    }
    reset
}

fn configured_start_index() -> usize {
    match env!("KASSIGNER_WORKFLOW_E2E_FROM") {
        "2" => 1,
        "3" => 2,
        "4" => 3,
        "5" => 4,
        "6" => 5,
        "7" => 6,
        "8" => 7,
        "9" => 8,
        "10" => 9,
        "11" => 10,
        _ => 0,
    }
}


#[cfg(feature = "workflow-hil-auto")]
fn hil_entropy_probe() -> bool {
    let mut sample = [0u8; 64];
    if crate::crypto::entropy::fill(&mut sample).is_err() || sample == [0u8; 64] {
        log!("KASSIGNER_WORKFLOW_HIL: RNG/IMU ENTROPY PROBE FAIL");
        return false;
    }
    shared_signer::bytes::zeroize_bytes(&mut sample);
    log!("KASSIGNER_WORKFLOW_HIL: RNG/IMU ENTROPY PROBE OK");
    true
}
