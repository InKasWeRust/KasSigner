//! Connected probes for production surfaces that were still catalog-only before connected coverage was added.
//!
//! Keep credit conservative: these probes execute real production parsers,
//! policy services, and navigation reducers, but physical flash/RTC/eFuse/SD
//! fault injection remains owned by the explicit HIL profile.

use crate::{
    runtime::interactions::TouchInput,
    hw::{display::BootDisplay, sdcard::SdCardType},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod firmware_update;

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: REMAINING PRODUCTION SURFACES BEGIN");
    let mut summary = super::remaining_status::ProbeSummary::new();
    summary.run("COVENANT-RESTORE", covenant_backup_forms);
    summary.run("COVENANT-SIGN", || covenant_signing_protocol(ad));
    summary.run("PRIVATE-SWAP", || private_swap_protocol(ad));
    summary.run("FIRMWARE-UPDATE", || firmware_update::exercise(ad));
    summary.run("MISSING-KEY", || missing_key_fail_closed(ad));
    summary.run("UNLOCK-GUARDS", || unlock_navigation_guards(ad));
    summary.run("DEVICE-BOUND-SD", || {
        device_bound_sd_routing(ad, display, i2c, sd, delay)
    });
    summary.run("FINISH-HOME", || finish(ad));
    summary.finish(8)
}

fn covenant_backup_forms() -> bool {
    use signer_firmware_core::qr::classification::{is_covenant_hex, is_covenant_raw};
    let forms = [
        (b"COVB0".as_slice(), b"434f564230".as_slice()),
        (b"COVI0".as_slice(), b"434f564930".as_slice()),
    ];
    let mut decoded = [0u8; 16];
    for (raw, hex) in forms {
        if !is_covenant_raw(raw) || !is_covenant_hex(hex) {
            return false;
        }
        let Ok(len) = signer_firmware_core::qr::classification::decode_hex(hex, &mut decoded) else {
            return false;
        };
        if &decoded[..len] != raw {
            return false;
        }
    }
    if is_covenant_raw(b"COVB") || is_covenant_hex(b"434f56GG") {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: COVENANT RESTORE RAW/HEX COVB/COVI BOUNDARIES PASS");
    true
}

fn covenant_signing_protocol(ad: &mut AppData) -> bool {
    use shared_signer::covenant_sign;
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: COVENANT SIGN MNEMONIC FIXTURE FAIL");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: COVENANT SIGN MNEMONIC FIXTURE READY");
    let mut request_wire = [0u8; 512];
    let mut reveal_wire = [0u8; covenant_sign::REVEAL_LEN];
    if !covenant_rejects_malformed(ad)
        || !covenant_opaque_round_trip(ad, &mut request_wire, &mut reveal_wire)
        || !covenant_known_round_trip(ad, &mut request_wire, &mut reveal_wire)
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: COVENANT SIGN KEYINFO/KNOWN/BINDKNOWN/OPAQUE/BINDOPAQUE/REVEAL PASS");
    true
}

fn covenant_rejects_malformed(ad: &mut AppData) -> bool {
    crate::services::covenant_sign::prepare_request(ad, b"CVSG", &mut || {}).is_err()
}

fn covenant_key_info(
    ad: &mut AppData,
    request_wire: &mut [u8; 512],
) -> Option<[u8; 32]> {
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, KnownScheme, RequestKind,
    };
    use crate::runtime::data::CovenantSigningMode;
    let request = CovenantSignRequest {
        kind: RequestKind::KeyInfo,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [0; wire::SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id: [0; 32],
        binding_token: [0; 32],
        commitment: [0; 32],
        script: &[],
        context: &[],
    };
    let len = wire::encode_request(&request, request_wire).ok()?;
    crate::services::covenant_sign::prepare_request(ad, &request_wire[..len], &mut || {}).ok()?;
    (ad.signing.covenant.mode == CovenantSigningMode::KeyInfo
        && ad.signing.covenant.response_len > 0)
        .then_some(ad.signing.covenant.pending_key_id)
}

fn covenant_bind_opaque(
    ad: &mut AppData,
    request_wire: &mut [u8; 512],
    key_id: [u8; 32],
    script: &[u8],
) -> Option<[u8; 32]> {
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, KnownScheme, RequestKind,
    };
    use crate::runtime::data::CovenantSigningMode;
    let request = CovenantSignRequest {
        kind: RequestKind::Bind,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [0; wire::SESSION_ID_LEN],
        host_commitment: [0; 32],
        key_id,
        binding_token: [0; 32],
        commitment: [0; 32],
        script,
        context: &[],
    };
    let len = wire::encode_request(&request, request_wire).ok()?;
    crate::services::covenant_sign::prepare_request(ad, &request_wire[..len], &mut || {}).ok()?;
    if ad.signing.covenant.mode != CovenantSigningMode::BindOpaque {
        return None;
    }
    crate::services::covenant_sign::complete_binding(ad, &mut || {}).ok()?;
    (ad.signing.covenant.binding_token != [0; 32]).then_some(ad.signing.covenant.binding_token)
}

fn covenant_opaque_round_trip(
    ad: &mut AppData,
    request_wire: &mut [u8; 512],
    reveal_wire: &mut [u8; shared_signer::covenant_sign::REVEAL_LEN],
) -> bool {
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, KnownScheme, RequestKind,
    };
    use crate::runtime::data::{CovenantSigningMode, CovenantSigningPhase};
    let Some(key_id) = covenant_key_info(ad, request_wire) else { return false; };
    let script = b"workflow opaque covenant";
    let Some(token) = covenant_bind_opaque(ad, request_wire, key_id, script) else { return false; };
    let host_secret = [0x39; 32];
    let session_id = [0x47; wire::SESSION_ID_LEN];
    let commitment = [0x51; 32];
    let request = CovenantSignRequest {
        kind: RequestKind::Opaque,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id,
        host_commitment: shared_signer::anti_klepto::host_commitment(&host_secret),
        key_id,
        binding_token: token,
        commitment,
        script,
        context: &[],
    };
    let Ok(len) = wire::encode_request(&request, request_wire) else { return false; };
    if crate::services::covenant_sign::prepare_request(ad, &request_wire[..len], &mut || {}).is_err()
        || ad.signing.covenant.mode != CovenantSigningMode::Opaque
        || crate::services::covenant_sign::begin_signing(ad, &mut || {}).is_err()
        || ad.signing.covenant.phase != CovenantSigningPhase::AwaitingReveal
    {
        return false;
    }
    covenant_reveal_matrix(ad, reveal_wire, session_id, key_id, commitment, host_secret)
}

fn covenant_reveal_matrix(
    ad: &mut AppData,
    reveal_wire: &mut [u8; shared_signer::covenant_sign::REVEAL_LEN],
    session_id: [u8; shared_signer::covenant_sign::SESSION_ID_LEN],
    key_id: [u8; 32],
    commitment: [u8; 32],
    host_secret: [u8; 32],
) -> bool {
    use shared_signer::covenant_sign::{self as wire, CovenantSignReveal};
    use crate::runtime::data::CovenantSigningPhase;
    if crate::services::covenant_sign::finalize_reveal(ad, b"CVRV", &mut || {}).is_ok()
        || ad.signing.covenant.phase != CovenantSigningPhase::AwaitingReveal
    {
        return false;
    }
    let wrong = CovenantSignReveal {
        session_id: [0x48; wire::SESSION_ID_LEN], key_id, commitment, host_secret,
    };
    if wire::encode_reveal(&wrong, reveal_wire).is_err()
        || crate::services::covenant_sign::finalize_reveal(ad, reveal_wire, &mut || {}).is_ok()
        || ad.signing.covenant.phase != CovenantSigningPhase::AwaitingReveal
    {
        return false;
    }
    let valid = CovenantSignReveal { session_id, key_id, commitment, host_secret };
    wire::encode_reveal(&valid, reveal_wire).is_ok()
        && crate::services::covenant_sign::finalize_reveal(ad, reveal_wire, &mut || {}).is_ok()
        && ad.signing.covenant.phase == CovenantSigningPhase::FinalResponse
        && ad.signing.covenant.response_len > 0
}

fn covenant_known_round_trip(
    ad: &mut AppData,
    request_wire: &mut [u8; 512],
    reveal_wire: &mut [u8; shared_signer::covenant_sign::REVEAL_LEN],
) -> bool {
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, CovenantSignReveal, KnownScheme, RequestKind,
    };
    use crate::runtime::data::{CovenantSigningMode, CovenantSigningPhase};
    let Some((key_id, commitment, script, token)) = prepare_known_covenant_binding(ad, request_wire) else {
        return false;
    };
    let context = b"workflow known covenant";
    let host_secret = [0x71; 32];
    let host_commitment = shared_signer::anti_klepto::host_commitment(&host_secret);
    let session_id = [0x72; wire::SESSION_ID_LEN];
    let known = CovenantSignRequest {
        kind: RequestKind::Known, scheme: KnownScheme::Sha256Preimage,
        binding: BindingHint::FixedCheckSigFromStack, session_id, host_commitment,
        key_id, binding_token: token, commitment, script: &script, context,
    };
    let Ok(known_len) = wire::encode_request(&known, request_wire) else { return false; };
    if crate::services::covenant_sign::prepare_request(ad, &request_wire[..known_len], &mut || {}).is_err()
        || ad.signing.covenant.mode != CovenantSigningMode::Known
        || crate::services::covenant_sign::begin_signing(ad, &mut || {}).is_err()
    { return false; }
    let reveal = CovenantSignReveal { session_id, key_id, commitment, host_secret };
    wire::encode_reveal(&reveal, reveal_wire).is_ok()
        && crate::services::covenant_sign::finalize_reveal(ad, reveal_wire, &mut || {}).is_ok()
        && ad.signing.covenant.phase == CovenantSigningPhase::FinalResponse
}

fn prepare_known_covenant_binding(ad: &mut AppData, request_wire: &mut [u8; 512])
    -> Option<([u8; 32], [u8; 32], [u8; 67], [u8; 32])> {
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, KnownScheme, RequestKind,
    };
    use crate::runtime::data::CovenantSigningMode;
    let key_info = CovenantSignRequest {
        kind: RequestKind::KeyInfo, scheme: KnownScheme::None, binding: BindingHint::None,
        session_id: [0; wire::SESSION_ID_LEN], host_commitment: [0; 32], key_id: [0; 32],
        binding_token: [0; 32], commitment: [0; 32], script: &[], context: &[],
    };
    let Ok(key_len) = wire::encode_request(&key_info, request_wire) else { return None; };
    if crate::services::covenant_sign::prepare_request(ad, &request_wire[..key_len], &mut || {}).is_err() { return None; }
    let key_id = ad.signing.covenant.pending_key_id;
    let pubkey = ad.signing.covenant.pending_pubkey_x;
    let context = b"workflow known covenant";
    let Some(commitment) = wire::recompute_known_commitment(KnownScheme::Sha256Preimage, context) else { return None; };
    let mut script = [0u8; 67];
    script[0] = 0x20;
    script[1..33].copy_from_slice(&commitment);
    script[33] = 0x20;
    script[34..66].copy_from_slice(&pubkey);
    script[66] = 0xd7;
    let bind = CovenantSignRequest {
        kind: RequestKind::Bind, scheme: KnownScheme::Sha256Preimage,
        binding: BindingHint::FixedCheckSigFromStack, session_id: [0; wire::SESSION_ID_LEN],
        host_commitment: [0; 32], key_id, binding_token: [0; 32], commitment,
        script: &script, context,
    };
    let Ok(bind_len) = wire::encode_request(&bind, request_wire) else { return None; };
    if crate::services::covenant_sign::prepare_request(ad, &request_wire[..bind_len], &mut || {}).is_err()
        || ad.signing.covenant.mode != CovenantSigningMode::BindKnown
        || crate::services::covenant_sign::complete_binding(ad, &mut || {}).is_err()
    { return None; }
    let token = ad.signing.covenant.binding_token;
    Some((key_id, commitment, script, token))
}

fn private_swap_protocol(ad: &mut AppData) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: PRIVATE SWAP MNEMONIC FIXTURE FAIL");
        return false;
    }
    use shared_signer::covenant_sign::private_swap::{
        self as wire, PrivateSwapRequest, RequestKind,
    };
    if crate::services::private_swap::prepare_request(ad, b"PSWG", &mut || {}).is_ok() {
        return false;
    }
    let requests = [
        PrivateSwapRequest {
            kind: RequestKind::KeyInfo, session_id: [0; 16], host_commitment: [0; 32],
            key_id: [0; 32], binding_token: [0; 32], adaptor_point: [0; 32],
            presignature: [0; 64], presignature_negated: false, payload: &[],
        },
        PrivateSwapRequest {
            kind: RequestKind::Bind, session_id: [0; 16], host_commitment: [0; 32],
            key_id: [2; 32], binding_token: [0; 32], adaptor_point: [3; 32],
            presignature: [0; 64], presignature_negated: false, payload: b"swap-script",
        },
    ];
    let mut encoded = [0u8; 320];
    for (index, request) in requests.into_iter().enumerate() {
        let Ok(len) = wire::encode_request(&request, &mut encoded) else { return false; };
        let Ok(parsed) = wire::parse_request(&encoded[..len]) else { return false; };
        if parsed.kind != request.kind { return false; }
        if index == 0 && (crate::services::private_swap::prepare_request(ad, &encoded[..len], &mut || {}).is_err()
            || ad.signing.private_swap.response_len == 0)
        {
            return false;
        }
    }
    let mut malformed = encoded;
    malformed[0] ^= 1;
    if wire::parse_request(&malformed).is_ok() { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: PRIVATE SWAP KEYINFO/BIND WIRE + MALFORMED REJECT PASS");
    true
}

fn missing_key_fail_closed(ad: &mut AppData) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ad) {
        return false;
    }
    use shared_signer::covenant_sign::{
        self as wire, BindingHint, CovenantSignRequest, KnownScheme, RequestKind,
    };
    let old_active = ad.wallet.seeds.seed_mgr.active;
    ad.wallet.seeds.seed_mgr.clear_active();
    let request = CovenantSignRequest {
        kind: RequestKind::Opaque,
        scheme: KnownScheme::None,
        binding: BindingHint::None,
        session_id: [1; wire::SESSION_ID_LEN],
        host_commitment: [2; 32],
        key_id: [3; 32],
        binding_token: [4; 32],
        commitment: [5; 32],
        script: b"missing-key-probe",
        context: &[],
    };
    let mut encoded = [0u8; 256];
    let Ok(len) = wire::encode_request(&request, &mut encoded) else { return false; };
    let missing = crate::services::covenant_sign::prepare_request(ad, &encoded[..len], &mut || {})
        == Err(crate::services::covenant_sign::CovenantSignError::MnemonicRequired);
    let restored = old_active == u8::MAX || ad.wallet.seeds.seed_mgr.set_active(usize::from(old_active));
    if !missing || !restored { return false; }

    let Some(expected_raw_slot) = ad.wallet.seeds.seed_mgr.find_free() else { return false; };
    let Some(raw_slot) = ad.wallet.seeds.seed_mgr.store_raw_key(&[7u8; 32]) else { return false; };
    if raw_slot != expected_raw_slot || !ad.wallet.seeds.seed_mgr.set_active(raw_slot) {
        if old_active != u8::MAX {
            let _ = ad.wallet.seeds.seed_mgr.set_active(usize::from(old_active));
        }
        return false;
    }
    let raw_rejected = crate::services::covenant_sign::prepare_request(ad, &encoded[..len], &mut || {})
        == Err(crate::services::covenant_sign::CovenantSignError::MnemonicRequired);
    ad.wallet.seeds.seed_mgr.delete(raw_slot);
    let restored = old_active == u8::MAX || ad.wallet.seeds.seed_mgr.set_active(usize::from(old_active));
    if !raw_rejected || !restored { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: MISSING MNEMONIC/RAW-HD SIGNING FAIL-CLOSED PASS");
    true
}

fn unlock_navigation_guards(ad: &mut AppData) -> bool {
    if !crate::runtime::interactions::persistence::workflow_unlock_back_guard(AppState::StorageUnlockPin)
        || !crate::runtime::interactions::persistence::workflow_unlock_back_guard(AppState::StorageUnlockPassword)
    {
        return false;
    }
    let pin_home_hidden = crate::runtime::navigation::workflow_home_shortcut_hidden_for_unlock(
        AppState::StorageUnlockPin,
    );
    let password_home_hidden = crate::runtime::navigation::workflow_home_shortcut_hidden_for_unlock(
        AppState::StorageUnlockPassword,
    );
    let backoff = crate::runtime::interactions::persistence::workflow_unlock_backoff_probe(ad);
    if !pin_home_hidden || !password_home_hidden || !backoff { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: UNLOCK BACK/HOME GUARDS + RETRY BACKOFF PASS");
    true
}

fn device_bound_sd_routing(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    use crate::ui::screens::device::advanced_security::{ADV_CARD_X, SD_STORAGE_Y};
    crate::runtime::effects::home(ad);
    let settings_zone = crate::ui::layout::HOME_GRID_ZONES[3];
    if !crate::runtime::interactions::menu::handle_root_touch(
        ad, settings_zone.x + settings_zone.w / 2, settings_zone.y + settings_zone.h / 2,
    ) || ad.navigation.app.state != AppState::SettingsMenu {
        return false;
    }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let security = list[2];
    if crate::runtime::interactions::settings::handle_settings_menu_navigation(
        ad, &list, &up, &down,
        TouchInput::new(security.x + security.w / 2, security.y + security.h / 2, false),
    ) != Some(true) || ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    crate::runtime::interactions::settings::advanced::workflow::install_saved_wallet_fixture(
        ad, crate::services::credential_policy::CredentialKind::Pin,
    );
    let x = *ADV_CARD_X.start() + 8;
    let y = *SD_STORAGE_Y.start() + 8;
    if crate::runtime::interactions::settings::advanced::workflow::open_card(
        TouchInput::new(x, y, false), ad, display, delay,
    ) != Some(true) || ad.navigation.app.state != AppState::StorageRecoveryAcknowledgement {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
        TouchInput::new(20, 20, true), ad, display, delay,
    ) != Some(true) || ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    if crate::runtime::interactions::settings::advanced::workflow::open_card(
        TouchInput::new(x, y, false), ad, display, delay,
    ) != Some(true)
        || crate::runtime::interactions::persistence::workflow_handle_recovery_acknowledgement(
            TouchInput::new(160, 188, false), ad, display, delay,
        ) != Some(true)
        || ad.navigation.app.state != AppState::AdvancedSdStorageWarning
    {
        return false;
    }
    if crate::runtime::interactions::settings::advanced::handle_pure(TouchInput::new(20, 20, true), ad) != Some(true)
        || ad.navigation.app.state != AppState::AdvancedFeatures
    {
        return false;
    }
    super::redraw_step(ad, display, i2c, sd);
    log!("KASSIGNER_WORKFLOW_TESTS: DEVICE-BOUND SD SETUP/ACK/CANCEL ROUTING PASS");
    true
}

fn finish(ad: &mut AppData) -> bool {
    crate::runtime::effects::home(ad);
    let ok = super::root::home_ok(ad);
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: REMAINING PRODUCTION SURFACES PASS"); }
    ok
}
