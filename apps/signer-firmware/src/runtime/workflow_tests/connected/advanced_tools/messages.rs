use crate::runtime::input::AppState;

use super::AdvancedToolsContext;

const KEY_OK: (u16, u16) = (295, 210);
const MESSAGE: &[u8] = b"KasSigner workflow message";

pub(super) fn exercise(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        return false;
    }
    let typed_ok = choice_and_typed(ctx);
    let qr_ok = qr_source(ctx);
    let sd_ok = sd_source(ctx);
    let sign_ok = sign_and_result(ctx);
    let owner_ok = single_sig_return_owner(ctx);
    typed_ok && qr_ok && sd_ok && sign_ok && owner_ok
}

fn open_choice(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    ctx.open_advanced_item(2, AppState::SignMsgChoice)
}

fn choice_and_typed(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !open_choice(ctx)
        || ctx.tx_touch(310, 100, false) != Some(false)
        || ctx.ad.navigation.app.state != AppState::SignMsgChoice
        || ctx.tx_touch(160, 90, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgType
    {
        return false;
    }
    ctx.ad.wallet.seeds.pp_input.reset();
    if ctx.tx_touch(KEY_OK.0, KEY_OK.1, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgType
    {
        return false;
    }
    ctx.set_text(MESSAGE);
    if ctx.tx_touch(KEY_OK.0, KEY_OK.1, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgPreview
        || &ctx.ad.signing.message.payload[..ctx.ad.signing.message.payload_len] != MESSAGE
    {
        return false;
    }
    if ctx.tx_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::SignMsgChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SIGN-MESSAGE TYPED EMPTY-REJECT/PREVIEW/BACK PASS");
    true
}

fn qr_source(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !open_choice(ctx) { return false; }
    if ctx.tx_touch(160, 136, false) != Some(true) || ctx.ad.navigation.app.state != AppState::SignMsgScan {
        return false;
    }
    if !crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        b"", ctx.ad,
    ) || ctx.ad.navigation.app.state != AppState::SignMsgScan {
        return false;
    }
    if !crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        b"bad\x01", ctx.ad,
    ) || ctx.ad.navigation.app.state != AppState::SignMsgScan {
        return false;
    }
    let oversized = [b'x'; 1_025];
    if !crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        &oversized, ctx.ad,
    ) || ctx.ad.navigation.app.state != AppState::SignMsgScan {
        return false;
    }
    if !crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        MESSAGE, ctx.ad,
    ) || ctx.ad.navigation.app.state != AppState::SignMsgPreview {
        return false;
    }
    if ctx.tx_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::SignMsgChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SIGN-MESSAGE QR EMPTY/CONTROL/OVERSIZE/VALID PASS");
    true
}

fn sd_source(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SignMsgFile));
    if crate::runtime::interactions::tx::workflow_accept_message_file(ctx.ad, b"").is_ok()
        || crate::runtime::interactions::tx::workflow_accept_message_file(ctx.ad, b"bad\x01").is_ok()
    {
        return false;
    }
    let oversized = [b'x'; 1_025];
    if crate::runtime::interactions::tx::workflow_accept_message_file(ctx.ad, &oversized).is_ok()
        || crate::runtime::interactions::tx::workflow_accept_message_file(ctx.ad, MESSAGE).is_err()
        || ctx.ad.navigation.app.state != AppState::SignMsgPreview
    {
        return false;
    }
    if ctx.tx_touch(20, 20, true) != Some(true) || ctx.ad.navigation.app.state != AppState::SignMsgChoice {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SIGN-MESSAGE SD CONTENT BOUNDARIES/PREVIEW PASS");
    true
}

fn sign_and_result(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SignMsgType));
    ctx.set_text(MESSAGE);
    if ctx.tx_touch(KEY_OK.0, KEY_OK.1, false) != Some(true)
        || !crate::runtime::interactions::tx::workflow_sign_message_preview(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::SignMsgResult
        || ctx.ad.signing.message.signature.iter().all(|byte| *byte == 0)
        || ctx.ad.signing.message.hash != offline_signer::crypto::message::message_digest(MESSAGE)
    {
        return false;
    }
    // Exercise the production no-card branch deterministically. The board may
    // have a physical QA card inserted, but controller E2E must not mutate it.
    if ctx.tx_touch_without_sd(90, 170, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgResult
    {
        return false;
    }
    if ctx.tx_touch(235, 170, false) != Some(false)
        || ctx.ad.navigation.app.state != AppState::SignMsgResultQr
        || ctx.tx_touch(160, 120, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgResult
        || ctx.tx_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::WalletAdvancedMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SIGN-MESSAGE SIGN/RESULT-QR/NO-SD/BACK PASS");
    true
}

fn single_sig_return_owner(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SingleSigMenu));
    ctx.ad.navigation.single_sig_menu.reset();
    let zone = ctx.list[1];
    if crate::runtime::interactions::menu::handle_signing_feedback_touch(
        ctx.ad,
        ctx.display,
        ctx.delay,
        &mut || {},
        &ctx.list,
        crate::runtime::interactions::TouchInput::new(zone.x + zone.w / 2, zone.y + zone.h / 2, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SignMsgChoice
        || ctx.tx_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SingleSigMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SIGN-MESSAGE CALLER RETURN-OWNER PASS");
    true
}
