use crate::runtime::input::AppState;

use super::AdvancedToolsContext;

const SECRET: &[u8] = b"offline secret";
const SALT: [u8; 8] = [0x42; 8];

pub(super) fn exercise(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    let commit_ok = commit_secret(ctx);
    let decrypt_ok = if commit_ok { decrypt_secret(ctx) } else { false };
    let caller_ok = caller_return_owners(ctx);
    commit_ok && decrypt_ok && caller_ok
}

fn commit_secret(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !commit_secret_preview(ctx) || !commit_secret_encrypt(ctx) || !commit_secret_qr(ctx) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED COMMIT-SECRET EMPTY/LENGTH/PREVIEW/ENCRYPT/QR PASS");
    true
}

fn commit_secret_preview(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad)
        || !ctx.open_advanced_item(3, AppState::CommitRevealType)
    {
        return false;
    }
    if crate::runtime::interactions::tx::workflow_store_commit_secret(ctx.ad, b"").is_ok()
        || crate::runtime::interactions::tx::workflow_store_commit_secret(ctx.ad, &[b'x'; 34]).is_ok()
        || ctx.ad.navigation.app.state != AppState::CommitRevealType
    {
        return false;
    }
    if crate::runtime::interactions::tx::workflow_store_commit_secret(ctx.ad, SECRET).is_err()
        || ctx.ad.navigation.app.state != AppState::CommitRevealPreview
        || ctx.ad.signing.commit_reveal.plaintext_len != SECRET.len() + SALT.len()
        || ctx.ad.signing.commit_reveal.plaintext[..8] != SALT
    {
        return false;
    }
    ctx.tx_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::CommitRevealType
}

fn commit_secret_encrypt(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::runtime::interactions::tx::workflow_store_commit_secret(ctx.ad, SECRET).is_ok()
        && crate::runtime::interactions::tx::workflow_encrypt_commit_secret(ctx.ad).is_ok()
        && ctx.ad.navigation.app.state == AppState::CommitRevealResult
        && !ctx.ad.signing.commit_reveal.ciphertext.is_empty()
        && ctx.ad.signing.commit_reveal.plaintext_len == 0
}

fn commit_secret_qr(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(160, 168, false) == Some(false)
        && ctx.ad.navigation.app.state == AppState::CommitRevealResultQr
        && ctx.tx_touch(160, 120, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::CommitRevealResult
}

fn decrypt_secret(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    let ciphertext = ctx.ad.signing.commit_reveal.ciphertext.clone();
    if !begin_decrypt_and_reject_malformed(ctx) {
        return false;
    }
    let mut hex = [0u8; 300];
    let Some(hex_len) = encode_hex(&ciphertext, &mut hex) else { return false; };
    if !decrypt_valid_payload(ctx, &hex[..hex_len])
        || !decrypt_result_navigation(ctx)
        || !wrong_recipient_rejects(ctx, &hex[..hex_len])
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED DECRYPT-SECRET MALFORMED/WRONG-KEY/ROUND-TRIP/QR PASS");
    true
}

fn begin_decrypt_and_reject_malformed(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if ctx.tx_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::WalletAdvancedMenu
        || !ctx.open_advanced_item(4, AppState::DecryptSecretScan)
    {
        return false;
    }
    crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        b"not-hex", ctx.ad,
    ) && ctx.ad.navigation.app.state == AppState::DecryptSecretScan
}

fn decrypt_valid_payload(ctx: &mut AdvancedToolsContext<'_, '_, '_>, ciphertext_hex: &[u8]) -> bool {
    let expected_len = SALT.len() + SECRET.len();
    crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        ciphertext_hex, ctx.ad,
    ) && ctx.ad.navigation.app.state == AppState::DecryptSecretResult
        && ctx.ad.signing.commit_reveal.plaintext_len == expected_len
        && ctx.ad.signing.commit_reveal.plaintext[..8] == SALT
        && &ctx.ad.signing.commit_reveal.plaintext[8..expected_len] == SECRET
}

fn decrypt_result_navigation(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    ctx.tx_touch(160, 168, false) == Some(false)
        && ctx.ad.navigation.app.state == AppState::DecryptSecretResultQr
        && ctx.tx_touch(160, 120, false) == Some(true)
        && ctx.ad.navigation.app.state == AppState::DecryptSecretResult
        && ctx.tx_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::WalletAdvancedMenu
        && ctx.ad.signing.commit_reveal.plaintext_len == 0
}

fn wrong_recipient_rejects(ctx: &mut AdvancedToolsContext<'_, '_, '_>, ciphertext_hex: &[u8]) -> bool {
    if !crate::services::wallet_session::install_workflow_wallet_inventory_fixture(ctx.ad)
        || !ctx.open_advanced_item(4, AppState::DecryptSecretScan)
    {
        return false;
    }
    crate::runtime::interactions::camera_loop::workflow_process_pending_payload(
        ciphertext_hex, ctx.ad,
    ) && ctx.ad.navigation.app.state == AppState::DecryptSecretScan
}

fn caller_return_owners(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        return false;
    }
    if !single_sig_tool(ctx, 3, AppState::CommitRevealType) {
        return false;
    }
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SingleSigMenu));
    ctx.ad.navigation.single_sig_menu.reset();
    if ctx.menu_touch(ctx.down.x + 20, ctx.down.y + 20, false) != Some(true)
        || ctx.ad.navigation.single_sig_menu.scroll != 4
    {
        return false;
    }
    let zone = ctx.list[0];
    if ctx.menu_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::DecryptSecretScan
        || ctx.tx_touch(20, 20, true) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SingleSigMenu
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED SECRET-TOOLS SINGLE-SIG PAGING/RETURN-OWNER PASS");
    true
}

fn single_sig_tool(
    ctx: &mut AdvancedToolsContext<'_, '_, '_>,
    item: usize,
    expected: AppState,
) -> bool {
    crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SingleSigMenu));
    ctx.ad.navigation.single_sig_menu.reset();
    let zone = ctx.list[item];
    ctx.menu_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) == Some(true)
        && ctx.ad.navigation.app.state == expected
        && ctx.tx_touch(20, 20, true) == Some(true)
        && ctx.ad.navigation.app.state == AppState::SingleSigMenu
}

fn encode_hex(input: &[u8], output: &mut [u8]) -> Option<usize> {
    if input.len().checked_mul(2)? > output.len() {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in input.iter().copied().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    Some(input.len() * 2)
}
