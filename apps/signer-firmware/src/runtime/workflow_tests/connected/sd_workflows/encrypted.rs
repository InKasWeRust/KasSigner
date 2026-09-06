use super::SdWorkflowContext;
use crate::runtime::{data::{EncryptedFileOperation, PendingStorageAction}, input::AppState};
use offline_signer::crypto::device_bound_storage::NONCE_SIZE;
use crate::services::credential_policy::SALT_SIZE;

const PASSWORD: &[u8] = b"CorrectHorse9";
const WRONG: &[u8] = b"WrongHorse9";

pub(super) fn exercise(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    let transaction_ok = encrypted_transaction(ctx);
    let backup_ok = backup_round_trip(ctx);
    let overwrite_ok = overwrite_decision(ctx);
    transaction_ok && backup_ok && overwrite_ok
}

fn encrypted_transaction(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    let Some(wire) = super::super::signing::fixture::wire(ctx.ad, super::super::signing::fixture::WireFormat::CompactKspt) else { return false; };
    let mut envelope = [0u8; 1024];
    let Ok(length) = crate::runtime::interactions::sd::workflow_seal_envelope(&wire, PASSWORD, &mut envelope) else { return false; };
    if !ctx.enter_import_list(AppState::SdKsptFileList) { return false; }
    crate::runtime::interactions::sd::workflow_import_transaction_payload(ctx.ad, ctx.display, ctx.delay, &envelope[..length]);
    if ctx.ad.navigation.app.state != AppState::SdKsptEncryptPass { return false; }
    ctx.set_password(WRONG);
    if ctx.sd_touch(290, 215, false) != Some(true) || ctx.ad.navigation.app.state != AppState::SdKsptFileList { return false; }
    crate::runtime::interactions::sd::workflow_import_transaction_payload(ctx.ad, ctx.display, ctx.delay, &envelope[..length]);
    ctx.set_password(PASSWORD);
    if ctx.sd_touch(290, 215, false) != Some(true) || ctx.ad.navigation.app.state != AppState::ConfirmTx { return false; }
    ctx.home();
    log!("KASSIGNER_WORKFLOW_TESTS: SD ENCRYPTED TX WRONG/CORRECT PASSWORD ROUND-TRIP PASS");
    true
}

fn backup_round_trip(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    let Some(slot) = ctx.ad.wallet.seeds.seed_mgr.active_slot() else { return false; };
    let Some(count) = slot.mnemonic_word_count() else { return false; };
    let mut plaintext = [0u8; 49];
    plaintext[0] = count;
    for (index, word) in slot.indices[..usize::from(count)].iter().enumerate() {
        plaintext[1 + index * 2..3 + index * 2].copy_from_slice(&word.to_le_bytes());
    }
    let payload_len = 1 + usize::from(count) * 2;
    let salt = [0x31u8; SALT_SIZE];
    let nonce = [0x42u8; NONCE_SIZE];
    let mut encrypted = [0u8; crate::services::backup::MAX_BACKUP_SIZE];
    let Ok(length) = crate::services::backup::seal_for_test(
        crate::services::backup::BackupKind::Seed,
        &plaintext[..payload_len], PASSWORD, &mut ctx.backup_device,
        &salt, &nonce, &mut encrypted,
    ) else { return false; };
    if crate::runtime::interactions::sd::workflow_import_backup_payload(
        ctx.ad, ctx.display, &encrypted[..length], WRONG, &mut ctx.backup_device,
    ).is_ok() { return false; }
    let Ok(next) = crate::runtime::interactions::sd::workflow_import_backup_payload(
        ctx.ad, ctx.display, &encrypted[..length], PASSWORD, &mut ctx.backup_device,
    ) else { return false; };
    let ok = next == crate::runtime::navigation::continuation!(PassphraseChoice)
        && ctx.ad.wallet.seeds.word_count == count;
    ctx.home();
    if ok { log!("KASSIGNER_WORKFLOW_TESTS: SD DEVICE-BOUND SEED BACKUP WRONG/CORRECT PASSWORD ROUND-TRIP PASS"); }
    ok
}

fn overwrite_decision(ctx: &mut SdWorkflowContext<'_, '_, '_>) -> bool {
    if !ctx.enter_import_menu()
        || !crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SdKsptFilename))
        || ctx.ad.navigation.app.state != AppState::SdKsptFilename
    {
        return false;
    }
    ctx.ad.storage.confirmation.overwrite_back = crate::runtime::navigation::continuation!(SdKsptFilename);
    ctx.ad.storage.confirmation.overwrite_action = PendingStorageAction::Navigate(crate::runtime::navigation::continuation!(SdKsptEncryptAsk));
    if !crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SdOverwriteWarning))
        || ctx.sd_touch(230, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SdKsptFilename
    {
        return false;
    }
    if !crate::runtime::effects::route(ctx.ad, crate::runtime::navigation::route!(SdOverwriteWarning))
        || ctx.sd_touch(90, 160, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SdKsptEncryptAsk
    {
        return false;
    }
    ctx.ad.storage.export_file.encrypted_operation = EncryptedFileOperation::None;
    ctx.home();
    log!("KASSIGNER_WORKFLOW_TESTS: SD OVERWRITE CANCEL/CONFIRM ROUTING OK");
    true
}

