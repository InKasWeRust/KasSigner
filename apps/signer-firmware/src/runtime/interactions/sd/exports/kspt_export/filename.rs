// SD controller workflow: encrypted transaction and text exports.
use super::super::super::{
    EncryptionPayload,
    EncryptionPromptWorkflow,
    PromptDestination,
    FilenameWorkflow,
    run_encryption_prompt,
    run_filename_workflow,
    SdIoContext,
};

pub(crate) fn handle_sd_kspt_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"KSP",
            back_state: crate::runtime::navigation::continuation!(ShowQrPopup),
            filename_state: crate::runtime::input::AppState::SdKsptFilename,
            next_state: crate::runtime::navigation::continuation!(SdKsptEncryptAsk),
            redraw_if_exists: false,
            redraw_if_available: false,
        },
    )
}

pub(crate) fn handle_sd_kspt_encrypt_ask(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_encryption_prompt(
        ctx,
        EncryptionPromptWorkflow {
            back_state: crate::runtime::navigation::continuation!(ShowQrPopup),
            payload: EncryptionPayload::Transaction,
            password_back_state: crate::runtime::navigation::continuation!(SdKsptEncryptAsk),
            encrypted_success_state: crate::runtime::navigation::continuation!(MainMenu),
            plain_destination: PromptDestination::MainMenu,
            progress_message: "Saving to SD...",
            success_message: "Saved!",
        },
    )
}
