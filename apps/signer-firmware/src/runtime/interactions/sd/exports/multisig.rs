use super::super::common::context::SdIoContext;
use crate::runtime::data::TextFileKind;
// SD controller workflow: multisig.
use super::super::{
    EncryptionPayload,
    EncryptionPromptWorkflow,
    PromptDestination,
    FilenameWorkflow,
    run_encryption_prompt,
    run_filename_workflow,
};
pub(crate) fn handle_sd_ms_addr_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"TXT",
            back_state: crate::runtime::navigation::continuation!(MultisigShowAddress),
            filename_state: crate::runtime::input::AppState::SdMsAddrFilename,
            next_state: crate::runtime::navigation::continuation!(SdMsAddrEncryptAsk),
            redraw_if_exists: true,
            redraw_if_available: true,
        },
    )
}

pub(crate) fn handle_sd_ms_addr_encrypt_ask(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_encryption_prompt(
        ctx,
        EncryptionPromptWorkflow {
            back_state: crate::runtime::navigation::continuation!(MultisigShowAddress),
            payload: EncryptionPayload::KpubExport { kind: TextFileKind::MultisigAddress },
            password_back_state: crate::runtime::navigation::continuation!(SdMsAddrEncryptAsk),
            encrypted_success_state: crate::runtime::navigation::continuation!(MultisigDescriptor),
            plain_destination: PromptDestination::Route(crate::runtime::navigation::continuation!(MultisigDescriptor)),
            progress_message: "Saving address...",
            success_message: "Address saved!",
        },
    )
}

pub(crate) fn handle_sd_ms_desc_filename(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_filename_workflow(
        ctx,
        FilenameWorkflow {
            extension: *b"TXT",
            back_state: crate::runtime::navigation::continuation!(MultisigDescriptor),
            filename_state: crate::runtime::input::AppState::SdMsDescFilename,
            next_state: crate::runtime::navigation::continuation!(SdMsDescEncryptAsk),
            redraw_if_exists: false,
            redraw_if_available: false,
        },
    )
}

pub(crate) fn handle_sd_ms_desc_encrypt_ask(ctx: SdIoContext<'_, '_, '_>) -> bool {
    run_encryption_prompt(
        ctx,
        EncryptionPromptWorkflow {
            back_state: crate::runtime::navigation::continuation!(MultisigDescriptor),
            payload: EncryptionPayload::Outgoing { kind: TextFileKind::MultisigDescriptor },
            password_back_state: crate::runtime::navigation::continuation!(SdMsDescEncryptAsk),
            encrypted_success_state: crate::runtime::navigation::continuation!(MultisigDescriptor),
            plain_destination: PromptDestination::Route(crate::runtime::navigation::continuation!(MultisigDescriptor)),
            progress_message: "Saving descriptor...",
            success_message: "Descriptor saved!",
        },
    )
}
