use super::super::common::context::{SdFileListContext, SdIoContext};
// SD controller workflow: file browser.
use super::super::{run_sd_file_list_context, sound, FileListWorkflow};
use super::selected_file;
use crate::runtime::destructive::{self, DestructiveAction, TouchRect};
pub(crate) fn handle_sd_file_list(context: SdFileListContext<'_, '_, '_>) -> bool {
    run_sd_file_list_context(
        context,
        FileListWorkflow {
            allow_delete: true,
            current_state: crate::runtime::input::AppState::SdFileList,
            back_state: crate::runtime::navigation::continuation!(SdImportMenu),
        },
        selected_file::import_selected_file,
    )
}

pub(crate) fn handle_sd_delete_confirm(ctx: SdIoContext<'_, '_, '_>) -> bool {
    let SdIoContext { ad, x, y, is_back, .. } = ctx;
    let return_state = ad.storage.confirmation.delete_return;
    let cancel_pressed = CANCEL_BUTTON.contains(x, y);
    if is_back || cancel_pressed {
        if cancel_pressed {
            sound::click();
        }
        ad.storage.confirmation.delete_return = crate::runtime::navigation::continuation!(MainMenu);
        crate::runtime::effects::continue_to(ad, return_state);
        return true;
    }
    if DELETE_BUTTON.contains(x, y) {
        destructive::begin(ad, DestructiveAction::DeleteSdFile);
        return false;
    }
    false
}

const DELETE_BUTTON: TouchRect = TouchRect::new(170, 180, 290, 230);
const CANCEL_BUTTON: TouchRect = TouchRect::new(30, 180, 150, 230);
