//! Separate JPEG selection and descriptor-text workflows for stego import.

use super::{context::StegoFileContext, TouchInput};
use crate::{runtime::interactions::text_files::TextFileSelectionContext, runtime::input::AppState};

mod descriptor;
mod jpeg;

pub(super) fn handle(context: StegoFileContext<'_, '_, '_>) -> Option<bool> {
    let StegoFileContext {
        ad, boot_display, delay, i2c, list_zones, page_up_zone, page_down_zone, input,
    } = context;
    let TouchInput { x, y, is_back } = input;
    let redraw = match ad.navigation.app.state {
        AppState::StegoImportPick => {
            jpeg::handle(ad, list_zones, page_up_zone, page_down_zone, x, y, is_back)
        }
        AppState::StegoImportDescChoice => {
            descriptor::handle_choice(ad, boot_display, delay, i2c, x, y, is_back)
        }
        AppState::StegoImportDescFile => {
            descriptor::handle_file(TextFileSelectionContext {
                ad, boot_display, delay, i2c, list_zones, input,
            })
        }
        _ => return None,
    };
    Some(redraw)
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) use descriptor::workflow_accept_content as workflow_accept_descriptor_file;
