use super::super::{AppData, display};
use crate::{
    runtime::interactions::text_files::{self, TextFileScanWorkflow, TextFileSelectionContext, TextFileSelectionWorkflow},
};

pub(super) fn handle_choice(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPick));
        return true;
    }
    if (40..280).contains(&x) && (68..112).contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPass));
        return true;
    }
    if (40..280).contains(&x) && (114..158).contains(&y) {
        return text_files::scan(
            ad,
            boot_display,
            delay,
            i2c,
            TextFileScanWorkflow {
                maximum_bytes: 96,
                next_state: crate::runtime::navigation::continuation!(StegoImportDescFile),
                empty_message: "No .TXT files on SD",
            },
        );
    }
    false
}

pub(super) fn handle_file(context: TextFileSelectionContext<'_, '_, '_>) -> bool {
    text_files::handle_selection::<128>(
        context,
        TextFileSelectionWorkflow {
            back_state: crate::runtime::navigation::continuation!(StegoImportDescChoice),
            read_error_message: "Read failed",
        },
        accept_content,
    )
}

fn accept_content(ad: &mut AppData, content: &[u8]) -> Result<(), &'static str> {
    if content.is_empty() {
        return Err("Descriptor required");
    }
    if content.len() > 96 {
        return Err("Description too large");
    }
    ad.wallet.seeds.pp_input.reset();
    ad.wallet.seeds.pp_input.buf[..content.len()].copy_from_slice(content);
    ad.wallet.seeds.pp_input.len = content.len();
    ad.wallet.seeds.pp_input.cursor = content.len();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPass));
    Ok(())
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_accept_content(ad: &mut AppData, content: &[u8]) -> Result<(), &'static str> {
    accept_content(ad, content)
}
