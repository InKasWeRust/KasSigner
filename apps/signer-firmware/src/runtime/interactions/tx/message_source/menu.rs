use super::super::{AppData, display};
use crate::{
    runtime::interactions::text_files::{self, TextFileScanWorkflow},
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::return_to(ad, crate::runtime::navigation::ReturnScope::SigningTool);
    } else if (40..280).contains(&x) && (68..112).contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgType));
    } else if (40..280).contains(&x) && (114..158).contains(&y) {
        ad.signing.message.payload_len = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgScan));
    } else if (40..280).contains(&x) && (160..204).contains(&y) {
        let maximum_bytes = ad.signing.message.payload.len() as u32;
        return text_files::scan(
            ad,
            boot_display,
            delay,
            i2c,
            TextFileScanWorkflow {
                maximum_bytes,
                next_state: crate::runtime::navigation::continuation!(SignMsgFile),
                empty_message: "No .TXT files on SD",
            },
        );
    } else {
        return false;
    }
    true
}
