use crate::{
    runtime::interactions::text_files::{self, TextFileScanWorkflow},
    hw::display,
    runtime::data::AppData,
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
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPick));
        return true;
    }

    if (40..280).contains(&x) && (68..112).contains(&y) {
        ad.wallet.seeds.pp_input.reset();
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDesc));
        return true;
    }

    if !(40..280).contains(&x) || !(114..158).contains(&y) {
        return false;
    }

    let maximum_bytes = 96u32;
    text_files::scan(
        ad,
        boot_display,
        delay,
        i2c,
        TextFileScanWorkflow {
            maximum_bytes,
            next_state: crate::runtime::navigation::continuation!(StegoJpegDescFile),
            empty_message: "No .TXT files on SD",
        },
    )
}
