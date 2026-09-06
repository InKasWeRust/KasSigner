// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0

//! Runtime audio servicing at the hardware-ownership boundary.

#[cfg(feature = "m5stack")]
fn credential_operation_blocks_click(ad: &crate::runtime::data::AppData) -> bool {
    crate::runtime::presentation::operation_kind(ad)
        .is_some_and(crate::runtime::data::OperationKind::is_credential)
        && matches!(
            crate::runtime::presentation::operation_phase(ad),
            crate::runtime::data::OperationPhase::Queued
                | crate::runtime::data::OperationPhase::Presented
                | crate::runtime::data::OperationPhase::Running
                | crate::runtime::data::OperationPhase::Progress(_)
        )
}

#[cfg(feature = "m5stack")]
#[inline(never)]
pub(crate) fn service(audio: &mut Option<crate::hw::sound::RuntimeAudio>) {
    if let Some(audio) = audio.as_mut() { audio.service_pending(); }
}

#[cfg(feature = "waveshare")]
pub(crate) fn service(_: &mut ()) {}

#[cfg(feature = "m5stack")]
pub(crate) fn click(
    ad: &crate::runtime::data::AppData,
    audio: &mut Option<crate::hw::sound::RuntimeAudio>,
) {
    // PIN/password submission commits the credential operation before the
    // router asks for click feedback. Drop that click before it can start an
    // I2S DMA transfer; ordinary loop audio servicing remains independent of
    // AppData/operation state.
    if credential_operation_blocks_click(ad) {
        crate::hw::sound::discard_pending();
        return;
    }
    crate::hw::sound::click();
    service(audio);
}

#[cfg(feature = "waveshare")]
pub(crate) fn click(_: &crate::runtime::data::AppData, _: &mut ()) { crate::hw::sound::click(); }

#[cfg(feature = "m5stack")]
pub(crate) fn toggle_global_mute(ad: &mut crate::runtime::data::AppData) -> u8 {
    let volume = ad.settings.toggle_mute();
    crate::runtime::effects::redraw(ad);
    volume
}
