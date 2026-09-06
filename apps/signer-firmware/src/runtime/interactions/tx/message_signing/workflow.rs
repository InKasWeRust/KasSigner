use crate::runtime::{data::AppData, input::AppState};

pub(super) fn sign_preview(ad: &mut AppData) -> bool {
    if ad.navigation.app.state != AppState::SignMsgPreview || ad.signing.message.payload_len == 0 {
        return false;
    }
    ad.signing.message.hash = super::service::message_digest(ad);
    let Ok(signature) = super::service::workflow_sign_reviewed_message(ad) else {
        return false;
    };
    ad.signing.message.signature = signature;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SignMsgResult));
    true
}
