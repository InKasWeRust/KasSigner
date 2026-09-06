use super::AppData;
use crate::runtime::input::AppState;

pub(super) fn handle(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::ShowQR => {
            advance_or_close(ad);
            Some(true)
        }
        AppState::Rejected => {
            let ok = crate::ui::layout::ERROR_OK_ZONE.contains(x, y);
            if is_back || ok {
                if !crate::runtime::effects::back(ad) {
                    crate::runtime::effects::home(ad);
                }
            }
            Some(true)
        }
        _ => None,
    }
}

fn advance_or_close(ad: &mut AppData) {
    use crate::runtime::data::AntiKleptoPhase;
    match ad.signing.anti_klepto.phase {
        AntiKleptoPhase::AwaitingReveal => {
            ad.qr.outgoing.frame_count = 0;
            ad.qr.outgoing.frame = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AntiKleptoRevealGuide));
            return;
        }
        AntiKleptoPhase::FinalResponse => {
            ad.signing.anti_klepto.reset();
            ad.qr.outgoing.frame_count = 0;
            crate::runtime::effects::home(ad);
            return;
        }
        _ => {}
    }
    if ad.qr.outgoing.length == 0 {
        crate::runtime::effects::home(ad);
        return;
    }
    if let Some(target) = ad.qr.outgoing.close_state {
        ad.qr.outgoing.clear();
        crate::runtime::effects::continue_to(ad, target);
        return;
    }
    if ad.qr.outgoing.manual_frames && ad.qr.outgoing.frame_count > 1 {
        let next = ad.qr.outgoing.frame + 1;
        if next < ad.qr.outgoing.frame_count {
            ad.qr.outgoing.frame = next;
            return;
        }
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQrPopup));
}
