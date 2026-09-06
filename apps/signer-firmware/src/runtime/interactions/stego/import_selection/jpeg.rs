use super::super::{AppData, touch};

pub(super) fn handle(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        if ad.storage.persistence.device_storage_intent.is_seed_onboarding() {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRestoreMenu));
        } else {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportMenu));
        }
        return true;
    }
    if page_up_zone.contains(x, y) && ad.stego.import.jpeg_selected >= 4 {
        ad.stego.import.jpeg_selected = ad.stego.import.jpeg_selected.saturating_sub(4);
        return true;
    }
    if page_down_zone.contains(x, y)
        && (ad.stego.import.jpeg_selected / 4 + 1) * 4 < ad.stego.import.jpeg_count
    {
        ad.stego.import.jpeg_selected = (ad.stego.import.jpeg_selected + 4)
            .min(ad.stego.import.jpeg_count.saturating_sub(1));
        return true;
    }

    let scroll = (ad.stego.import.jpeg_selected / 4) * 4;
    let Some(slot) = list_zones.iter().position(|zone| zone.contains(x, y)) else {
        return false;
    };
    let selected = scroll + slot as u8;
    if selected >= ad.stego.import.jpeg_count {
        return false;
    }
    ad.stego.import.jpeg_selected = selected;
    ad.stego.import.embedded_payload_len = 0;
    ad.stego.import.carrier = None;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportDescChoice));
    true
}
