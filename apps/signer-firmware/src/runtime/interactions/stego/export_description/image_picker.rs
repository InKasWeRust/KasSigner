use crate::{
    hw::touch::TouchZone,
    runtime::data::AppData,
};

const PAGE_SIZE: u8 = 4;

pub(super) fn handle(
    ad: &mut AppData,
    list_zones: &[TouchZone; 4],
    page_up_zone: &TouchZone,
    page_down_zone: &TouchZone,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoSecuritySelect));
        return true;
    }

    if page_up_zone.contains(x, y) && ad.stego.export_flow.jpeg_selected >= PAGE_SIZE {
        ad.stego.export_flow.jpeg_selected -= PAGE_SIZE;
        return true;
    }

    if page_down_zone.contains(x, y) {
        return advance_page(ad);
    }

    select_visible_image(ad, list_zones, x, y)
}

fn advance_page(ad: &mut AppData) -> bool {
    let selected = ad.stego.export_flow.jpeg_selected;
    let count = ad.stego.export_flow.jpeg_file_count;
    if (selected / PAGE_SIZE + 1) * PAGE_SIZE >= count {
        return false;
    }
    ad.stego.export_flow.jpeg_selected = (selected + PAGE_SIZE).min(count - 1);
    true
}

fn select_visible_image(
    ad: &mut AppData,
    list_zones: &[TouchZone; 4],
    x: u16,
    y: u16,
) -> bool {
    let page_start = (ad.stego.export_flow.jpeg_selected / PAGE_SIZE) * PAGE_SIZE;
    for slot in 0..PAGE_SIZE {
        if !list_zones[slot as usize].contains(x, y) {
            continue;
        }
        let absolute = page_start + slot;
        if absolute >= ad.stego.export_flow.jpeg_file_count {
            return false;
        }
        ad.stego.export_flow.jpeg_selected = absolute;
        ad.stego.export_flow.jpeg_desc_len = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescChoice));
        return true;
    }
    false
}
