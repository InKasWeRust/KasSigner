use crate::runtime::data::AppData;

pub(super) fn handle(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescChoice));
        return true;
    }
    if !(185..=225).contains(&y) {
        return false;
    }

    if (170..=300).contains(&x) {
        shared_signer::bytes::zeroize_bytes(&mut ad.stego.hint.buffer);
        ad.stego.hint.length = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegPpAsk));
        return true;
    }
    if (20..=150).contains(&x) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoJpegDescChoice));
        return true;
    }
    false
}
