// QR presentation routing.
use super::AppData;

mod presentation;

pub(super) fn handle(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> Option<bool> {
    presentation::handle(ad, x, y, is_back)
}
