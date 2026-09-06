pub(super) mod format;
pub(super) mod masking;
pub(super) mod matrix;
pub(super) mod version;

use matrix::QrCode;

pub(crate) fn build(version: u8, codewords: &[u8]) -> QrCode {
    let mut qr = QrCode::new(version);
    qr.draw_function_patterns();
    qr.place_data(codewords);
    qr.apply_best_mask();
    qr
}
