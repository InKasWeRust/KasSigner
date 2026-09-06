//! Transaction-review presentation façade.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_HINT, COLOR_ORANGE, COLOR_TEXT, COLOR_TEXT_DIM, DrawTarget,
    Drawable, KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive, PrimitiveStyle, draw_lato_body,
    draw_lato_title, draw_oswald_header, measure_body, measure_header, measure_title,
};

mod address;
mod footer;
mod input;
mod output;
mod summary;

impl<'a> BootDisplay<'a> {
    /// Draw a transaction review page (amount, fee, addresses).
    pub fn draw_tx_page(
        &mut self,
        tx: &offline_signer::transaction::model::Transaction,
        page: u8,
        ownership: &[crate::runtime::data::OutputOwnership; offline_signer::transaction::model::MAX_OUTPUTS],
    ) {
        self.display.clear(COLOR_BG).ok();
        let total_pages = 1 + tx.num_outputs as u8;

        if page == 0 {
            self.draw_tx_summary(tx, ownership);
        } else {
            self.draw_tx_output(tx, page, ownership[(page - 1) as usize]);
        }

        self.draw_tx_footer(page, total_pages);
    }
}
