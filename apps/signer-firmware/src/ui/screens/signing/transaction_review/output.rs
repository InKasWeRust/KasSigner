//! Transaction-review output rendering using signer-verified ownership.
use super::{
    BootDisplay, COLOR_ORANGE, COLOR_TEXT, COLOR_TEXT_DIM, Drawable, KASPA_TEAL, Line, Point,
    Primitive, PrimitiveStyle, draw_lato_title, draw_oswald_header, measure_header, measure_title,
};
use core::fmt::Write;
use crate::runtime::data::OutputOwnership;

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_tx_output(
        &mut self,
        transaction: &offline_signer::transaction::model::Transaction,
        page: u8,
        ownership: OutputOwnership,
    ) {
        let output_index = usize::from(page - 1);
        if output_index >= transaction.num_outputs { return; }
        let output = &transaction.outputs[output_index];
        self.draw_output_heading(output_index, ownership);
        self.draw_output_amount(output.value, ownership);
        self.draw_tx_destination(&output.script_public_key, transaction.network);
    }

    fn draw_output_heading(&mut self, output_index: usize, ownership: OutputOwnership) {
        let mut title = heapless::String::<40>::new();
        let label = match ownership {
            OutputOwnership::Change => "CHANGE",
            OutputOwnership::Receive => "OWN RECEIVE",
            OutputOwnership::External => "DESTINATION",
        };
        write!(&mut title, "{label} {}", output_index + 1).ok();
        let color = if ownership == OutputOwnership::External { COLOR_TEXT } else { KASPA_TEAL };
        let width = measure_header(title.as_str());
        draw_oswald_header(&mut self.display, title.as_str(), (320 - width) / 2, 30, color);
        Line::new(Point::new(20, 40), Point::new(300, 40))
            .into_styled(PrimitiveStyle::with_stroke(KASPA_TEAL, 1))
            .draw(&mut self.display).ok();
    }

    fn draw_output_amount(&mut self, value: u64, ownership: OutputOwnership) {
        let kas = value / 100_000_000;
        let sompi = value % 100_000_000;
        let mut amount = heapless::String::<32>::new();
        write!(&mut amount, "{kas}.{sompi:08} KAS").ok();
        let color = if ownership == OutputOwnership::Change { COLOR_TEXT_DIM } else { COLOR_ORANGE };
        let width = measure_title(amount.as_str());
        draw_lato_title(&mut self.display, amount.as_str(), (320 - width) / 2, 75, color);
    }
}
