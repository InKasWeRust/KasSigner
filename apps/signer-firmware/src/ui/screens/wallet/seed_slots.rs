// KasSigner — shared seed-slot list presentation.

use super::super::{
    BootDisplay,
    COLOR_CARD,
    COLOR_CARD_BORDER,
    COLOR_ORANGE,
    COLOR_TEXT,
    COLOR_TEXT_DIM,
    Circle,
    CornerRadii,
    Drawable,
    KASPA_ACCENT,
    KASPA_TEAL,
    Point,
    Primitive,
    PrimitiveStyle,
    Rectangle,
    Rgb565,
    RoundedRectangle,
    Size,
    Triangle,
    draw_lato_hint,
    draw_lato_title,
    measure_hint,
    measure_title,
};

pub(super) struct SeedSlotListConfig {
    pub start_y: i32,
    pub include_add_slot: bool,
    pub active_fill: Rgb565,
    pub active_border: Rgb565,
    pub active_text: Rgb565,
}

impl<'a> BootDisplay<'a> {
    pub(super) fn draw_seed_slot_list(
        &mut self,
        seed_mgr: &crate::wallet::seed_manager::SeedManager,
        scroll: u8,
        config: SeedSlotListConfig,
    ) {
        let (loaded, loaded_count) = loaded_seed_slots(seed_mgr);
        let can_add = config.include_add_slot && seed_mgr.find_free().is_some();
        let scroll_offset = usize::from(scroll);
        for visible_index in 0..MAX_VISIBLE_SEED_SLOTS {
            let row_y = config.start_y
                + visible_index as i32 * (SEED_CARD_HEIGHT + SEED_CARD_GAP);
            let list_index = scroll_offset + visible_index;
            self.draw_seed_slot_row(
                seed_mgr, &loaded, loaded_count, can_add, list_index, row_y, &config,
            );
        }
        let visible_total = loaded_count + usize::from(can_add);
        draw_seed_slot_arrows(&mut self.display, visible_total, scroll_offset, config.start_y);
        draw_seed_slot_pages(&mut self.display, visible_total, scroll_offset);
    }

    fn draw_seed_slot_row(
        &mut self,
        seed_mgr: &crate::wallet::seed_manager::SeedManager,
        loaded: &[usize; crate::wallet::seed_manager::MAX_SLOTS],
        loaded_count: usize,
        can_add: bool,
        list_index: usize,
        row_y: i32,
        config: &SeedSlotListConfig,
    ) {
        let rectangle = seed_card_rectangle(row_y);
        if can_add && list_index == 0 {
            draw_add_seed_slot(&mut self.display, rectangle, row_y);
            return;
        }
        let wallet_index = list_index.saturating_sub(usize::from(can_add));
        if wallet_index >= loaded_count { return; }
        let slot_index = loaded[wallet_index];
        draw_loaded_seed_slot(
            &mut self.display, seed_mgr, slot_index, wallet_index, rectangle, row_y, config,
        );
    }
}

const SEED_CARD_HEIGHT: i32 = 42;
const SEED_CARD_GAP: i32 = 4;
const SEED_CARD_WIDTH: u32 = 232;
const SEED_CARD_START_X: i32 = 44;
const MAX_VISIBLE_SEED_SLOTS: usize = 3;

fn loaded_seed_slots(
    seed_mgr: &crate::wallet::seed_manager::SeedManager,
) -> ([usize; crate::wallet::seed_manager::MAX_SLOTS], usize) {
    let mut loaded = [0usize; crate::wallet::seed_manager::MAX_SLOTS];
    let mut count = 0usize;
    for index in 0..crate::wallet::seed_manager::MAX_SLOTS {
        if seed_mgr.slot_visible(index) {
            loaded[count] = index;
            count += 1;
        }
    }
    (loaded, count)
}

fn seed_card_rectangle(row_y: i32) -> Rectangle {
    Rectangle::new(
        Point::new(SEED_CARD_START_X, row_y),
        Size::new(SEED_CARD_WIDTH, SEED_CARD_HEIGHT as u32),
    )
}

fn draw_add_seed_slot(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = Rgb565>,
    rectangle: Rectangle,
    row_y: i32,
) {
    let corner = CornerRadii::new(Size::new(6, 6));
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(COLOR_CARD))
        .draw(display).ok();
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_stroke(COLOR_CARD_BORDER, 1))
        .draw(display).ok();
    let width = measure_title("+");
    draw_lato_title(
        display,
        "+",
        SEED_CARD_START_X + (SEED_CARD_WIDTH as i32 - width) / 2,
        row_y + 28,
        COLOR_TEXT_DIM,
    );
}

fn draw_loaded_seed_slot(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = Rgb565>,
    seed_mgr: &crate::wallet::seed_manager::SeedManager,
    slot_index: usize,
    wallet_index: usize,
    rectangle: Rectangle,
    row_y: i32,
    config: &SeedSlotListConfig,
) {
    let slot = &seed_mgr.slots[slot_index];
    let active = seed_mgr.active == slot_index as u8;
    let fill = if active { config.active_fill } else { COLOR_CARD };
    let border = if active { config.active_border } else { COLOR_CARD_BORDER };
    let text = if active { config.active_text } else { COLOR_TEXT };
    let corner = CornerRadii::new(Size::new(6, 6));
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_fill(fill))
        .draw(display).ok();
    RoundedRectangle::new(rectangle, corner)
        .into_styled(PrimitiveStyle::with_stroke(border, if active { 2 } else { 1 }))
        .draw(display).ok();
    draw_seed_slot_identity(display, slot, wallet_index, row_y, text);
}

fn draw_seed_slot_identity(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = Rgb565>,
    slot: &crate::wallet::seed_manager::SeedSlot,
    wallet_index: usize,
    row_y: i32,
    text: Rgb565,
) {
    let mut label: heapless::String<20> = heapless::String::new();
    if slot.name_len > 0 {
        for ch in slot.name_str().chars().take(11) {
            if label.push(ch).is_err() { break; }
        }
    } else {
        core::fmt::Write::write_fmt(&mut label, format_args!("Wallet {}", wallet_index + 1)).ok();
    }
    draw_lato_title(display, label.as_str(), SEED_CARD_START_X + 12, row_y + 20, text);

    // The canonical WALLETS card always exposes the wallet material type. For
    // mnemonic wallets this is the familiar 12w/24w cue from the retired seed
    // picker, without retaining any legacy destructive row affordance.
    draw_lato_hint(
        display,
        slot.source.display_label(),
        SEED_CARD_START_X + 12,
        row_y + 35,
        COLOR_TEXT_DIM,
    );
    if slot.is_mnemonic() && slot.passphrase_len > 0 {
        draw_lato_hint(display, "Pass", SEED_CARD_START_X + 54, row_y + 35, COLOR_ORANGE);
    }
    let network = slot.network.short_label();
    let network_width = measure_hint(network);
    draw_lato_hint(
        display, network,
        SEED_CARD_START_X + SEED_CARD_WIDTH as i32 - 10 - network_width,
        row_y + 35, COLOR_TEXT_DIM,
    );
}

fn draw_seed_slot_arrows(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = Rgb565>,
    visible_total: usize,
    scroll_offset: usize,
    start_y: i32,
) {
    let disabled_teal = Rgb565::new(0b00001, 0b000100, 0b00010);
    let arrow_y = start_y
        + (MAX_VISIBLE_SEED_SLOTS as i32 * (SEED_CARD_HEIGHT + SEED_CARD_GAP) - SEED_CARD_GAP) / 2;
    let previous_color = if scroll_offset > 0 { KASPA_TEAL } else { disabled_teal };
    Triangle::new(Point::new(5, arrow_y), Point::new(30, arrow_y - 17), Point::new(30, arrow_y + 17))
        .into_styled(PrimitiveStyle::with_fill(previous_color))
        .draw(display).ok();
    let can_next = visible_total > MAX_VISIBLE_SEED_SLOTS
        && scroll_offset + MAX_VISIBLE_SEED_SLOTS < visible_total;
    let next_color = if can_next { KASPA_TEAL } else { disabled_teal };
    Triangle::new(Point::new(315, arrow_y), Point::new(290, arrow_y - 17), Point::new(290, arrow_y + 17))
        .into_styled(PrimitiveStyle::with_fill(next_color))
        .draw(display).ok();
}

fn draw_seed_slot_pages(
    display: &mut impl embedded_graphics::draw_target::DrawTarget<Color = Rgb565>,
    visible_total: usize,
    scroll_offset: usize,
) {
    if visible_total <= MAX_VISIBLE_SEED_SLOTS {
        return;
    }
    let disabled_teal = Rgb565::new(0b00001, 0b000100, 0b00010);
    let pages = visible_total.div_ceil(MAX_VISIBLE_SEED_SLOTS) as u8;
    let current = (scroll_offset / MAX_VISIBLE_SEED_SLOTS) as u8;
    let total_width = i32::from(pages) * 7 + (i32::from(pages) - 1) * 8;
    let start_x = (320 - total_width) / 2;
    for page in 0..pages {
        let x = start_x + i32::from(page) * 15;
        let color = if page == current { KASPA_ACCENT } else { disabled_teal };
        Circle::new(Point::new(x, 232), 7)
            .into_styled(PrimitiveStyle::with_fill(color))
            .draw(display).ok();
    }
}
