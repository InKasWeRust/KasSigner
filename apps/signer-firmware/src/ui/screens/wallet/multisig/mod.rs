// KasSigner screen façade.

use super::super::{
    BootDisplay, COLOR_BG, COLOR_CARD, COLOR_CARD_BORDER, COLOR_DANGER, COLOR_HINT, COLOR_TEXT,
    COLOR_TEXT_DIM, CornerRadii, Drawable, KASPA_ACCENT, KASPA_TEAL, Line, Point, Primitive,
    PrimitiveStyle, Rectangle, RoundedRectangle, Size, draw_lato_body,
    draw_lato_hint, draw_lato_title, draw_oswald_header, draw_rubik_big, measure_big, measure_body,
    measure_header, measure_hint, measure_title,
};

mod result;
mod setup;
