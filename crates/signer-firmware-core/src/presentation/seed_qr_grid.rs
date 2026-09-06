//! Pure SeedQR grid-navigation reducer.

const VIEW_CELLS: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedQrGridState {
    pub pan_x: u8,
    pub pan_y: u8,
    pub compact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedQrGridEffect {
    None,
    Exit,
    Move(SeedQrGridState),
}

fn horizontal_move(state: SeedQrGridState, max_pan: u8, x: u16, y: u16) -> Option<SeedQrGridState> {
    if x >= 55 {
        return None;
    }
    if (50..130).contains(&y) {
        return Some(SeedQrGridState {
            pan_x: state.pan_x.saturating_sub(1),
            ..state
        });
    }
    (130..200).contains(&y).then(|| SeedQrGridState {
        pan_x: state.pan_x.saturating_add(1).min(max_pan),
        ..state
    })
}

fn vertical_move(state: SeedQrGridState, max_pan: u8, x: u16, y: u16) -> Option<SeedQrGridState> {
    if x <= 265 {
        return None;
    }
    if (50..130).contains(&y) {
        return Some(SeedQrGridState {
            pan_y: state.pan_y.saturating_sub(1),
            ..state
        });
    }
    (130..200).contains(&y).then(|| SeedQrGridState {
        pan_y: state.pan_y.saturating_add(1).min(max_pan),
        ..state
    })
}

pub fn reduce_grid(
    state: SeedQrGridState,
    qr_size: u8,
    x: u16,
    y: u16,
    is_back: bool,
) -> SeedQrGridEffect {
    if is_back {
        return SeedQrGridEffect::Exit;
    }
    let max_pan = qr_size.saturating_sub(VIEW_CELLS);
    let next =
        horizontal_move(state, max_pan, x, y).or_else(|| vertical_move(state, max_pan, x, y));
    match next {
        Some(next) if next != state => SeedQrGridEffect::Move(next),
        _ => SeedQrGridEffect::None,
    }
}
