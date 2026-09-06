#[derive(Clone, Copy)]
pub(super) enum IndexKey {
    Digit(u8),
    Clear,
    Submit,
}

pub(super) fn hit(x: u16, y: u16) -> Option<IndexKey> {
    let column = if (55..120).contains(&x) {
        0
    } else if (130..195).contains(&x) {
        1
    } else if (205..270).contains(&x) {
        2
    } else {
        return None;
    };
    let row = if (76..106).contains(&y) {
        0
    } else if (110..140).contains(&y) {
        1
    } else if (144..174).contains(&y) {
        2
    } else if (178..208).contains(&y) {
        3
    } else {
        return None;
    };
    match row * 3 + column {
        value @ 0..=8 => Some(IndexKey::Digit((value + 1) as u8)),
        9 => Some(IndexKey::Clear),
        10 => Some(IndexKey::Digit(0)),
        11 => Some(IndexKey::Submit),
        _ => None,
    }
}
