// Pure scalar setting adjustment shared by brightness and volume controls.

pub(super) fn update(value: u8, x: u16, y: u16) -> Option<u8> {
    if x <= 68 && (70..=120).contains(&y) {
        Some(value.saturating_sub(25))
    } else if x >= 252 && (70..=120).contains(&y) {
        Some(value.saturating_add(25))
    } else if (70..=250).contains(&x) && (75..=115).contains(&y) {
        Some(((u32::from(x) - 70) * 255 / 180).min(255) as u8)
    } else {
        None
    }
}
