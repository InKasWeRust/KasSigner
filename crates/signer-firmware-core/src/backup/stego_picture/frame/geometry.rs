use super::{Component, FrameParseState};
use crate::backup::stego_picture::PictureError;

pub(super) fn frame_geometry(context: &FrameParseState) -> Result<(u32, u32, u32), PictureError> {
    let active_components = context
        .components
        .get(..context.component_count)
        .ok_or(PictureError::Malformed)?;
    let (horizontal_span, vertical_span) = component_spans(active_components)?;
    let mcu_columns = rounded_units(context.width, horizontal_span)?;
    let mcu_rows = rounded_units(context.height, vertical_span)?;
    let blocks_per_mcu = blocks_per_mcu(active_components)?;
    Ok((mcu_columns, mcu_rows, blocks_per_mcu))
}

fn component_spans(components: &[Component]) -> Result<(u32, u32), PictureError> {
    let maximum_horizontal = components
        .iter()
        .map(|component| component.horizontal)
        .max()
        .unwrap_or(1);
    let maximum_vertical = components
        .iter()
        .map(|component| component.vertical)
        .max()
        .unwrap_or(1);
    let horizontal_span = maximum_horizontal
        .checked_mul(8)
        .ok_or(PictureError::Malformed)?;
    let vertical_span = maximum_vertical
        .checked_mul(8)
        .ok_or(PictureError::Malformed)?;
    Ok((horizontal_span, vertical_span))
}

fn rounded_units(value: u32, span: u32) -> Result<u32, PictureError> {
    value
        .checked_add(span.saturating_sub(1))
        .map(|rounded| rounded / span)
        .ok_or(PictureError::Malformed)
}

fn blocks_per_mcu(components: &[Component]) -> Result<u32, PictureError> {
    components.iter().try_fold(0u32, |total, component| {
        component
            .horizontal
            .checked_mul(component.vertical)
            .and_then(|blocks| total.checked_add(blocks))
            .ok_or(PictureError::Malformed)
    })
}
