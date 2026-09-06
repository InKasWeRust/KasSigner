//! Baseline sequential JPEG frame parsing.

extern crate alloc;
use super::{huffman::HuffmanTable, PictureError};
use alloc::{boxed::Box, vec::Vec};

mod geometry;
mod huffman_tables;

use geometry::frame_geometry;
pub(super) use huffman_tables::parse_huffman_tables;

#[derive(Clone, Copy)]
pub(super) struct Component {
    pub(super) horizontal: u32,
    pub(super) vertical: u32,
    pub(super) dc_table: usize,
    pub(super) ac_table: usize,
}

struct FrameParseState {
    width: u32,
    height: u32,
    component_count: usize,
    ids: [u8; 4],
    components: [Component; 4],
    restart_interval: u32,
    dc_tables: Box<[HuffmanTable]>,
    ac_tables: Box<[HuffmanTable]>,
}

fn empty_huffman_tables() -> Result<Box<[HuffmanTable]>, PictureError> {
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(4)
        .map_err(|_| PictureError::AllocationFailed)?;
    for _ in 0..4 {
        tables.push(HuffmanTable::empty());
    }
    Ok(tables.into_boxed_slice())
}

impl FrameParseState {
    fn new() -> Result<Self, PictureError> {
        Ok(Self {
            width: 0,
            height: 0,
            component_count: 0,
            ids: [0u8; 4],
            components: [Component {
                horizontal: 1,
                vertical: 1,
                dc_table: 0,
                ac_table: 0,
            }; 4],
            restart_interval: 0,
            dc_tables: empty_huffman_tables()?,
            ac_tables: empty_huffman_tables()?,
        })
    }
}

pub(super) struct Frame {
    pub(super) scan_start: usize,
    pub(super) scan_end: usize,
    pub(super) components: [Component; 4],
    pub(super) component_count: usize,
    pub(super) mcu_columns: u32,
    pub(super) mcu_rows: u32,
    pub(super) restart_interval: u32,
    pub(super) dc_tables: Box<[HuffmanTable]>,
    pub(super) ac_tables: Box<[HuffmanTable]>,
    pub(super) blocks_per_mcu: u32,
}

impl Frame {
    pub(super) fn positions(&self) -> u32 {
        self.mcu_columns
            .saturating_mul(self.mcu_rows)
            .saturating_mul(self.blocks_per_mcu)
            .saturating_mul(63)
    }
}

pub(super) fn parse(jpeg: &[u8]) -> Result<Frame, PictureError> {
    validate_jpeg_header(jpeg)?;
    let mut state = FrameParseState::new()?;
    let mut position = 2usize;
    while jpeg.len().saturating_sub(position) >= 4 {
        let Some((marker, segment_length, segment)) = next_segment(jpeg, &mut position)? else {
            continue;
        };
        if marker == 0xD9 {
            break;
        }
        if let Some(frame) =
            process_segment(jpeg, position, marker, segment_length, segment, &mut state)?
        {
            return Ok(frame);
        }
        position = advance_segment_position(position, segment_length)?;
    }
    Err(PictureError::Malformed)
}

fn advance_segment_position(position: usize, segment_length: usize) -> Result<usize, PictureError> {
    checked_add(position, 2)?
        .checked_add(segment_length)
        .ok_or(PictureError::Malformed)
}

fn validate_jpeg_header(jpeg: &[u8]) -> Result<(), PictureError> {
    if jpeg.len() < 4 || !jpeg.starts_with(&[0xFF, 0xD8]) {
        return Err(PictureError::Malformed);
    }
    Ok(())
}

fn checked_add(left: usize, right: usize) -> Result<usize, PictureError> {
    left.checked_add(right).ok_or(PictureError::Malformed)
}

type Segment<'a> = (u8, usize, &'a [u8]);
type SegmentResult<'a> = Result<Option<Segment<'a>>, PictureError>;

fn next_segment<'a>(jpeg: &'a [u8], position: &mut usize) -> SegmentResult<'a> {
    let Some(marker) = marker_at(jpeg, *position)? else {
        *position = checked_add(*position, 1)?;
        return Ok(None);
    };
    if marker_has_no_length(marker) {
        *position = checked_add(*position, 2)?;
        return Ok(None);
    }
    if marker == 0xD9 {
        return Ok(Some((marker, 0, &[])));
    }
    segment_with_length(jpeg, *position, marker)
}

fn marker_at(jpeg: &[u8], position: usize) -> Result<Option<u8>, PictureError> {
    if *jpeg.get(position).ok_or(PictureError::Malformed)? != 0xFF {
        return Ok(None);
    }
    Ok(Some(
        *jpeg
            .get(checked_add(position, 1)?)
            .ok_or(PictureError::Malformed)?,
    ))
}

fn segment_with_length(jpeg: &[u8], position: usize, marker: u8) -> SegmentResult<'_> {
    let segment_length = read_segment_length(jpeg, position)?;
    let segment = read_segment_payload(jpeg, position, segment_length)?;
    Ok(Some((marker, segment_length, segment)))
}

const fn marker_has_no_length(marker: u8) -> bool {
    matches!(marker, 0xD8 | 0x01 | 0xD0..=0xD7)
}

fn read_segment_length(jpeg: &[u8], position: usize) -> Result<usize, PictureError> {
    let start = checked_add(position, 2)?;
    let bytes = jpeg
        .get(start..checked_add(start, 2)?)
        .ok_or(PictureError::Malformed)?;
    let length = (usize::from(bytes[0]) << 8) | usize::from(bytes[1]);
    if length < 2 {
        return Err(PictureError::Malformed);
    }
    Ok(length)
}

fn read_segment_payload(
    jpeg: &[u8],
    position: usize,
    segment_length: usize,
) -> Result<&[u8], PictureError> {
    let end = checked_add(checked_add(position, 2)?, segment_length)?;
    if end > jpeg.len() {
        return Err(PictureError::Malformed);
    }
    let start = checked_add(position, 4)?;
    jpeg.get(start..end).ok_or(PictureError::Malformed)
}

fn process_segment(
    jpeg: &[u8],
    position: usize,
    marker: u8,
    segment_length: usize,
    segment: &[u8],
    state: &mut FrameParseState,
) -> Result<Option<Frame>, PictureError> {
    if is_nonbaseline_marker(marker) {
        return Err(PictureError::NotBaseline);
    }
    if marker == 0xDA {
        return parse_scan(jpeg, position, segment_length, segment, state).map(Some);
    }
    process_metadata_segment(marker, segment, state)?;
    Ok(None)
}

fn process_metadata_segment(
    marker: u8,
    segment: &[u8],
    state: &mut FrameParseState,
) -> Result<(), PictureError> {
    match marker {
        0xC0 | 0xC1 => parse_frame_header(
            segment,
            &mut state.width,
            &mut state.height,
            &mut state.component_count,
            &mut state.ids,
            &mut state.components,
        )?,
        0xC4 => parse_huffman_tables(segment, &mut state.dc_tables, &mut state.ac_tables)?,
        0xDD => state.restart_interval = parse_restart_interval(segment)?,
        _ => {}
    }
    Ok(())
}

fn is_nonbaseline_marker(marker: u8) -> bool {
    marker == 0xCC || matches!(marker, 0xC2 | 0xC3 | 0xC5..=0xC7 | 0xC9..=0xCF)
}

fn parse_restart_interval(segment: &[u8]) -> Result<u32, PictureError> {
    let bytes = segment.get(..2).ok_or(PictureError::Malformed)?;
    Ok(u32::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn parse_frame_header(
    segment: &[u8],
    width: &mut u32,
    height: &mut u32,
    component_count: &mut usize,
    ids: &mut [u8; 4],
    components: &mut [Component; 4],
) -> Result<(), PictureError> {
    let header = segment.get(..6).ok_or(PictureError::Malformed)?;
    *height = u32::from(u16::from_be_bytes([header[1], header[2]]));
    *width = u32::from(u16::from_be_bytes([header[3], header[4]]));
    *component_count = usize::from(header[5]);
    validate_frame_component_span(segment.len(), *component_count)?;
    for index in 0..*component_count {
        let (id, component) = parse_frame_component(segment, index)?;
        ids[index] = id;
        components[index].horizontal = component.horizontal;
        components[index].vertical = component.vertical;
    }
    Ok(())
}

fn validate_frame_component_span(segment_length: usize, count: usize) -> Result<(), PictureError> {
    let required = count
        .checked_mul(3)
        .and_then(|length| length.checked_add(6))
        .ok_or(PictureError::Malformed)?;
    if count == 0 || count > 4 || segment_length < required {
        return Err(PictureError::Malformed);
    }
    Ok(())
}

fn parse_frame_component(segment: &[u8], index: usize) -> Result<(u8, Component), PictureError> {
    let base = checked_add(6, index.checked_mul(3).ok_or(PictureError::Malformed)?)?;
    let id = *segment.get(base).ok_or(PictureError::Malformed)?;
    let sampling = *segment
        .get(checked_add(base, 1)?)
        .ok_or(PictureError::Malformed)?;
    let horizontal = u32::from(sampling >> 4);
    let vertical = u32::from(sampling & 0x0F);
    if horizontal == 0 || vertical == 0 || horizontal > 4 || vertical > 4 {
        return Err(PictureError::Malformed);
    }
    Ok((
        id,
        Component {
            horizontal,
            vertical,
            dc_table: 0,
            ac_table: 0,
        },
    ))
}

fn parse_scan(
    jpeg: &[u8],
    marker_position: usize,
    segment_length: usize,
    segment: &[u8],
    state: &mut FrameParseState,
) -> Result<Frame, PictureError> {
    let scan_components = validate_scan_header(segment, state)?;
    assign_scan_tables(segment, scan_components, state)?;
    validate_scan_tables(state)?;
    build_frame(jpeg, marker_position, segment_length, state)
}

fn validate_scan_header(segment: &[u8], context: &FrameParseState) -> Result<usize, PictureError> {
    validate_scan_context(segment, context)?;
    let scan_components = usize::from(segment[0]);
    let selectors_length = scan_components
        .checked_mul(2)
        .and_then(|length| length.checked_add(1))
        .ok_or(PictureError::Malformed)?;
    let required = checked_add(selectors_length, 3)?;
    if !scan_shape_is_baseline(
        scan_components,
        segment.len(),
        required,
        context.component_count,
    ) {
        return Err(PictureError::NotBaseline);
    }
    validate_spectral_selection(segment, selectors_length)?;
    Ok(scan_components)
}

fn validate_scan_context(segment: &[u8], context: &FrameParseState) -> Result<(), PictureError> {
    if segment.is_empty() || context.width == 0 || context.height == 0 {
        Err(PictureError::Malformed)
    } else {
        Ok(())
    }
}

fn scan_shape_is_baseline(
    scan_components: usize,
    segment_len: usize,
    required: usize,
    component_count: usize,
) -> bool {
    scan_components != 0
        && scan_components <= 4
        && segment_len >= required
        && scan_components == component_count
}

fn validate_spectral_selection(
    segment: &[u8],
    selectors_length: usize,
) -> Result<(), PictureError> {
    let spectral_start = segment[selectors_length];
    let spectral_end = segment[checked_add(selectors_length, 1)?];
    let approximation = segment[checked_add(selectors_length, 2)?];
    if spectral_start == 0 && spectral_end == 63 && approximation == 0 {
        Ok(())
    } else {
        Err(PictureError::NotBaseline)
    }
}

fn assign_scan_tables(
    segment: &[u8],
    scan_components: usize,
    context: &mut FrameParseState,
) -> Result<(), PictureError> {
    for scan_index in 0..scan_components {
        let base = checked_add(1, scan_index.checked_mul(2).ok_or(PictureError::Malformed)?)?;
        let selector = *segment.get(base).ok_or(PictureError::Malformed)?;
        let table_selector = *segment
            .get(checked_add(base, 1)?)
            .ok_or(PictureError::Malformed)?;
        let component_index = context.ids[..context.component_count]
            .iter()
            .position(|id| *id == selector)
            .ok_or(PictureError::Malformed)?;
        let dc_table = usize::from(table_selector >> 4);
        let ac_table = usize::from(table_selector & 0x0F);
        if dc_table >= 4 || ac_table >= 4 {
            return Err(PictureError::Malformed);
        }
        context.components[component_index].dc_table = dc_table;
        context.components[component_index].ac_table = ac_table;
    }
    Ok(())
}

fn validate_scan_tables(context: &FrameParseState) -> Result<(), PictureError> {
    for component in context.components.iter().take(context.component_count) {
        if !context.dc_tables[component.dc_table].present
            || !context.ac_tables[component.ac_table].present
        {
            return Err(PictureError::Malformed);
        }
    }
    Ok(())
}

fn build_frame(
    jpeg: &[u8],
    marker_position: usize,
    segment_length: usize,
    context: &mut FrameParseState,
) -> Result<Frame, PictureError> {
    let (mcu_columns, mcu_rows, blocks_per_mcu) = frame_geometry(context)?;
    let scan_start = checked_add(checked_add(marker_position, 2)?, segment_length)?;
    if scan_start > jpeg.len() {
        return Err(PictureError::Malformed);
    }
    let dc_tables = core::mem::replace(&mut context.dc_tables, Vec::new().into_boxed_slice());
    let ac_tables = core::mem::replace(&mut context.ac_tables, Vec::new().into_boxed_slice());
    Ok(Frame {
        scan_start,
        scan_end: find_scan_end(jpeg, scan_start),
        components: context.components,
        component_count: context.component_count,
        mcu_columns,
        mcu_rows,
        restart_interval: context.restart_interval,
        dc_tables,
        ac_tables,
        blocks_per_mcu,
    })
}

fn find_scan_end(jpeg: &[u8], start: usize) -> usize {
    let mut position = start;
    while jpeg.len().saturating_sub(position) >= 2 {
        if jpeg.get(position) == Some(&0xFF) {
            let Some(&next) = jpeg.get(position.saturating_add(1)) else {
                break;
            };
            if next != 0x00 && !(0xD0..=0xD7).contains(&next) {
                return position;
            }
        }
        position = position.saturating_add(1);
    }
    jpeg.len()
}
