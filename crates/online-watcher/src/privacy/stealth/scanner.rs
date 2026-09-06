pub fn scan_raw_for_preimage(raw: &[u8], transaction_id: &[u8]) -> Option<Vec<u8>> {
    if !scan_input_valid(raw, transaction_id) {
        return None;
    }
    for position in 4..raw.len().saturating_sub(50) {
        let Some(script) = candidate_script(raw, transaction_id, position) else {
            continue;
        };
        if let Some(preimage) = first_push(script) {
            return Some(preimage.to_vec());
        }
    }
    None
}

fn scan_input_valid(raw: &[u8], transaction_id: &[u8]) -> bool {
    transaction_id.len() == 32 && raw.len() >= 50
}

fn candidate_script<'a>(raw: &'a [u8], transaction_id: &[u8], position: usize) -> Option<&'a [u8]> {
    if !candidate_outpoint_matches(raw, transaction_id, position) {
        return None;
    }
    script_after_outpoint(raw, position)
}

fn candidate_outpoint_matches(raw: &[u8], transaction_id: &[u8], position: usize) -> bool {
    raw[position] == 1
        && &raw[position + 1..position + 33] == transaction_id
        && read_u32_length(raw, position - 4) == Some(37)
}

fn script_after_outpoint(raw: &[u8], position: usize) -> Option<&[u8]> {
    let after_outpoint = position.checked_add(37)?;
    let script_length = read_u32_length(raw, after_outpoint)?;
    if !(10..=1000).contains(&script_length) {
        return None;
    }
    let script_start = after_outpoint.checked_add(4)?;
    let script_end = script_start.checked_add(script_length)?;
    raw.get(script_start..script_end)
}

fn read_u32_length(bytes: &[u8], start: usize) -> Option<usize> {
    let end = start.checked_add(4)?;
    let encoded = u32::from_le_bytes(bytes.get(start..end)?.try_into().ok()?);
    usize::try_from(encoded).ok()
}

pub(super) fn first_push(script: &[u8]) -> Option<&[u8]> {
    let (start, length) = push_bounds(script)?;
    if !valid_push_length(length) {
        return None;
    }
    script.get(start..start.checked_add(length)?)
}

fn push_bounds(script: &[u8]) -> Option<(usize, usize)> {
    let opcode = *script.first()?;
    match opcode {
        1..=0x4b => Some((1usize, usize::from(opcode))),
        0x4c => Some((2usize, usize::from(*script.get(1)?))),
        0x4d => Some((
            3usize,
            usize::from(u16::from_le_bytes([*script.get(1)?, *script.get(2)?])),
        )),
        _ => None,
    }
}

fn valid_push_length(length: usize) -> bool {
    (1..=200).contains(&length)
}
