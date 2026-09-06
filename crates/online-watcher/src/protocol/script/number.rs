use super::opcode;

pub fn push_int(script: &mut Vec<u8>, value: u64) {
    if value == 0 {
        script.push(opcode::OP_0);
        return;
    }
    if value <= 16 {
        script.push(0x50 + value as u8);
        return;
    }

    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    script.push(u8::try_from(bytes.len()).expect("u64 script integers use at most 9 bytes"));
    script.extend_from_slice(&bytes);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScriptItem {
    Opcode,
    Integer(u64),
    OversizedInteger,
}

#[must_use]
fn read_script_int(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[..data.len()].copy_from_slice(data);
    u64::from_le_bytes(bytes)
}

fn classify_push(data: &[u8]) -> ScriptItem {
    if data.len() > 8 {
        ScriptItem::OversizedInteger
    } else {
        ScriptItem::Integer(read_script_int(data))
    }
}

fn read_push_item(
    script: &[u8],
    start: usize,
    length: usize,
    truncated_message: &'static str,
) -> Result<(usize, ScriptItem), String> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let data = script
        .get(start..end)
        .ok_or_else(|| truncated_message.to_string())?;
    Ok((end, classify_push(data)))
}

pub(super) fn read_pushdata1(
    script: &[u8],
    position: usize,
) -> Result<(usize, ScriptItem), String> {
    let length_position = position
        .checked_add(1)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let length = *script
        .get(length_position)
        .ok_or_else(|| "Truncated OP_PUSHDATA1 length".to_string())? as usize;
    let start = position
        .checked_add(2)
        .ok_or_else(|| "Script position overflow".to_string())?;
    read_push_item(script, start, length, "Truncated OP_PUSHDATA1 data")
}

pub(super) fn read_pushdata2(
    script: &[u8],
    position: usize,
) -> Result<(usize, ScriptItem), String> {
    let start = position
        .checked_add(1)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let end = start
        .checked_add(2)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let bytes = script
        .get(start..end)
        .ok_or_else(|| "Truncated OP_PUSHDATA2 length".to_string())?;
    let length = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    read_push_item(script, end, length, "Truncated OP_PUSHDATA2 data")
}

fn read_pushdata4(script: &[u8], position: usize) -> Result<(usize, ScriptItem), String> {
    let start = position
        .checked_add(1)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let end = start
        .checked_add(4)
        .ok_or_else(|| "Script position overflow".to_string())?;
    let bytes = script
        .get(start..end)
        .ok_or_else(|| "Truncated OP_PUSHDATA4 length".to_string())?;
    let length = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    read_push_item(script, end, length, "Truncated OP_PUSHDATA4 data")
}

fn next_position(position: usize, amount: usize, script_len: usize) -> Result<usize, String> {
    let next = position
        .checked_add(amount)
        .ok_or_else(|| "Script position overflow".to_string())?;
    if next <= position || next > script_len {
        return Err("Truncated script item".to_string());
    }
    Ok(next)
}

fn next_pushdata_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if opcode == 0x4c {
        read_pushdata1(script, position)
    } else {
        next_wide_pushdata_item(script, position, opcode)
    }
}

fn next_wide_pushdata_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if opcode == 0x4d {
        read_pushdata2(script, position)
    } else {
        read_pushdata4(script, position)
    }
}

fn next_push_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if opcode <= 0x4b {
        let start = position
            .checked_add(1)
            .ok_or_else(|| "Script position overflow".to_string())?;
        read_push_item(
            script,
            start,
            opcode as usize,
            "Truncated direct script push",
        )
    } else {
        next_pushdata_item(script, position, opcode)
    }
}

fn next_zero_or_push_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if opcode == 0x00 {
        Ok((
            next_position(position, 1, script.len())?,
            ScriptItem::Integer(0),
        ))
    } else {
        next_push_item(script, position, opcode)
    }
}

fn next_non_push_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if (0x51..=0x60).contains(&opcode) {
        Ok((
            next_position(position, 1, script.len())?,
            ScriptItem::Integer((opcode - 0x50) as u64),
        ))
    } else {
        Ok((
            next_position(position, 1, script.len())?,
            ScriptItem::Opcode,
        ))
    }
}

pub(super) fn next_script_item(
    script: &[u8],
    position: usize,
    opcode: u8,
) -> Result<(usize, ScriptItem), String> {
    if opcode <= 0x4e {
        next_zero_or_push_item(script, position, opcode)
    } else {
        next_non_push_item(script, position, opcode)
    }
}

pub(super) fn find_preceding_script_integer(
    script: &[u8],
    target_opcode: u8,
) -> Result<Option<u64>, String> {
    let mut position = 0usize;
    let mut previous = ScriptItem::Opcode;
    for _ in 0..script.len() {
        let Some(&current_opcode) = script.get(position) else {
            return Ok(None);
        };
        if current_opcode == target_opcode {
            return match previous {
                ScriptItem::Integer(value) => Ok(Some(value)),
                ScriptItem::OversizedInteger => Err("Script integer exceeds 8 bytes".to_string()),
                ScriptItem::Opcode => Ok(None),
            };
        }
        let (next, item) = next_script_item(script, position, current_opcode)?;
        previous = item;
        position = next;
    }
    if position >= script.len() {
        Ok(None)
    } else {
        Err("Script walker exceeded item bound".to_string())
    }
}
