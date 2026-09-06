use super::number::next_script_item;

pub(crate) fn item_end(script: &[u8], offset: usize) -> Option<usize> {
    script.get(offset).and_then(|opcode| {
        next_script_item(script, offset, *opcode)
            .ok()
            .map(|(next, _)| next)
    })
}

pub(crate) fn contains_opcode_pair(script: &[u8], first: u8, second: u8) -> bool {
    let mut offset = 0usize;
    for _ in 0..script.len() {
        let Some(&opcode) = script.get(offset) else {
            return false;
        };
        if opcode == first && script.get(offset.saturating_add(1)) == Some(&second) {
            return true;
        }
        let Some(next) = item_end(script, offset) else {
            return false;
        };
        offset = next;
    }
    false
}
