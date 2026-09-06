use crate::protocol::script::walk::item_end;

#[cfg(test)]
use crate::protocol::pskt::model::KsptSigRecord;

#[cfg(test)]
use super::parse_compact_kspt_transaction;

#[cfg(test)]
pub(crate) fn parse_compact_kspt_signatures(
    data: &[u8],
) -> Result<Vec<Vec<KsptSigRecord>>, String> {
    parse_compact_kspt_transaction(data).map(|transaction| {
        transaction
            .inputs
            .into_iter()
            .map(|input| {
                input
                    .signatures
                    .into_iter()
                    .map(|signature| KsptSigRecord {
                        pubkey_pos: signature.pubkey_pos,
                        sighash_type: signature.sighash_type,
                        sig: signature.signature,
                    })
                    .collect()
            })
            .collect()
    })
}

fn copy_xonly(script: &[u8], start: usize) -> Option<[u8; 32]> {
    let end = start.checked_add(32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(script.get(start..end)?);
    Some(key)
}

fn standard_multisig_key_count(script: &[u8]) -> Option<usize> {
    if script.last() != Some(&0xae) {
        return None;
    }
    let threshold = *script.first()?;
    let key_count_opcode = *script.get(script.len().checked_sub(2)?)?;
    if !(0x51..=0x60).contains(&threshold) {
        return None;
    }
    if !(0x51..=0x60).contains(&key_count_opcode) {
        return None;
    }
    let key_count = usize::from(key_count_opcode - 0x50);
    let expected_len = 3usize.checked_add(key_count.checked_mul(33)?)?;
    (script.len() == expected_len).then_some(key_count)
}

fn standard_multisig_xonly(script: &[u8], position: u8) -> Option<[u8; 32]> {
    let key_count = standard_multisig_key_count(script)?;
    let position = usize::from(position);
    if position >= key_count {
        return None;
    }
    let start = 2usize.checked_add(position.checked_mul(33)?)?;
    copy_xonly(script, start)
}

fn checksig_follows(script: &[u8], offset: usize) -> bool {
    matches!(script.get(offset), Some(0xac | 0xad))
        || matches!(script.get(offset.saturating_add(1)), Some(0xac | 0xad))
}

fn covenant_xonly(script: &[u8], position: u8) -> Option<[u8; 32]> {
    let mut key_index = 0u8;
    let mut offset = 0usize;
    for _ in 0..script.len() {
        let opcode = *script.get(offset)?;
        let next = item_end(script, offset)?;
        if opcode == 0x20 && checksig_follows(script, next) {
            if key_index == position {
                return copy_xonly(script, offset.checked_add(1)?);
            }
            key_index = key_index.saturating_add(1);
        }
        offset = next;
    }
    None
}

pub(crate) fn xonly_at_position(script: &[u8], position: u8) -> Option<[u8; 32]> {
    standard_multisig_xonly(script, position).or_else(|| covenant_xonly(script, position))
}
