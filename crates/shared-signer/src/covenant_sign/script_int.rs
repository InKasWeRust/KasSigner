//! Canonical non-negative ScriptInt parsing used by Known covenant validators.

pub(super) fn canonical_u64_push(push: &[u8]) -> bool {
    if push == [0x00] {
        return true;
    }
    if push.len() == 1 {
        return (0x51..=0x60).contains(&push[0]);
    }
    let Some((&length, data)) = push.split_first() else {
        return false;
    };
    canonical_u64_push_data(usize::from(length), data)
}

fn canonical_u64_push_data(length: usize, data: &[u8]) -> bool {
    if !(1..=9).contains(&length) || data.len() != length {
        return false;
    }
    let Some(significant) = canonical_positive_u64_bytes(data) else {
        return false;
    };
    if significant.len() > 8 {
        return false;
    }
    decode_script_u64(significant) > 16
}

fn canonical_positive_u64_bytes(data: &[u8]) -> Option<&[u8]> {
    let (&last, prefix) = data.split_last()?;
    if last == 0 {
        let &previous = prefix.last()?;
        return (previous & 0x80 != 0).then_some(prefix);
    }
    (last & 0x80 == 0).then_some(data)
}

fn decode_script_u64(data: &[u8]) -> u64 {
    data.iter().enumerate().fold(0u64, |acc, (index, byte)| {
        acc | (u64::from(*byte) << (index * 8))
    })
}
