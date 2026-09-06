//! Untrusted BIP32 derivation-hint extraction for multisig PSKT fields.

use crate::transaction::model::Ms45Hint;

/// Extract the v1.0.6 45' trailing `cosigner/chain/index` search hint from a
/// validated PSKT KeySource value. The hint is never authoritative: signing
/// still derives and matches the redeem script before using a key.
pub(super) fn extract_ms45_hint(src: &[u8], start: usize, end: usize) -> Option<Ms45Hint> {
    let region = src.get(start..end)?;
    parse_ms45_path(find_derivation_path(region)?)
}

fn find_derivation_path(region: &[u8]) -> Option<&[u8]> {
    let needle = b"\"derivationPath\"";
    let offset = find_subslice(region, needle)?;
    // `offset` came from a successful match of `needle`, so this slice start is
    // provably inside `region`; keeping a second checked get only created an
    // unreachable host-coverage branch.
    let tail = &region[offset + needle.len()..];
    let quote = find_byte(tail, b'"')?;
    if find_delimiter(&tail[..quote]).is_some() {
        return None;
    }
    // `quote` and `end_quote` are positions returned from these exact slices.
    // Direct slicing preserves the same semantics without redundant Option
    // branches that cannot fail after the successful searches above.
    let value = &tail[quote + 1..];
    let end_quote = find_byte(value, b'"')?;
    Some(&value[..end_quote])
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn find_byte(bytes: &[u8], target: u8) -> Option<usize> {
    bytes.iter().position(|byte| *byte == target)
}

fn find_delimiter(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|byte| matches!(*byte, b',' | b'}'))
}

fn parse_ms45_path(path: &[u8]) -> Option<Ms45Hint> {
    let tail = path.strip_prefix(b"m/45'/111111'/0'/")?;
    let mut components = tail.split(|byte| *byte == b'/');
    let cosigner = parse_soft_decimal(components.next()?)?;
    let chain = parse_soft_decimal(components.next()?)?;
    let index = parse_soft_decimal(components.next()?)?;
    if components.next().is_some() || chain > 1 {
        return None;
    }
    Some(Ms45Hint {
        present: true,
        cosigner,
        chain,
        index,
    })
}

fn parse_soft_decimal(component: &[u8]) -> Option<u32> {
    let value = core::str::from_utf8(component).ok()?.parse::<u32>().ok()?;
    (value < 0x8000_0000).then_some(value)
}

#[cfg(test)]
mod unit_tests;
