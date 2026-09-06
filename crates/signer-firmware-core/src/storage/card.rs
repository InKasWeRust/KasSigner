//! Pure SD-card protocol decisions shared by board transports.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardKind {
    V1,
    V2Standard,
    V2HighCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardState {
    Standby,
    Transfer,
    Other,
}

pub const fn classify_card_kind(sd_v2: bool, ocr: u32) -> CardKind {
    if !sd_v2 {
        CardKind::V1
    } else if ocr & (1 << 30) != 0 {
        CardKind::V2HighCapacity
    } else {
        CardKind::V2Standard
    }
}

pub fn map_card_kind<T: Copy>(kind: CardKind, v1: T, v2_standard: T, v2_high_capacity: T) -> T {
    match kind {
        CardKind::V1 => v1,
        CardKind::V2Standard => v2_standard,
        CardKind::V2HighCapacity => v2_high_capacity,
    }
}

pub fn decode_card_type_code<T: Copy>(
    code: u8,
    v1: T,
    v2_standard: T,
    v2_high_capacity: T,
) -> Option<T> {
    match code {
        1 => Some(v1),
        2 => Some(v2_standard),
        3 => Some(v2_high_capacity),
        _ => None,
    }
}

pub const fn classify_card_state(status: u32) -> CardState {
    match (status >> 9) & 0x0f {
        3 => CardState::Standby,
        4 => CardState::Transfer,
        _ => CardState::Other,
    }
}

pub const fn command_frame(command: u8, argument: u32) -> [u8; 5] {
    [
        0x40 | command,
        (argument >> 24) as u8,
        (argument >> 16) as u8,
        (argument >> 8) as u8,
        argument as u8,
    ]
}

/// Return the card capacity as 512-byte logical sectors from a 16-byte CSD.
/// Supports CSD v1 (SDSC) and CSD v2 (SDHC/SDXC). SDUC CSD v3 requires a
/// wider host addressing contract and is rejected here.
pub fn csd_sector_count(csd: &[u8; 16]) -> Result<u32, &'static str> {
    match csd[0] >> 6 {
        0 => csd_v1_sector_count(csd),
        1 => csd_v2_sector_count(csd),
        _ => Err("Unsupported SD CSD structure"),
    }
}

fn csd_v2_sector_count(csd: &[u8; 16]) -> Result<u32, &'static str> {
    let c_size = (u32::from(csd[7] & 0x3f) << 16) | (u32::from(csd[8]) << 8) | u32::from(csd[9]);
    c_size
        .checked_add(1)
        .and_then(|value| value.checked_mul(1024))
        .ok_or("SDHC capacity overflow")
}

fn csd_v1_sector_count(csd: &[u8; 16]) -> Result<u32, &'static str> {
    let read_bl_len = u32::from(csd[5] & 0x0f);
    let c_size =
        (u32::from(csd[6] & 0x03) << 10) | (u32::from(csd[7]) << 2) | u32::from(csd[8] >> 6);
    let c_size_mult = (u32::from(csd[9] & 0x03) << 1) | u32::from(csd[10] >> 7);
    let block_len = 1u64
        .checked_shl(read_bl_len)
        .ok_or("SDSC block length overflow")?;
    let multiplier = 1u64
        .checked_shl(c_size_mult + 2)
        .ok_or("SDSC multiplier overflow")?;
    let bytes = u64::from(c_size + 1)
        .checked_mul(multiplier)
        .and_then(|value| value.checked_mul(block_len))
        .ok_or("SDSC capacity overflow")?;
    let sectors = bytes / 512;
    u32::try_from(sectors).map_err(|_| "SDSC sector count overflow")
}
