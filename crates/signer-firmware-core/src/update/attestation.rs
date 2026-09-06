//! Pure ESP image-layout and human-readable attestation helpers.

pub const ESP_IMAGE_MAGIC: u8 = 0xE9;
pub const ESP_IMAGE_HEADER_SIZE: usize = 24;
pub const ESP_SEGMENT_HEADER_SIZE: usize = 8;
pub const ESP_IMAGE_MAX_SEGMENTS: u8 = 16;
pub const ESP_IMAGE_ALIGNMENT: u32 = 16;
pub const SECURE_BOOT_IMAGE_ALIGNMENT: u32 = 64 * 1024;
pub const SECURE_BOOT_SIGNATURE_MAGIC: u8 = 0xE7;
pub const SECURE_BOOT_SIGNATURE_VERSION: u8 = 0x02;
pub const SECURE_BOOT_SIGNATURE_PREFIX_SIZE: usize = 36;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageLayoutError {
    InvalidHeader,
    InvalidSegment,
    Overflow,
    MissingImageHash,
    InvalidSignatureBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EspImageHeader {
    pub segment_count: u8,
    pub hash_appended: bool,
}

pub fn parse_image_header(
    header: &[u8; ESP_IMAGE_HEADER_SIZE],
) -> Result<EspImageHeader, ImageLayoutError> {
    if header[0] != ESP_IMAGE_MAGIC || !(1..=ESP_IMAGE_MAX_SEGMENTS).contains(&header[1]) {
        return Err(ImageLayoutError::InvalidHeader);
    }
    if header[23] != 1 {
        return Err(ImageLayoutError::MissingImageHash);
    }
    Ok(EspImageHeader {
        segment_count: header[1],
        hash_appended: true,
    })
}

pub fn segment_data_len(header: &[u8; ESP_SEGMENT_HEADER_SIZE]) -> Result<u32, ImageLayoutError> {
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if length > 8 * 1024 * 1024 {
        return Err(ImageLayoutError::InvalidSegment);
    }
    Ok(length)
}

pub fn advance_segment(cursor: u32, data_len: u32) -> Result<u32, ImageLayoutError> {
    cursor
        .checked_add(ESP_SEGMENT_HEADER_SIZE as u32)
        .and_then(|value| value.checked_add(data_len))
        .ok_or(ImageLayoutError::Overflow)
}

pub fn appended_hash_offset(segment_end: u32) -> Result<u32, ImageLayoutError> {
    align_up(
        segment_end
            .checked_add(1)
            .ok_or(ImageLayoutError::Overflow)?,
        ESP_IMAGE_ALIGNMENT,
    )
}

pub fn signed_image_end(appended_hash_offset: u32) -> Result<u32, ImageLayoutError> {
    appended_hash_offset
        .checked_add(32)
        .ok_or(ImageLayoutError::Overflow)
}

pub fn secure_boot_signature_offset(image_end: u32) -> Result<u32, ImageLayoutError> {
    align_up(image_end, SECURE_BOOT_IMAGE_ALIGNMENT)
}

pub fn parse_signature_digest(
    prefix: &[u8; SECURE_BOOT_SIGNATURE_PREFIX_SIZE],
) -> Result<[u8; 32], ImageLayoutError> {
    if prefix[0] != SECURE_BOOT_SIGNATURE_MAGIC
        || prefix[1] != SECURE_BOOT_SIGNATURE_VERSION
        || prefix[2] != 0
        || prefix[3] != 0
    {
        return Err(ImageLayoutError::InvalidSignatureBlock);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&prefix[4..36]);
    Ok(digest)
}

pub fn attestation_words(hash: &[u8; 32]) -> [&'static str; 4] {
    let indices = [
        hash[0] >> 2,
        ((hash[0] & 0x03) << 4) | (hash[1] >> 4),
        ((hash[1] & 0x0f) << 2) | (hash[2] >> 6),
        hash[2] & 0x3f,
    ];
    [
        WORDS[indices[0] as usize],
        WORDS[indices[1] as usize],
        WORDS[indices[2] as usize],
        WORDS[indices[3] as usize],
    ]
}

fn align_up(value: u32, alignment: u32) -> Result<u32, ImageLayoutError> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(ImageLayoutError::Overflow)
}

const WORDS: [&str; 64] = [
    "amber", "anchor", "apple", "atlas", "bamboo", "beacon", "birch", "bison", "cactus", "cedar",
    "chisel", "cobalt", "coral", "crane", "delta", "ember", "falcon", "fern", "fjord", "flint",
    "forest", "frost", "garnet", "globe", "harbor", "hazel", "heron", "ivory", "jade", "juniper",
    "kestrel", "lagoon", "lantern", "maple", "marble", "mesa", "meteor", "mint", "nebula", "onyx",
    "opal", "orbit", "otter", "pearl", "pine", "quartz", "raven", "reef", "river", "sable", "sage",
    "solar", "spruce", "stone", "tiger", "topaz", "torch", "tulip", "umber", "valley", "walnut",
    "willow", "zephyr", "zinc",
];
