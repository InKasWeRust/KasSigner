//! Canonical signed firmware-update manifest shared by host tooling and firmware.

use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"KSFU";
pub const SCHEMA_VERSION: u8 = 3;
pub const CHANNEL_PRODUCTION: u8 = 1;
pub const BOARD_M5STACK_CORES3: u8 = 1;
pub const BOARD_WAVESHARE: u8 = 2;
pub const BOARD_WAVESHARE_AF: u8 = 3;
pub const SIGNED_LEN: usize = 88;
pub const SIGNATURE_LEN: usize = 64;
pub const MANIFEST_LEN: usize = SIGNED_LEN + SIGNATURE_LEN;
pub const DOMAIN: &[u8] = b"KasSigner/FirmwareManifest/v3\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareUpdateManifest {
    pub schema: u8,
    pub board: u8,
    pub channel: u8,
    /// Human-facing package semantic version (MMmmpp encoding).
    pub version: u32,
    /// Monotonic ordinary release ordering. Independent of package SemVer.
    pub release_sequence: u32,
    /// Irreversible security rollback epoch mirrored into ESP32-S3 SECURE_VERSION.
    pub security_version: u32,
    pub image_size: u32,
    pub partition_layout_hash: [u8; 32],
    pub image_hash: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

impl FirmwareUpdateManifest {
    pub const fn empty() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            board: 0,
            channel: 0,
            version: 0,
            release_sequence: 0,
            security_version: 0,
            image_size: 0,
            partition_layout_hash: [0; 32],
            image_hash: [0; 32],
            signature: [0; SIGNATURE_LEN],
        }
    }

    pub fn signed_bytes(&self) -> [u8; SIGNED_LEN] {
        encode_signed_fields(self)
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        signing_digest(&self.signed_bytes())
    }

    pub fn encode(&self) -> [u8; MANIFEST_LEN] {
        let mut output = [0u8; MANIFEST_LEN];
        output[..SIGNED_LEN].copy_from_slice(&self.signed_bytes());
        output[SIGNED_LEN..].copy_from_slice(&self.signature);
        output
    }
}

pub fn parse(input: &[u8]) -> Option<FirmwareUpdateManifest> {
    if input.len() != MANIFEST_LEN || input[..4] != MAGIC {
        return None;
    }
    if input[4] != SCHEMA_VERSION || input[7] != 0 {
        return None;
    }
    let mut manifest = FirmwareUpdateManifest::empty();
    manifest.schema = input[4];
    manifest.board = input[5];
    manifest.channel = input[6];
    manifest.version = read_u32_exact(input, 8);
    manifest.release_sequence = read_u32_exact(input, 12);
    manifest.security_version = read_u32_exact(input, 16);
    manifest.image_size = read_u32_exact(input, 20);
    manifest
        .partition_layout_hash
        .copy_from_slice(&input[24..56]);
    manifest.image_hash.copy_from_slice(&input[56..88]);
    manifest.signature.copy_from_slice(&input[88..152]);
    Some(manifest)
}

pub fn signing_digest(signed_fields: &[u8; SIGNED_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(signed_fields);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn encode_signed_fields(manifest: &FirmwareUpdateManifest) -> [u8; SIGNED_LEN] {
    let mut output = [0u8; SIGNED_LEN];
    output[..4].copy_from_slice(&MAGIC);
    output[4] = SCHEMA_VERSION;
    output[5] = manifest.board;
    output[6] = manifest.channel;
    output[7] = 0;
    output[8..12].copy_from_slice(&manifest.version.to_le_bytes());
    output[12..16].copy_from_slice(&manifest.release_sequence.to_le_bytes());
    output[16..20].copy_from_slice(&manifest.security_version.to_le_bytes());
    output[20..24].copy_from_slice(&manifest.image_size.to_le_bytes());
    output[24..56].copy_from_slice(&manifest.partition_layout_hash);
    output[56..88].copy_from_slice(&manifest.image_hash);
    output
}

fn read_u32_exact(input: &[u8], offset: usize) -> u32 {
    // parse() has already required MANIFEST_LEN, and all four offsets are fixed
    // inside SIGNED_LEN. Indexing cannot fail here, so an Option/try_into path
    // only created unreachable host-coverage branches.
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}
