// features/fw_update.rs — Firmware update parsing and verification
// 100% Rust, no-std, no-alloc
//
// Verifies firmware update images before flashing.
// The developer signs SHA256(firmware_binary) with a Schnorr key.
// KasSigner scans the signature + version via QR, verifies against
// the hardcoded developer public key, and confirms the update is authentic.
//
// Update flow:
//   1. Developer builds firmware, computes SHA256 hash
//   2. Developer signs hash with Schnorr private key
//   3. Developer publishes: firmware.bin + update QR containing:
//      [KSFU magic][version_u32][hash_32B][signature_64B] = 104 bytes
//   4. User copies firmware.bin to SD card
//   5. User scans update QR with KasSigner
//   6. KasSigner reads firmware.bin from SD, computes SHA256
//   7. KasSigner verifies: schnorr_verify(DEV_PUBKEY, computed_hash, signature)
//   8. If valid AND version > current: prompt user to confirm
//   9. Device reboots into espflash bootloader mode for USB flash
//      (or: mark update partition for next boot — future OTA)


use sha2::{Sha256, Digest};

/// Magic bytes for firmware update QR: "KSFU" (KasSigner Firmware Update)
pub const UPDATE_MAGIC: [u8; 4] = [0x4B, 0x53, 0x46, 0x55];

/// Developer public key (x-only Schnorr, 32 bytes)
/// Developer public key for firmware signature verification
pub const DEV_PUBKEY: [u8; 32] = [
    0xf5, 0x7f, 0x09, 0xaf, 0xf8, 0xd0, 0x6b, 0x3f, 0x24, 0xc8, 0xb3, 0xf9, 0xc0, 0xc9, 0x91, 0xca, 0x6b, 0x43, 0xe9, 0xa6, 0x8e, 0xf8, 0xbe, 0x3a, 0x91, 0x7b, 0x62, 0x88, 0x30, 0x80, 0xf7, 0xf3
];

/// Current firmware version (incremented each release)
pub const CURRENT_VERSION: u32 = 10000; // v1.0.0 = 10000

/// Parsed firmware update QR data
#[derive(Debug)]
pub struct FirmwareUpdate {
    pub version: u32,
    pub hash: [u8; 32],
    pub signature: [u8; 64],
    pub valid: bool,
}

impl FirmwareUpdate {
        /// Create an empty (invalid) firmware update record.
pub const fn empty() -> Self {
        Self {
            version: 0,
            hash: [0u8; 32],
            signature: [0u8; 64],
            valid: false,
        }
    }
}

/// Parse a firmware update QR payload.
/// Format: [KSFU(4B)][version(4B LE)][hash(32B)][signature(64B)] = 104 bytes
pub fn parse_update_qr(data: &[u8]) -> Option<FirmwareUpdate> {
    if data.len() < 104 { return None; }
    if &data[0..4] != &UPDATE_MAGIC { return None; }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut update = FirmwareUpdate::empty();
    update.version = version;
    update.hash.copy_from_slice(&data[8..40]);
    update.signature.copy_from_slice(&data[40..104]);

    Some(update)
}

/// Verify a firmware update against the developer public key.
/// 1. Check version > current
/// 2. Verify Schnorr signature of the hash
///
/// Returns true if signature is valid and version is newer.
pub fn verify_update(update: &FirmwareUpdate) -> bool {
    // Version must be strictly newer
    if update.version <= CURRENT_VERSION {
        return false;
    }

    // Verify Schnorr signature: sign(DEV_PRIVKEY, hash) should verify with DEV_PUBKEY
    let sig = crate::wallet::schnorr::SchnorrSignature { bytes: update.signature };
    match crate::wallet::schnorr::schnorr_verify(&DEV_PUBKEY, &update.hash, &sig) {
        Ok(()) => true,
        Err(_) => false,
    }
}

/// Compute SHA256 hash of firmware data (read from SD card in chunks).
/// For streaming hash: call init, update with chunks, finalize.
pub struct FirmwareHasher {
    hasher: Sha256,
    bytes_hashed: usize,
}

impl FirmwareHasher {
        /// Parse firmware update header from raw bytes.
pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes_hashed: 0,
        }
    }

    /// Feed a chunk of firmware data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_hashed += data.len();
    }

    /// Finalize and return the SHA256 hash
    pub fn finalize(self) -> ([u8; 32], usize) {
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        (hash, self.bytes_hashed)
    }
}

/// Verify a firmware binary on SD card against an update QR.
/// Reads the file in 512-byte chunks, computes SHA256, compares with update.hash.
///
/// Returns true if the computed hash matches the signed hash.
pub fn verify_firmware_hash(computed_hash: &[u8; 32], update: &FirmwareUpdate) -> bool {
    computed_hash == &update.hash
}

/// Format a version number as human-readable string.
/// 10000 -> "1.0.0", 10100 -> "1.1.0", 10101 -> "1.1.1"
pub fn format_version(version: u32, buf: &mut [u8]) -> usize {
    let major = version / 10000;
    let minor = (version % 10000) / 100;
    let patch = version % 100;

    let mut pos = 0;
    pos += write_u32(major, &mut buf[pos..]);
    if pos < buf.len() { buf[pos] = b'.'; pos += 1; }
    pos += write_u32(minor, &mut buf[pos..]);
    if pos < buf.len() { buf[pos] = b'.'; pos += 1; }
    pos += write_u32(patch, &mut buf[pos..]);
    pos
}

fn write_u32(mut val: u32, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut digits = [0u8; 10];
    let mut count = 0;
    while val > 0 {
        digits[count] = b'0' + (val % 10) as u8;
        val /= 10;
        count += 1;
    }
    let written = count.min(buf.len());
    for i in 0..written {
        buf[i] = digits[count - 1 - i];
    }
    written
}
