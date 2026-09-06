use super::FirmwareInfo;
// Display formatting and version helpers.

impl FirmwareInfo {
    /// Get the expected firmware hash for display.
    pub fn get_display_hash(&self) -> [u8; 32] {
        self.expected_hash
    }

    /// Convert a 32-byte hash to a 64-bit (16-hex-character) verification code.
    pub fn hash_to_hex_short(&self, hash: &[u8; 32]) -> heapless::String<16> {
        use core::fmt::Write;
        let mut s = heapless::String::new();
        for byte in &hash[0..8] {
            write!(&mut s, "{byte:02x}").unwrap_or(());
        }
        s
    }

    /// Convert a 32-byte digest to the complete 64-character SHA-256 string.
    #[cfg(feature = "production")]
    pub fn hash_to_hex_full(&self, hash: &[u8; 32]) -> heapless::String<64> {
        use core::fmt::Write;
        let mut s = heapless::String::new();
        for byte in hash {
            write!(&mut s, "{byte:02x}").unwrap_or(());
        }
        s
    }

    /// Four-word, 24-bit visual checksum derived from the signed-image digest.
    #[cfg(feature = "production")]
    pub fn attestation_phrase(&self, hash: &[u8; 32]) -> heapless::String<48> {
        use core::fmt::Write;
        let words = signer_firmware_core::update::attestation::attestation_words(hash);
        let mut s = heapless::String::new();
        write!(&mut s, "{} {} {} {}", words[0], words[1], words[2], words[3]).unwrap_or(());
        s
    }

    /// Format the firmware version as a "major.minor.patch" string.
    pub fn version_string(&self) -> heapless::String<16> {
        use core::fmt::Write;
        let mut s = heapless::String::new();
        write!(
            &mut s,
            "{}.{}.{}",
            self.version_major, self.version_minor, self.version_patch
        )
        .unwrap_or(());
        s
    }
}
