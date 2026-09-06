#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupError {
    InvalidFormat,
    UnsupportedFormat,
    WrongPurpose,
    InvalidLength,
    InvalidCredential,
    EntropyUnavailable,
    DeviceKeyUnavailable,
    EncryptionFailed,
    AuthenticationFailed,
    BufferTooSmall,
    InvalidMnemonic,
}

impl BackupError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidFormat => "Invalid backup format",
            Self::UnsupportedFormat => "Unsupported backup format",
            Self::WrongPurpose => "Wrong backup type",
            Self::InvalidLength => "Invalid backup length",
            Self::InvalidCredential => "Password needs 8+ chars, letter + number",
            Self::EntropyUnavailable => "Hardware RNG failed",
            Self::DeviceKeyUnavailable => "Device-bound backup key unavailable",
            Self::EncryptionFailed => "Backup encryption failed",
            Self::AuthenticationFailed => "Wrong password/device or damaged backup",
            Self::BufferTooSmall => "Backup buffer too small",
            Self::InvalidMnemonic => "Invalid mnemonic backup",
        }
    }
}
