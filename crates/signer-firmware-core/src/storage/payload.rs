//! Pure SD-import payload classification.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedPayload {
    CovenantBackup { trimmed_len: usize },
    PlainXprv { trimmed_len: usize },
    PlainPrivateKey { trimmed_len: usize },
    Unknown { trimmed_len: usize },
}

impl DetectedPayload {
    pub const fn trimmed_len(self) -> usize {
        match self {
            Self::CovenantBackup { trimmed_len }
            | Self::PlainXprv { trimmed_len }
            | Self::PlainPrivateKey { trimmed_len }
            | Self::Unknown { trimmed_len } => trimmed_len,
        }
    }
}

pub fn detect_payload(buffer: &[u8], original_len: usize) -> DetectedPayload {
    let trimmed_len = trimmed_length(buffer, original_len);
    classify(&buffer[..trimmed_len], trimmed_len)
}

fn trimmed_length(buffer: &[u8], original_len: usize) -> usize {
    let mut length = original_len.min(buffer.len());
    while length > 0 && matches!(buffer[length - 1], b'\n' | b'\r' | b' ' | 0) {
        length -= 1;
    }
    length
}

fn classify(content: &[u8], trimmed_len: usize) -> DetectedPayload {
    if content.starts_with(b"COVB") || content.starts_with(b"COVI") {
        DetectedPayload::CovenantBackup { trimmed_len }
    } else if content.starts_with(b"xprv") {
        DetectedPayload::PlainXprv { trimmed_len }
    } else if trimmed_len == 64 {
        DetectedPayload::PlainPrivateKey { trimmed_len }
    } else {
        DetectedPayload::Unknown { trimmed_len }
    }
}
