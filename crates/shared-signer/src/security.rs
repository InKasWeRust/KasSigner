//! Cross-host/device security invariants that belong to shared wire/session handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSessionError {
    MixedSession,
    TotalChanged,
}

pub fn authorize_frame_session<const N: usize>(
    active: bool,
    active_session: &[u8; N],
    active_total: u8,
    incoming_session: &[u8; N],
    incoming_total: u8,
) -> Result<(), FrameSessionError> {
    if !active {
        return Ok(());
    }
    if active_session != incoming_session {
        return Err(FrameSessionError::MixedSession);
    }
    if active_total != incoming_total {
        return Err(FrameSessionError::TotalChanged);
    }
    Ok(())
}
