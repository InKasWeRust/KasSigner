use crate::security::{authorize_frame_session, FrameSessionError};

#[test]
fn frame_session_authorization_rejects_mixing_and_total_changes() {
    let first = [1u8; 12];
    let second = [2u8; 12];
    assert_eq!(
        authorize_frame_session(false, &first, 0, &second, 4),
        Ok(())
    );
    assert_eq!(authorize_frame_session(true, &first, 4, &first, 4), Ok(()));
    assert_eq!(
        authorize_frame_session(true, &first, 4, &second, 4),
        Err(FrameSessionError::MixedSession)
    );
    assert_eq!(
        authorize_frame_session(true, &first, 4, &first, 5),
        Err(FrameSessionError::TotalChanged)
    );
}
