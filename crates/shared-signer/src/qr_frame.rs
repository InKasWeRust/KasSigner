//! Session-bound multi-frame QR wire format shared by signer and watcher.
//!
//! Frame layout:
//! `[magic:2][version:1][session:12][index:1][total:1][length:1][fragment]`.
//! The session identifier is a domain-separated SHA-256 digest prefix over the
//! entire payload and its exact length. Frames from another payload are rejected
//! without resetting the active assembly.

use sha2::{Digest, Sha256};

pub const FRAME_MAGIC: [u8; 2] = *b"KQ";
pub const FRAME_VERSION: u8 = 1;
pub const SESSION_ID_LEN: usize = 12;
pub const FRAME_HEADER_LEN: usize = 2 + 1 + SESSION_ID_LEN + 1 + 1 + 1;
pub const MIN_ENCODED_FRAME_LEN: usize = 20;
pub const MAX_FRAMES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    BufferTooSmall,
    InvalidHeader,
    InvalidIndex,
    InvalidLength,
    NonCanonicalPadding,
}

#[derive(Clone, Copy)]
pub struct ParsedFrame<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub frame_index: u8,
    pub total_frames: u8,
    pub fragment: &'a [u8],
}

#[must_use]
pub fn session_id(payload: &[u8]) -> [u8; SESSION_ID_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(b"KasSigner/multi-frame/v1");
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut identifier = [0u8; SESSION_ID_LEN];
    identifier.copy_from_slice(&digest[..SESSION_ID_LEN]);
    identifier
}

pub fn encode_frame(
    identifier: &[u8; SESSION_ID_LEN],
    frame_index: u8,
    total_frames: u8,
    fragment: &[u8],
    output: &mut [u8],
) -> Result<usize, FrameError> {
    if total_frames < 2
        || usize::from(total_frames) > MAX_FRAMES
        || frame_index >= total_frames
        || fragment.is_empty()
        || fragment.len() > u8::MAX as usize
    {
        return Err(FrameError::InvalidIndex);
    }
    let encoded_len = FRAME_HEADER_LEN
        .checked_add(fragment.len())
        .ok_or(FrameError::InvalidLength)?;
    let display_len = encoded_len.max(MIN_ENCODED_FRAME_LEN);
    if display_len > output.len() {
        return Err(FrameError::BufferTooSmall);
    }

    output[..display_len].fill(0);
    output[..2].copy_from_slice(&FRAME_MAGIC);
    output[2] = FRAME_VERSION;
    output[3..3 + SESSION_ID_LEN].copy_from_slice(identifier);
    output[3 + SESSION_ID_LEN] = frame_index;
    output[4 + SESSION_ID_LEN] = total_frames;
    output[5 + SESSION_ID_LEN] = fragment.len() as u8;
    output[FRAME_HEADER_LEN..encoded_len].copy_from_slice(fragment);
    Ok(display_len)
}

fn validate_frame_header(data: &[u8]) -> Result<(), FrameError> {
    if data.len() < FRAME_HEADER_LEN || data[..2] != FRAME_MAGIC {
        return Err(FrameError::InvalidHeader);
    }
    if data[2] != FRAME_VERSION {
        return Err(FrameError::InvalidHeader);
    }
    Ok(())
}

fn validate_frame_index(
    total_frames: u8,
    frame_index: u8,
    fragment_len: usize,
) -> Result<(), FrameError> {
    if total_frames < 2 || usize::from(total_frames) > MAX_FRAMES {
        return Err(FrameError::InvalidIndex);
    }
    if frame_index >= total_frames || fragment_len == 0 {
        return Err(FrameError::InvalidIndex);
    }
    Ok(())
}

pub fn parse_frame(data: &[u8]) -> Result<ParsedFrame<'_>, FrameError> {
    validate_frame_header(data)?;
    let mut identifier = [0u8; SESSION_ID_LEN];
    identifier.copy_from_slice(&data[3..3 + SESSION_ID_LEN]);
    let frame_index = data[3 + SESSION_ID_LEN];
    let total_frames = data[4 + SESSION_ID_LEN];
    let fragment_len = usize::from(data[5 + SESSION_ID_LEN]);
    validate_frame_index(total_frames, frame_index, fragment_len)?;
    let end = FRAME_HEADER_LEN
        .checked_add(fragment_len)
        .ok_or(FrameError::InvalidLength)?;
    if end > data.len() {
        return Err(FrameError::InvalidLength);
    }
    if data[end..].iter().any(|byte| *byte != 0) {
        return Err(FrameError::NonCanonicalPadding);
    }
    Ok(ParsedFrame {
        session_id: identifier,
        frame_index,
        total_frames,
        fragment: &data[FRAME_HEADER_LEN..end],
    })
}

#[must_use]
pub fn verify_session(payload: &[u8], expected: &[u8; SESSION_ID_LEN]) -> bool {
    session_id(payload) == *expected
}

#[must_use]
pub fn is_session_frame(data: &[u8]) -> bool {
    data.len() >= FRAME_HEADER_LEN && data[..2] == FRAME_MAGIC && data[2] == FRAME_VERSION
}
