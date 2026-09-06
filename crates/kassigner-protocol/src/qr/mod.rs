use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, ProtocolResult};

const MAX_FRAME_DATA: usize = crate::capabilities::QR_MULTI_FRAME_FRAGMENT_BYTES;
const SINGLE_FRAME_PAYLOAD: usize = crate::capabilities::QR_SINGLE_FRAME_PAYLOAD_BYTES;
const MAX_FRAMES: usize = shared_signer::qr_frame::MAX_FRAMES;

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrFrame {
    pub index: u8,
    pub total: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frames(payload: &[u8]) -> ProtocolResult<Vec<QrFrame>> {
    if payload.is_empty() {
        return Err(ProtocolError::qr("empty QR payload"));
    }
    if payload.len() <= SINGLE_FRAME_PAYLOAD {
        return Ok(vec![QrFrame {
            index: 0,
            total: 1,
            payload: payload.to_vec(),
        }]);
    }
    let total_frames = payload.len().div_ceil(MAX_FRAME_DATA);
    if total_frames > MAX_FRAMES {
        return Err(ProtocolError::qr(format!(
            "QR payload too large: {} bytes ({} frames, max {})",
            payload.len(),
            total_frames,
            MAX_FRAMES
        )));
    }
    let chunk_size = payload.len().div_ceil(total_frames);
    let total =
        u8::try_from(total_frames).map_err(|_| ProtocolError::qr("QR frame count exceeds u8"))?;
    let session_id = shared_signer::qr_frame::session_id(payload);
    let mut frames = Vec::with_capacity(total_frames);
    for index in 0..total_frames {
        let start = index * chunk_size;
        let end = (start + chunk_size).min(payload.len());
        let mut wire = [0u8; 134];
        let length = shared_signer::qr_frame::encode_frame(
            &session_id,
            u8::try_from(index).map_err(|_| ProtocolError::qr("QR frame index exceeds u8"))?,
            total,
            &payload[start..end],
            &mut wire,
        )
        .map_err(|error| ProtocolError::qr(format!("QR frame encoding failed: {error:?}")))?;
        frames.push(QrFrame {
            index: index as u8,
            total,
            payload: wire[..length].to_vec(),
        });
    }
    Ok(frames)
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrProgress {
    pub total: u8,
    pub received: u8,
    pub bits: Vec<bool>,
}

pub struct QrDecoder {
    session_id: [u8; shared_signer::qr_frame::SESSION_ID_LEN],
    session_active: bool,
    total_frames: u8,
    received: [bool; MAX_FRAMES],
    fragments: [Vec<u8>; MAX_FRAMES],
}

impl Default for QrDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QrDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_id: [0; shared_signer::qr_frame::SESSION_ID_LEN],
            session_active: false,
            total_frames: 0,
            received: [false; MAX_FRAMES],
            fragments: core::array::from_fn(|_| Vec::new()),
        }
    }

    pub fn reset(&mut self) {
        self.session_id.fill(0);
        self.session_active = false;
        self.total_frames = 0;
        self.received.fill(false);
        for fragment in &mut self.fragments {
            fragment.clear();
        }
    }

    #[must_use]
    pub fn progress(&self) -> QrProgress {
        let total = usize::from(self.total_frames);
        let bits = self.received[..total].to_vec();
        let received = bits
            .iter()
            .filter(|value| **value)
            .count()
            .min(u8::MAX as usize) as u8;
        QrProgress {
            total: self.total_frames,
            received,
            bits,
        }
    }

    pub fn accept(&mut self, payload: &[u8]) -> ProtocolResult<Option<Vec<u8>>> {
        if !shared_signer::qr_frame::is_session_frame(payload) {
            return self.accept_raw(payload);
        }
        let frame = shared_signer::qr_frame::parse_frame(payload)
            .map_err(|error| ProtocolError::qr(format!("invalid multi-frame QR: {error:?}")))?;
        self.accept_session(frame.session_id, frame.total_frames)?;
        let index = usize::from(frame.frame_index);
        if self.received[index] {
            if self.fragments[index].as_slice() != frame.fragment {
                return Err(ProtocolError::qr("conflicting duplicate QR frame rejected"));
            }
            return Ok(None);
        }
        self.received[index] = true;
        self.fragments[index] = frame.fragment.to_vec();
        if !(0..usize::from(frame.total_frames)).all(|position| self.received[position]) {
            return Ok(None);
        }
        self.finish()
    }

    fn accept_raw(&self, payload: &[u8]) -> ProtocolResult<Option<Vec<u8>>> {
        if payload.starts_with(&shared_signer::qr_frame::FRAME_MAGIC) {
            return Err(ProtocolError::qr("invalid multi-frame QR header"));
        }
        if self.session_active {
            return Err(ProtocolError::qr("mixed multi-frame QR session rejected"));
        }
        Ok(Some(payload.to_vec()))
    }

    fn accept_session(
        &mut self,
        session_id: [u8; shared_signer::qr_frame::SESSION_ID_LEN],
        total_frames: u8,
    ) -> ProtocolResult<()> {
        shared_signer::security::authorize_frame_session(
            self.session_active,
            &self.session_id,
            self.total_frames,
            &session_id,
            total_frames,
        )
        .map_err(|_| ProtocolError::qr("mixed multi-frame QR session rejected"))?;
        if !self.session_active {
            self.session_id = session_id;
            self.session_active = true;
            self.total_frames = total_frames;
        }
        Ok(())
    }

    fn finish(&mut self) -> ProtocolResult<Option<Vec<u8>>> {
        let total = usize::from(self.total_frames);
        let mut complete = Vec::new();
        for index in 0..total {
            complete.extend_from_slice(&self.fragments[index]);
        }
        let expected = self.session_id;
        self.reset();
        if !shared_signer::qr_frame::verify_session(&complete, &expected) {
            return Err(ProtocolError::qr("assembled QR session digest mismatch"));
        }
        Ok(Some(complete))
    }
}
