//! Isolated state for universal covenant-key derivation/signing.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CovenantSigningMode {
    None,
    KeyInfo,
    BindKnown,
    BindOpaque,
    Known,
    Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CovenantSigningPhase { Idle, Prepared, AwaitingReveal, FinalResponse }

pub struct CovenantSigningState {
    pub mode: CovenantSigningMode,
    pub phase: CovenantSigningPhase,
    pub scheme: shared_signer::covenant_sign::KnownScheme,
    pub session_id: [u8; shared_signer::covenant_sign::SESSION_ID_LEN],
    pub host_commitment: [u8; 32],
    pub key_id: [u8; 32],
    pub pubkey_x: [u8; 32],
    pub binding_token: [u8; 32],
    pub commitment: [u8; 32],
    pub script_hash: [u8; 32],
    pub context: [u8; shared_signer::covenant_sign::MAX_CONTEXT_LEN],
    pub context_len: usize,
    pub context_page: u8,
    pub provisional_signature: [u8; 64],
    pub nonce_point: [u8; 33],
    pub signature: [u8; 64],
    pub response: [u8; shared_signer::covenant_sign::RESPONSE_LEN],
    pub response_len: usize,
    pub nonce_qr_shown: bool,
    /// One device-generated, not-yet-bound covenant key allocation. This is
    /// non-secret and intentionally survives workflow resets until it is bound
    /// or replaced by a newer key allocation.
    pub pending_key_id: [u8; 32],
    pub pending_pubkey_x: [u8; 32],
}

impl CovenantSigningState {
    pub(super) fn new() -> Self {
        Self {
            mode: CovenantSigningMode::None,
            phase: CovenantSigningPhase::Idle,
            scheme: shared_signer::covenant_sign::KnownScheme::None,
            session_id: [0; shared_signer::covenant_sign::SESSION_ID_LEN],
            host_commitment: [0; 32], key_id: [0; 32], pubkey_x: [0; 32], binding_token: [0; 32],
            commitment: [0; 32], script_hash: [0; 32],
            context: [0; shared_signer::covenant_sign::MAX_CONTEXT_LEN], context_len: 0,
            context_page: 0, provisional_signature: [0; 64], nonce_point: [0; 33], signature: [0; 64],
            response: [0; shared_signer::covenant_sign::RESPONSE_LEN], response_len: 0,
            nonce_qr_shown: false, pending_key_id: [0; 32], pending_pubkey_x: [0; 32],
        }
    }

    /// Clear only the active transport/review/signing session. A pending
    /// device-generated key allocation is retained so the host can build the
    /// third-party script and return with a BIND request.
    pub fn reset(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.session_id);
        shared_signer::bytes::zeroize_bytes(&mut self.host_commitment);
        shared_signer::bytes::zeroize_bytes(&mut self.key_id);
        shared_signer::bytes::zeroize_bytes(&mut self.pubkey_x);
        shared_signer::bytes::zeroize_bytes(&mut self.binding_token);
        shared_signer::bytes::zeroize_bytes(&mut self.commitment);
        shared_signer::bytes::zeroize_bytes(&mut self.script_hash);
        shared_signer::bytes::zeroize_bytes(&mut self.context);
        shared_signer::bytes::zeroize_bytes(&mut self.provisional_signature);
        shared_signer::bytes::zeroize_bytes(&mut self.nonce_point);
        shared_signer::bytes::zeroize_bytes(&mut self.signature);
        shared_signer::bytes::zeroize_bytes(&mut self.response);
        self.mode = CovenantSigningMode::None; self.phase = CovenantSigningPhase::Idle;
        self.scheme = shared_signer::covenant_sign::KnownScheme::None;
        self.context_len = 0; self.context_page = 0; self.response_len = 0; self.nonce_qr_shown = false;
    }

    pub fn replace_pending_allocation(&mut self, key_id: [u8; 32], pubkey_x: [u8; 32]) {
        self.pending_key_id = key_id;
        self.pending_pubkey_x = pubkey_x;
    }

    pub fn clear_pending_allocation(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.pending_key_id);
        shared_signer::bytes::zeroize_bytes(&mut self.pending_pubkey_x);
    }

    pub fn context_page_count(&self) -> u8 {
        let text = core::str::from_utf8(&self.context[..self.context_len]).unwrap_or("");
        let pages = text.chars().count().saturating_add(59) / 60;
        u8::try_from(pages.max(1)).unwrap_or(u8::MAX)
    }

    pub fn context_page_text(&self) -> &str {
        let text = core::str::from_utf8(&self.context[..self.context_len]).unwrap_or("");
        let start_char = usize::from(self.context_page) * 60;
        let end_char = start_char.saturating_add(60);
        let start = text.char_indices().nth(start_char).map(|(index, _)| index).unwrap_or(text.len());
        let end = text.char_indices().nth(end_char).map(|(index, _)| index).unwrap_or(text.len());
        &text[start..end]
    }
}
