pub struct PortableCredentialState {
    password: [u8; 128],
    password_len: usize,
}

impl PortableCredentialState {
    pub(super) const fn new() -> Self { Self { password: [0; 128], password_len: 0 } }
    pub fn password(&self) -> &[u8] { &self.password[..self.password_len] }
    pub fn set_password(&mut self, password: &[u8]) {
        self.clear();
        let length=password.len().min(self.password.len());
        self.password[..length].copy_from_slice(&password[..length]);
        self.password_len=length;
    }
    pub fn clear(&mut self) { shared_signer::bytes::zeroize_bytes(&mut self.password); self.password_len=0; }
}
