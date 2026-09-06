use k256::elliptic_curve::ScalarPrimitive;
use k256::{Scalar, Secp256k1};
use sha2::{Digest, Sha256};

const STEALTH_TAG: &[u8] = b"KasStealth";
const VIEW_TAG: &[u8] = b"KasStealthViewTag";

pub(crate) fn view_tag(shared_secret_x: &[u8; 32]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(VIEW_TAG);
    hasher.update(shared_secret_x);
    hasher.finalize()[0]
}

pub(crate) fn stealth_tweak(shared_secret_x: &[u8; 32], counter: u32) -> (Scalar, u32) {
    let mut hasher = Sha256::new();
    hasher.update(STEALTH_TAG);
    hasher.update(shared_secret_x);
    hasher.update(counter.to_be_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(&hash).unwrap_or_else(|_| {
        let mut adjusted = [0u8; 32];
        adjusted[1..].copy_from_slice(&hash[..31]);
        ScalarPrimitive::<Secp256k1>::from_slice(&adjusted).expect("31-byte reduced stealth tweak")
    });
    let index =
        u32::from_be_bytes(hash[..4].try_into().expect("four-byte hash prefix")) & 0x7fff_ffff;
    (Scalar::from(primitive), index)
}
