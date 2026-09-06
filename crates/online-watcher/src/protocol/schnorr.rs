use k256::elliptic_curve::{ops::Reduce, ScalarPrimitive};
use k256::{ProjectivePoint, Scalar, Secp256k1, U256};
use sha2::{Digest, Sha256};

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

fn xonly_to_point(xonly: &[u8; 32]) -> Result<ProjectivePoint, String> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(xonly);
    let key = k256::PublicKey::from_sec1_bytes(&compressed)
        .map_err(|error| format!("Invalid x-only pubkey: {error}"))?;
    Ok(key.to_projective())
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, String> {
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(bytes)
        .map_err(|error| format!("Invalid scalar: {error}"))?;
    Ok(Scalar::from(primitive))
}

fn challenge(rx: &[u8; 32], px: &[u8; 32], message: &[u8; 32]) -> Scalar {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(rx);
    data[32..64].copy_from_slice(px);
    data[64..].copy_from_slice(message);
    let hash = tagged_hash(b"BIP0340/challenge", &data);
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
}

pub(crate) fn bip340_verify(
    public_key: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<bool, String> {
    let mut nonce_x = [0u8; 32];
    nonce_x.copy_from_slice(&signature[..32]);
    let mut response_bytes = [0u8; 32];
    response_bytes.copy_from_slice(&signature[32..]);
    let public_point = xonly_to_point(public_key)?;
    let response = scalar_from_bytes(&response_bytes)?;
    let left = ProjectivePoint::GENERATOR * response;
    let right = xonly_to_point(&nonce_x)? + public_point * challenge(&nonce_x, public_key, message);
    Ok(left == right)
}
