use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{AffinePoint, PublicKey, Scalar, Secp256k1};

pub fn x_only_pub(public_key: &PublicKey) -> [u8; 32] {
    x_only_bytes(public_key)
}

pub(crate) fn x_only_bytes(public_key: &PublicKey) -> [u8; 32] {
    let encoded = public_key.to_encoded_point(true);
    x_coordinate(encoded.as_bytes())
}

pub(crate) fn x_only_from_affine(affine: &AffinePoint) -> [u8; 32] {
    let encoded = affine.to_encoded_point(true);
    x_coordinate(encoded.as_bytes())
}

fn x_coordinate(compressed: &[u8]) -> [u8; 32] {
    let mut x = [0u8; 32];
    x.copy_from_slice(&compressed[1..33]);
    x
}

pub fn pubkey_from_xonly(bytes: &[u8]) -> Result<PublicKey, String> {
    if bytes.len() != 32 {
        return Err(format!(
            "xonly pubkey must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(bytes);
    PublicKey::from_sec1_bytes(&compressed).map_err(|error| format!("Invalid pubkey: {error}"))
}

pub(crate) fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, String> {
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(bytes)
        .map_err(|error| format!("Invalid scalar: {error}"))?;
    Ok(Scalar::from(primitive))
}
