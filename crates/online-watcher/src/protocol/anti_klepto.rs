//! Public-only host-assisted anti-klepto verification shared by transaction and covenant flows.

use k256::elliptic_curve::{group::Group, ops::Reduce, sec1::ToEncodedPoint};
use k256::{ProjectivePoint, Scalar, U256};

pub(crate) fn verify_nonce_relation(
    provisional_nonce_point: &[u8; 33],
    final_signature: &[u8; 64],
    session_id: &[u8; shared_signer::anti_klepto::SESSION_ID_LEN],
    host_secret: &[u8; 32],
    input_index: u32,
    signature_slot: u8,
    public_key: &[u8; 33],
) -> Result<(), String> {
    if (public_key[0], provisional_nonce_point[0]) != (0x02, 0x02) {
        return Err("anti-klepto nonce points must use even-Y encoding".into());
    }
    let provisional = k256::PublicKey::from_sec1_bytes(provisional_nonce_point)
        .map_err(|_| "anti-klepto provisional nonce is invalid".to_string())?;
    k256::PublicKey::from_sec1_bytes(public_key)
        .map_err(|_| "anti-klepto public key is invalid".to_string())?;
    let material = shared_signer::anti_klepto::host_scalar_material(
        session_id,
        host_secret,
        input_index,
        signature_slot,
        public_key,
        provisional_nonce_point,
    );
    let contribution = <Scalar as Reduce<U256>>::reduce_bytes(&material.into());
    if bool::from(contribution.is_zero()) {
        return Err("anti-klepto host contribution is invalid".into());
    }
    let expected = provisional.to_projective() + ProjectivePoint::GENERATOR * contribution;
    let expected_x =
        point_x(&expected).ok_or_else(|| "anti-klepto nonce point is invalid".to_string())?;
    let final_x: [u8; 32] = final_signature[..32]
        .try_into()
        .map_err(|_| "anti-klepto final signature is invalid".to_string())?;
    shared_signer::bytes::constant_time_eq_32(&expected_x, &final_x)
        .then_some(())
        .ok_or_else(|| "anti-klepto final nonce does not include the host contribution".to_string())
}

fn point_x(point: &ProjectivePoint) -> Option<[u8; 32]> {
    if bool::from(point.is_identity()) {
        return None;
    }
    let encoded = point.to_affine().to_encoded_point(false);
    let mut x = [0u8; 32];
    x.copy_from_slice(encoded.x()?);
    Some(x)
}
