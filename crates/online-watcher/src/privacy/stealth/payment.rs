use k256::elliptic_curve::ops::Add;
use k256::{ProjectivePoint, PublicKey};

use super::derivation::{stealth_tweak, view_tag};
use super::keys::{scalar_from_bytes, x_only_bytes, x_only_from_affine};
use super::metadata::StealthMeta;

pub struct StealthPayment {
    pub one_time_pubkey: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub stealth_index: u32,
    pub view_tag: u8,
}

pub fn generate_stealth_payment(
    meta: &StealthMeta,
    entropy: &[u8; 32],
) -> Result<StealthPayment, String> {
    let ephemeral_secret = scalar_from_bytes(entropy)?;
    let ephemeral_point = ProjectivePoint::GENERATOR * ephemeral_secret;
    let ephemeral_key = PublicKey::from_affine(ephemeral_point.to_affine())
        .map_err(|error| format!("Bad ephemeral point: {error}"))?;
    let shared = meta.scan_pubkey.to_projective() * ephemeral_secret;
    let shared_x = x_only_from_affine(&shared.to_affine());
    let (tweak, stealth_index) = stealth_tweak(&shared_x, 0);
    let one_time = meta
        .spend_pubkey
        .to_projective()
        .add(&(ProjectivePoint::GENERATOR * tweak));
    Ok(StealthPayment {
        one_time_pubkey: x_only_from_affine(&one_time.to_affine()),
        ephemeral_pubkey: x_only_bytes(&ephemeral_key),
        stealth_index,
        view_tag: view_tag(&shared_x),
    })
}
