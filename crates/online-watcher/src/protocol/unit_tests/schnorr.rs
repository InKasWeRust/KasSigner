use crate::protocol::schnorr::bip340_verify;

#[test]
fn verifier_rejects_invalid_points_and_scalars_without_panicking() {
    assert!(bip340_verify(&[0xff; 32], &[0u8; 32], &[0u8; 64]).is_err());
    let mut signature = [0u8; 64];
    signature[..32].fill(0xff);
    assert!(bip340_verify(&[2u8; 32], &[3u8; 32], &signature).is_err());
}
