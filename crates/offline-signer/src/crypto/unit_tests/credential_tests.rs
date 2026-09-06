use super::{CredentialKind, SALT_SIZE};

#[test]
fn credential_kind_byte_round_trip_rejects_unknown_values() {
    assert_eq!(CredentialKind::from_byte(1), Some(CredentialKind::Pin));
    assert_eq!(CredentialKind::from_byte(2), Some(CredentialKind::Password));
    assert_eq!(CredentialKind::from_byte(0), None);
    assert_eq!(CredentialKind::from_byte(3), None);
    assert_eq!(SALT_SIZE, 16);
}
