use crate::storage::payload::{detect_payload, DetectedPayload};

#[test]
fn payload_detection_rejects_retired_password_only_wallet_backup_formats() {
    let retired = [
        b"KAS\x01legacy".as_slice(),
        b"KAS\x02legacy".as_slice(),
        b"KAX\x02legacy".as_slice(),
        b"KAS\x04password-only".as_slice(),
    ];
    for payload in retired {
        assert_eq!(
            detect_payload(payload, payload.len()),
            DetectedPayload::Unknown {
                trimmed_len: payload.len()
            },
        );
    }
    assert_eq!(
        detect_payload(b"current", 7),
        DetectedPayload::Unknown { trimmed_len: 7 },
    );
    assert_eq!(
        detect_payload(b"current", 7),
        DetectedPayload::Unknown { trimmed_len: 7 },
    );
}

#[test]
fn payload_detection_keeps_non_wallet_import_formats() {
    let cases = [
        (
            b"COVBdata".as_slice(),
            DetectedPayload::CovenantBackup { trimmed_len: 8 },
        ),
        (
            b"COVIdata".as_slice(),
            DetectedPayload::CovenantBackup { trimmed_len: 8 },
        ),
        (
            b"xprv-example".as_slice(),
            DetectedPayload::PlainXprv { trimmed_len: 12 },
        ),
    ];
    for (payload, expected) in cases {
        assert_eq!(detect_payload(payload, payload.len()), expected);
    }
}

#[test]
fn payload_detection_trims_padding_caps_length_and_recognizes_private_keys() {
    let private_key = [b'a'; 64];
    assert_eq!(
        detect_payload(&private_key, usize::MAX),
        DetectedPayload::PlainPrivateKey { trimmed_len: 64 },
    );
    assert_eq!(
        detect_payload(b"xprv-data\r\n \0ignored", 13),
        DetectedPayload::PlainXprv { trimmed_len: 9 },
    );
    assert_eq!(
        detect_payload(b"ignored", 0),
        DetectedPayload::Unknown { trimmed_len: 0 },
    );
}

#[test]
fn trimmed_len_accessor_covers_every_supported_payload_variant() {
    let variants = [
        DetectedPayload::CovenantBackup { trimmed_len: 1 },
        DetectedPayload::PlainXprv { trimmed_len: 2 },
        DetectedPayload::PlainPrivateKey { trimmed_len: 3 },
        DetectedPayload::Unknown { trimmed_len: 4 },
    ];
    assert_eq!(variants.map(DetectedPayload::trimmed_len), [1, 2, 3, 4]);
}
