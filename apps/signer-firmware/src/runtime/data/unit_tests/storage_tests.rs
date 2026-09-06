use super::{EncryptedFileOperation, EncryptedPayloadKind, TextFileKind};

#[test]
fn import_replaces_prior_export_without_inheriting_direction_or_filename() {
    let mut operation = EncryptedFileOperation::Export {
        kind: EncryptedPayloadKind::Transaction,
        filename: *b"PREVIOUSKSP",
        back_state: crate::runtime::navigation::continuation!(SdKsptEncryptAsk),
        success_state: crate::runtime::navigation::continuation!(MainMenu),
    };
    operation = EncryptedFileOperation::Import {
        kind: EncryptedPayloadKind::Text(TextFileKind::Kpub),
        back_state: crate::runtime::navigation::continuation!(SdKpubFileList),
    };

    assert!(matches!(
        operation,
        EncryptedFileOperation::Import {
            kind: EncryptedPayloadKind::Text(TextFileKind::Kpub),
            ..
        }
    ));
    assert_eq!(operation.back_state(), crate::runtime::navigation::continuation!(SdKpubFileList));
}

#[test]
fn every_encrypted_workflow_uses_its_explicit_back_state() {
    let operations = [
        EncryptedFileOperation::Import {
            kind: EncryptedPayloadKind::Transaction,
            back_state: crate::runtime::navigation::continuation!(SdKsptFileList),
        },
        EncryptedFileOperation::Import {
            kind: EncryptedPayloadKind::Text(TextFileKind::MultisigDescriptor),
            back_state: crate::runtime::navigation::continuation!(SdKpubFileList),
        },
        EncryptedFileOperation::Export {
            kind: EncryptedPayloadKind::Text(TextFileKind::MultisigAddress),
            filename: *b"MULTISIGTXT",
            back_state: crate::runtime::navigation::continuation!(SdMsAddrEncryptAsk),
            success_state: crate::runtime::navigation::continuation!(MainMenu),
        },
    ];
    let expected = [
        crate::runtime::navigation::continuation!(SdKsptFileList),
        crate::runtime::navigation::continuation!(SdKpubFileList),
        crate::runtime::navigation::continuation!(SdMsAddrEncryptAsk),
    ];

    for (operation, expected_state) in operations.into_iter().zip(expected) {
        assert_eq!(operation.back_state(), expected_state);
    }
}
