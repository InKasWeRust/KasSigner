use super::*;
use crate::transaction::model::{SigHashType, Transaction};
use shared_signer::PsktParsed;

#[test]
fn facade_wallet_generation_restore_and_watch_export_cover_public_surface() {
    let signer = OfflineSigner::new();
    let entropy12 = [0x11u8; 16];
    let entropy24 = [0x22u8; 32];
    let mnemonic12 = signer.generate_wallet_12(&entropy12);
    let mnemonic24 = signer.generate_wallet_24(&entropy24);
    let seed12 = signer
        .restore_wallet_12(&mnemonic12, "passphrase")
        .expect("12-word restore");
    let seed24 = signer
        .restore_wallet_24(&mnemonic24, "passphrase")
        .expect("24-word restore");
    assert_ne!(seed12.bytes, seed24.bytes);

    let mut kpub = [0u8; xpub::KPUB_MAX_LEN];
    let written = signer
        .export_watch_account(&seed12.bytes, &mut kpub)
        .expect("watch export");
    assert!(written > 0);
    assert!(kpub[..written].iter().any(|byte| *byte != 0));
}

#[test]
fn facade_review_routes_both_wire_formats_and_preserves_errors() {
    let signer = OfflineSigner::new();
    let mut scratch = [0u8; 512];
    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::default();

    assert!(matches!(
        signer.review_transaction(
            TxInputFormat::KsptCompact,
            &[0u8; 2],
            &mut scratch,
            &mut transaction,
            &mut parsed,
        ),
        Err(TransactionEnvelopeError::Kspt(_))
    ));

    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::default();
    assert!(matches!(
        signer.review_transaction(
            TxInputFormat::PsktPskb,
            br#"{}"#,
            &mut scratch,
            &mut transaction,
            &mut parsed,
        ),
        Err(TransactionEnvelopeError::Pskt(_))
    ));

    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::default();
    assert!(matches!(
        signer.review_transaction(
            TxInputFormat::PsktSingle,
            br#"{}"#,
            &mut scratch,
            &mut transaction,
            &mut parsed,
        ),
        Err(TransactionEnvelopeError::Pskt(_))
    ));
}

#[test]
fn facade_signing_routes_transaction_and_message_domains() {
    let signer = OfflineSigner::new();
    let private_key = [1u8; 32];
    assert!(signer
        .sign_transaction(
            &Transaction::try_new().expect("transaction test allocation"),
            &private_key,
            SigHashType::All
        )
        .is_err());

    let signature = signer
        .sign_user_message_with_entropy(&private_key, b"KasSigner facade coverage", &[7u8; 32])
        .expect("message signature");
    assert_ne!(signature.bytes, [0u8; 64]);
}
