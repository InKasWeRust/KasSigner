#![no_main]

use libfuzzer_sys::fuzz_target;
use offline_signer::transaction::{
    model::Transaction,
    std_pskt::{parse_pskt, serialize_pskt, PSKB_MAGIC, PSKT_MAGIC},
};
use shared_signer::{PsktParsed, TxInputFormat};

fuzz_target!(|data: &[u8]| {
    let wire = &data[..data.len().min(16_384)];
    let mut scratch = [0u8; 8_192];
    let Ok(mut transaction) = Transaction::try_new() else {
        return;
    };
    let mut parsed = PsktParsed::empty();
    if parse_pskt(wire, &mut scratch, &mut transaction, &mut parsed).is_ok() {
        let format = if wire.starts_with(PSKB_MAGIC) {
            TxInputFormat::PsktPskb
        } else {
            assert!(wire.starts_with(PSKT_MAGIC));
            TxInputFormat::PsktSingle
        };
        let mut canonical = [0u8; 32_768];
        let written = serialize_pskt(
            &transaction,
            &parsed,
            &scratch,
            format,
            &mut canonical,
        )
        .expect("every accepted PSKT must serialize canonically");

        let mut second_scratch = [0u8; 8_192];
        let Ok(mut second_transaction) = Transaction::try_new() else {
            return;
        };
        let mut second_parsed = PsktParsed::empty();
        parse_pskt(
            &canonical[..written],
            &mut second_scratch,
            &mut second_transaction,
            &mut second_parsed,
        )
        .expect("canonical PSKT must parse");
        let mut second = [0u8; 32_768];
        let second_length = serialize_pskt(
            &second_transaction,
            &second_parsed,
            &second_scratch,
            format,
            &mut second,
        )
        .expect("reparsed PSKT must serialize");
        assert_eq!(&canonical[..written], &second[..second_length]);
    }
});
