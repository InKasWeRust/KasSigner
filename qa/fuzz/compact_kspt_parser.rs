#![no_main]

use libfuzzer_sys::fuzz_target;
use offline_signer::transaction::{
    kspt::{parse_compact_kspt, serialize_compact_kspt},
    model::Transaction,
};

fuzz_target!(|data: &[u8]| {
    let Ok(mut parsed) = Transaction::try_new() else {
        return;
    };
    if parse_compact_kspt(data, &mut parsed).is_ok() {
        let mut canonical = [0u8; 32768];
        let written = serialize_compact_kspt(&parsed, &mut canonical)
            .expect("every accepted compact KSPT must serialize");
        let Ok(mut reparsed) = Transaction::try_new() else {
            return;
        };
        parse_compact_kspt(&canonical[..written], &mut reparsed)
            .expect("canonical serialization must parse");
        let mut second = [0u8; 32768];
        let second_len = serialize_compact_kspt(&reparsed, &mut second)
            .expect("reparsed transaction must serialize");
        assert_eq!(&canonical[..written], &second[..second_len]);
    }
});
