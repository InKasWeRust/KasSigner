use super::{build_redeem_script, resolve_address_path, MultisigDescriptor};

#[test]
fn static_descriptor_is_sorted_before_script_encoding() {
    let descriptor = MultisigDescriptor::parse(&format!(
        "multi(1,{}, {})",
        "02".repeat(32),
        "01".repeat(32)
    ))
    .expect("descriptor");
    let keys = descriptor.public_keys_at(0, 0, 0).expect("keys");
    assert!(keys[0] < keys[1]);
    let script = build_redeem_script(descriptor.threshold(), &keys).expect("script");
    assert_eq!(script[0], 0x51);
    assert_eq!(script.last(), Some(&0xae));
}

#[test]
fn hd_descriptor_parsing_covers_valid_derivation_and_validation_failures() {
    const GENERATOR_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let first = format!("02{}{}", GENERATOR_X, "11".repeat(32));
    let second = format!("03{}{}", GENERATOR_X, "22".repeat(32));
    let descriptor = MultisigDescriptor::parse(&format!("multi_hd(1,{}, {})", first, second,))
        .expect("HD descriptor");
    assert!(descriptor.is_hd());
    assert_eq!(descriptor.threshold(), 1);
    assert_eq!(descriptor.participant_count(), 2);
    let keys = descriptor.public_keys_at(7, 0, 0).expect("derived keys");
    assert_eq!(keys.len(), 2);
    assert!(keys[0] <= keys[1]);

    for invalid in [
        "multi_hd(1,only-one)",
        "multi_hd(0,a,b)",
        "multi_hd(3,a,b)",
        "multi_hd(not-a-number,a,b)",
    ] {
        assert!(MultisigDescriptor::parse(invalid).is_err());
    }

    let short = format!("multi_hd(1,{}, {})", "00".repeat(64), second);
    assert!(MultisigDescriptor::parse(&short)
        .unwrap_err()
        .contains("130 hex chars"));

    let bad_hex = format!("multi_hd(1,{}, {})", "zz".repeat(65), second);
    assert!(MultisigDescriptor::parse(&bad_hex)
        .unwrap_err()
        .contains("Invalid xpub hex"));

    let invalid_key = format!("{}{}", "00".repeat(33), "44".repeat(32));
    assert!(
        MultisigDescriptor::parse(&format!("multi_hd(1,{}, {})", invalid_key, second,))
            .unwrap_err()
            .contains("Invalid compressed pubkey")
    );
}

#[test]
fn address_index_resolution_covers_static_hd_match_and_miss() {
    let static_descriptor =
        MultisigDescriptor::parse(&format!("multi(1,{},{})", "01".repeat(32), "02".repeat(32),))
            .expect("static descriptor");
    assert_eq!(
        resolve_address_path(&static_descriptor, "kaspa:any", 37).map(|path| path.index),
        Ok(37)
    );

    const GENERATOR_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let first = format!("02{}{}", GENERATOR_X, "11".repeat(32));
    let second = format!("03{}{}", GENERATOR_X, "22".repeat(32));
    let hd = MultisigDescriptor::parse(&format!("multi_hd(1,{}, {})", first, second))
        .expect("HD descriptor");
    let target_index = 7;
    let keys = hd.public_keys_at(target_index, 0, 0).expect("derived keys");
    let script = build_redeem_script(hd.threshold(), &keys).expect("redeem script");
    let source =
        crate::protocol::script::p2sh::script_to_address(&script, "kaspa").expect("source address");
    assert_eq!(
        resolve_address_path(&hd, &source, 99).map(|path| path.index),
        Ok(target_index)
    );

    let missing_script =
        build_redeem_script(1, &[[0x31; 32], [0x32; 32]]).expect("unrelated redeem");
    let missing = crate::protocol::script::p2sh::script_to_address(&missing_script, "kaspa")
        .expect("unrelated address");
    assert!(resolve_address_path(&hd, &missing, 0)
        .unwrap_err()
        .contains("Could not find address index"));
}

#[test]
fn v106_hd45_cross_implementation_vector_is_exact() {
    // Copied from v1.0.6 bootloader/src/wallet/transaction.rs. The expected
    // address came from rusty-kaspa 2.0.1 and, there, from the Go
    // implementation. Parent kpub strings are intentionally unsorted.
    const KPUBS: [&str; 5] = [
        "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
        "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
        "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
        "kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
        "kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
    ];
    const EXPECTED: &str = "kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998";

    let descriptor_text = format!(
        "multi_hd45(2,{},{},{},{},{})",
        KPUBS[0], KPUBS[1], KPUBS[2], KPUBS[3], KPUBS[4],
    );
    let descriptor = MultisigDescriptor::parse(&descriptor_text).expect("v1.0.6 descriptor");
    assert!(descriptor.is_hd45());
    assert_eq!(descriptor.participant_count(), 5);
    let keys = descriptor.public_keys_at(0, 1, 0).expect("45' children");
    let redeem = build_redeem_script(2, &keys).expect("45' redeem");
    let address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").expect("45' P2SH");
    assert_eq!(address, EXPECTED);
}

#[test]
fn v106_legacy_hd44_vector_remains_exact() {
    // Descriptor and expected addresses were evaluated by the shipped v1.0.6
    // KasSee WASM. This pins the legacy /0/index branch independently of the
    // restored 45' path.
    const FIRST: &str =
        "0268700dcff8518ddf9a3ab82d54fb5f1040ec9e7b62b0d4d2f8fefa445e24f9cd80095e40f2735a48e4069987bb450545f59bf488c1a161736a139e58ed49add5";
    const SECOND: &str =
        "0264a667fd8f51b5c3e4403b094515555a202a319e8b6fa0e938435a36ee9668da6664eda430099a30858e170ffe67a10870a38f488f3e18fc79c83f70a7db2a14";
    const EXPECTED: [(u32, &str); 3] = [
        (
            0,
            "kaspa:pzusak623u773576gj4ep7eazg5c240e06xty8egwgnem55azuqw2f8lawdlw",
        ),
        (
            7,
            "kaspa:pr59s5mjd5hfajew9y3atjew67yscy9lyqyf604mdjta50sjkgdkk28wuhdvd",
        ),
        (
            39,
            "kaspa:pp4px347dcpfjue2ydtluquuszvv2zv3zm3uvgy7n0s3jgk9m8rjwp7f3a9dv",
        ),
    ];
    let descriptor = MultisigDescriptor::parse(&format!("multi_hd(2,{FIRST},{SECOND})"))
        .expect("v1.0.6 legacy descriptor");
    for (index, expected) in EXPECTED {
        let keys = descriptor
            .public_keys_at(index, 0, 0)
            .expect("legacy children");
        let redeem = build_redeem_script(2, &keys).expect("legacy redeem");
        let address = crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa")
            .expect("legacy P2SH");
        assert_eq!(address, expected);
    }
}

#[test]
fn hd45_parser_rejects_duplicates_bad_length_and_invalid_base58() {
    const KPUB: &str = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    assert!(
        MultisigDescriptor::parse(&format!("multi_hd45(1,{KPUB},{KPUB})"))
            .unwrap_err()
            .contains("Duplicate cosigner")
    );
    assert!(MultisigDescriptor::parse("multi_hd45(1,short,also-short)")
        .unwrap_err()
        .contains("111 characters"));
    let invalid = "x".repeat(111);
    assert!(
        MultisigDescriptor::parse(&format!("multi_hd45(1,{KPUB},{invalid})"))
            .unwrap_err()
            .contains("Invalid 45' cosigner kpub")
    );
}

#[test]
fn hd45_address_path_resolution_covers_cosigner_and_change_branches() {
    use super::resolve_address_path;
    const FIRST: &str = "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    const SECOND: &str = "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz";
    let descriptor = MultisigDescriptor::parse(&format!("multi_hd45(1,{FIRST},{SECOND})"))
        .expect("45' descriptor");
    let keys = descriptor.public_keys_at(2, 1, 1).expect("change keys");
    let redeem = build_redeem_script(1, &keys).expect("change redeem");
    let address =
        crate::protocol::script::p2sh::script_to_address(&redeem, "kaspa").expect("change address");
    let path = resolve_address_path(&descriptor, &address, 99).expect("resolved path");
    assert_eq!((path.cosigner, path.chain, path.index), (1, 1, 2));
}

#[test]
fn redeem_script_validation_covers_threshold_count_and_conversion_boundaries() {
    let one = [[0x11u8; 32]];
    assert!(build_redeem_script(0, &one)
        .unwrap_err()
        .contains("Invalid 0-of-1"));
    assert!(build_redeem_script(2, &one)
        .unwrap_err()
        .contains("Invalid 2-of-1"));

    let seventeen = vec![[0x22u8; 32]; 17];
    assert!(build_redeem_script(1, &seventeen)
        .unwrap_err()
        .contains("Invalid 1-of-17"));

    let too_many = vec![[0x33u8; 32]; 256];
    assert!(build_redeem_script(1, &too_many)
        .unwrap_err()
        .contains("Too many multisig"));
}

#[test]
fn descriptor_error_rendering_covers_static_length_hex_duplicates_and_generic_errors() {
    let short_static = format!("multi(1,{}, {})", "11".repeat(31), "22".repeat(32));
    assert!(MultisigDescriptor::parse(&short_static)
        .unwrap_err()
        .contains("64 hex chars"));

    let bad_static = format!("multi(1,{}, {})", "zz".repeat(32), "22".repeat(32));
    assert!(MultisigDescriptor::parse(&bad_static)
        .unwrap_err()
        .contains("Invalid pubkey hex"));

    let duplicate = format!("multi(1,{0},{0})", "11".repeat(32));
    assert!(MultisigDescriptor::parse(&duplicate)
        .unwrap_err()
        .contains("Duplicate cosigner"));

    let invalid_threshold = format!("multi(0,{}, {})", "11".repeat(32), "22".repeat(32));
    assert!(MultisigDescriptor::parse(&invalid_threshold)
        .unwrap_err()
        .contains("Invalid M value"));
}
