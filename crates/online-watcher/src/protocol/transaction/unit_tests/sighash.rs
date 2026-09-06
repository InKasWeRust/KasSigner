use crate::protocol::transaction::sighash::{
    compute_full_sighash, FullSighashInput, FullSighashRequest, SighashContext, SighashOutput,
};

static NATIVE_SUBNETWORK_ID: [u8; 20] = [0; 20];

fn native_context<'a>(locktime: u64, payload: &'a [u8]) -> SighashContext<'a> {
    SighashContext {
        subnetwork_id: &NATIVE_SUBNETWORK_ID,
        gas: 0,
        locktime,
        payload,
    }
}

#[test]
fn full_sighash_all_version_one_vector_is_stable() {
    let transaction_id = [0x11; 32];
    let outputs = [SighashOutput {
        value: 5,
        spk_version: 0,
        spk_script: vec![0x51],
        covenant: None,
    }];
    let context = native_context(6, &[]);
    let inputs = [FullSighashInput {
        transaction_id: &transaction_id,
        index: 2,
        amount: 4,
        sequence: 3,
        sig_op_count: 7,
        spk_version: 0,
        spk_script: &[0x51],
    }];

    let full = compute_full_sighash(FullSighashRequest {
        tx_version: 1,
        inputs: &inputs,
        input_index: 0,
        outputs: &outputs,
        context: &context,
        sighash_type: 0x01,
    })
    .expect("valid full sighash");

    assert_eq!(
        hex::encode(full),
        "6eb878a1f83bcbc18e85e1288adfed5a9dd8d6505cf204575a355f956669e246"
    );
}

#[test]
fn full_sighash_modes_are_distinct_and_invalid_types_fail_closed() {
    let transaction_id = [0x22; 32];
    let inputs = [FullSighashInput {
        transaction_id: &transaction_id,
        index: 1,
        amount: 100,
        sequence: 9,
        sig_op_count: 2,
        spk_version: 0,
        spk_script: &[0x51],
    }];
    let outputs = [SighashOutput {
        value: 90,
        spk_version: 0,
        spk_script: vec![0x51],
        covenant: None,
    }];
    let context = native_context(7, &[]);
    let calculate = |sighash_type| {
        compute_full_sighash(FullSighashRequest {
            tx_version: 1,
            inputs: &inputs,
            input_index: 0,
            outputs: &outputs,
            context: &context,
            sighash_type,
        })
    };

    let all = calculate(0x01).expect("ALL");
    let none = calculate(0x02).expect("NONE");
    let single = calculate(0x04).expect("SINGLE");
    let anyone_can_pay = calculate(0x81).expect("ALL|ANYONECANPAY");
    assert_ne!(all, none);
    assert_ne!(all, single);
    assert_ne!(all, anyone_can_pay);
    assert!(calculate(0x00).is_err());
    assert!(calculate(0x03).is_err());
    assert!(calculate(0xff).is_err());
}

#[test]
fn version_zero_sigop_hash_binds_noncurrent_inputs_except_anyone_can_pay() {
    let first_txid = [0x31; 32];
    let second_txid = [0x32; 32];
    let outputs = [SighashOutput {
        value: 75,
        spk_version: 0,
        spk_script: vec![0x51],
        covenant: None,
    }];
    let context = native_context(11, &[]);
    let first = FullSighashInput {
        transaction_id: &first_txid,
        index: 0,
        amount: 50,
        sequence: 1,
        sig_op_count: 1,
        spk_version: 0,
        spk_script: &[0x51],
    };
    let second = FullSighashInput {
        transaction_id: &second_txid,
        index: 1,
        amount: 30,
        sequence: 2,
        sig_op_count: 2,
        spk_version: 0,
        spk_script: &[0x51],
    };
    let inputs = [first, second];
    let changed_inputs = [
        first,
        FullSighashInput {
            sig_op_count: 3,
            ..second
        },
    ];

    let calculate = |inputs: &[FullSighashInput<'_>], sighash_type| {
        compute_full_sighash(FullSighashRequest {
            tx_version: 0,
            inputs,
            input_index: 0,
            outputs: &outputs,
            context: &context,
            sighash_type,
        })
        .expect("valid version-zero sighash")
    };

    assert_ne!(calculate(&inputs, 0x01), calculate(&changed_inputs, 0x01));
    assert_eq!(calculate(&inputs, 0x81), calculate(&changed_inputs, 0x81));
}

#[derive(Clone, Copy)]
enum ExactVectorMutation {
    None,
    OtherSequence,
    Payload,
    OtherSigOpCount,
    NonMatchingOutput,
    MatchingOutput,
    OtherPreviousOutput,
    EmptyPayload,
}

fn exact_full_vector(sighash_type: u8, mutation: ExactVectorMutation) -> String {
    let first_transaction_id = if matches!(mutation, ExactVectorMutation::OtherPreviousOutput) {
        [0x12; 32]
    } else {
        [0x11; 32]
    };
    let second_transaction_id = [0x22; 32];
    let first = FullSighashInput {
        transaction_id: &first_transaction_id,
        index: 1,
        amount: 1_000,
        sequence: if matches!(mutation, ExactVectorMutation::OtherSequence) {
            6
        } else {
            5
        },
        sig_op_count: if matches!(mutation, ExactVectorMutation::OtherSigOpCount) {
            4
        } else {
            2
        },
        spk_version: 0,
        spk_script: &[0x20, 0xaa],
    };
    let second = FullSighashInput {
        transaction_id: &second_transaction_id,
        index: 2,
        amount: 2_000,
        sequence: 9,
        sig_op_count: 3,
        spk_version: 1,
        spk_script: &[0x51, 0xac],
    };
    let inputs = [first, second];
    let outputs = [
        SighashOutput {
            value: if matches!(mutation, ExactVectorMutation::NonMatchingOutput) {
                701
            } else {
                700
            },
            spk_version: 0,
            spk_script: vec![0x51],
            covenant: None,
        },
        SighashOutput {
            value: if matches!(mutation, ExactVectorMutation::MatchingOutput) {
                1_201
            } else {
                1_200
            },
            spk_version: 1,
            spk_script: vec![0x52, 0xac],
            covenant: Some((0, [0x33; 32])),
        },
        SighashOutput {
            value: 100,
            spk_version: 0,
            spk_script: vec![0x53],
            covenant: None,
        },
    ];
    let subnetwork_id = [0x44; 20];
    let payload: &[u8] = match mutation {
        ExactVectorMutation::Payload => b"abd",
        ExactVectorMutation::EmptyPayload => b"",
        _ => b"abc",
    };
    let context = SighashContext {
        subnetwork_id: &subnetwork_id,
        gas: 7,
        locktime: 11,
        payload,
    };

    hex::encode(
        compute_full_sighash(FullSighashRequest {
            tx_version: 0,
            inputs: &inputs,
            input_index: 1,
            outputs: &outputs,
            context: &context,
            sighash_type,
        })
        .expect("exact full sighash vector"),
    )
}

#[test]
fn full_sighash_every_mode_has_a_byte_exact_vector() {
    for (sighash_type, expected) in [
        (
            0x01,
            "224df12ad73ce66f8cc79f144faea6374ebdc24a7169495cd59d0b85a2694072",
        ),
        (
            0x02,
            "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0",
        ),
        (
            0x04,
            "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892",
        ),
        (
            0x81,
            "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37",
        ),
        (
            0x82,
            "09169a7d19a3d99107209644b39087940ba3f7c397021081b08d766c49522f75",
        ),
        (
            0x84,
            "d3ce2184238d90c89f2f0072153d01355b6cdad8e57cb5c8c81c40f337c5690f",
        ),
    ] {
        assert_eq!(
            exact_full_vector(sighash_type, ExactVectorMutation::None),
            expected
        );
    }
}

#[test]
fn full_sighash_mode_components_bind_exactly_the_fields_the_mode_selects() {
    // Other-input sequence is committed by ALL only. NONE, SINGLE, and
    // ANYONECANPAY intentionally zero the aggregate sequence component.
    assert_eq!(
        exact_full_vector(0x01, ExactVectorMutation::OtherSequence),
        "115a4d4cad47fcd9d40fba8e464464e921f2006d0051c12bfda4f9693caa882a"
    );
    assert_eq!(
        exact_full_vector(0x02, ExactVectorMutation::OtherSequence),
        "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0"
    );
    assert_eq!(
        exact_full_vector(0x04, ExactVectorMutation::OtherSequence),
        "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892"
    );
    assert_eq!(
        exact_full_vector(0x81, ExactVectorMutation::OtherSequence),
        "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37"
    );

    // Version-zero sig-op aggregation follows the same ANYONECANPAY boundary.
    assert_eq!(
        exact_full_vector(0x01, ExactVectorMutation::OtherSigOpCount),
        "aa945d72312d7b47af2e62fc34b16b7ba75d261ab5855180dcdc708dc8129471"
    );
    assert_eq!(
        exact_full_vector(0x81, ExactVectorMutation::OtherSigOpCount),
        "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37"
    );

    // ANYONECANPAY excludes the other input's previous outpoint completely.
    assert_eq!(
        exact_full_vector(0x01, ExactVectorMutation::OtherPreviousOutput),
        "4b6ef93ba69596b6c8e30396043b87d7e3a388ccd2774755d223e9f4758b568e"
    );
    assert_eq!(
        exact_full_vector(0x81, ExactVectorMutation::OtherPreviousOutput),
        "b61009b8a8adb253b4fd141fb727704133e00dc950f81e5580c2cb225c2e9f37"
    );

    // NONE commits no outputs. SINGLE commits output[input_index] and ignores
    // every other output. ALL commits every output.
    assert_eq!(
        exact_full_vector(0x01, ExactVectorMutation::NonMatchingOutput),
        "3ad156bb54a21b3f62f8a9036a4408042ba8e42cb1fb3e0c5220b1fe3dee4cc5"
    );
    assert_eq!(
        exact_full_vector(0x02, ExactVectorMutation::NonMatchingOutput),
        "3fd7364f751948c0d2e145f246d743a9b3ac9736b2df2a5e256184dc33aad5c0"
    );
    assert_eq!(
        exact_full_vector(0x04, ExactVectorMutation::NonMatchingOutput),
        "08d9501be22bdbc4e3bc3b85a39e2e33709274265889007d49b99e805eb04892"
    );
    assert_eq!(
        exact_full_vector(0x04, ExactVectorMutation::MatchingOutput),
        "6246fc2641678aeca851a7865656a70cbb16e964ed26a78ea30a9e46f7bfa4ec"
    );
    assert_eq!(
        exact_full_vector(0x84, ExactVectorMutation::NonMatchingOutput),
        "d3ce2184238d90c89f2f0072153d01355b6cdad8e57cb5c8c81c40f337c5690f"
    );
    assert_eq!(
        exact_full_vector(0x84, ExactVectorMutation::MatchingOutput),
        "96109d55ff9dff46c01e7cf8a4ebf535b205b9caab16ad3c39dbe23603dbc383"
    );
}

#[test]
fn full_sighash_payload_is_byte_exact_for_every_mode_and_non_native_empty_payload() {
    for (sighash_type, expected) in [
        (
            0x01,
            "86f8407d58458c63f27ba9339e791ecd795ba108f6bb41725f2e1901e42cde04",
        ),
        (
            0x02,
            "97cfabcdf55909620073c9a2181d5e68a91cf747fc96115dbf70aab21b55f857",
        ),
        (
            0x04,
            "f966a9a8d05bd527a36552b58c90d650b51e4602ddb8362a734dd496b809cfa8",
        ),
        (
            0x81,
            "3570761a65bebfe297093ff7c3c64294442152f648ee33ba30ed040eee6a7fef",
        ),
        (
            0x82,
            "ce8ccb9e4542988be2c022f9007e36ab030fa09a4817a586a5ee697a4b15fd11",
        ),
        (
            0x84,
            "06a80a151d069073f6bed2f23eb0591c9eb06d656c946c1fc124edd1109d31a5",
        ),
    ] {
        assert_eq!(
            exact_full_vector(sighash_type, ExactVectorMutation::Payload),
            expected
        );
    }

    // Empty payload is represented by zero only for the native subnetwork.
    // A non-native transaction still commits the encoded zero-length payload.
    assert_eq!(
        exact_full_vector(0x01, ExactVectorMutation::EmptyPayload),
        "018ffeecd45ca1b316cac30e3a31e0391b09a5e4f77422777f38f912e07e882a"
    );
}

#[test]
fn full_sighash_native_non_empty_payload_has_a_byte_exact_vector() {
    let transaction_id = [0x11; 32];
    let outputs = [SighashOutput {
        value: 5,
        spk_version: 0,
        spk_script: vec![0x51],
        covenant: None,
    }];
    let inputs = [FullSighashInput {
        transaction_id: &transaction_id,
        index: 2,
        amount: 4,
        sequence: 3,
        sig_op_count: 0,
        spk_version: 0,
        spk_script: &[0x51],
    }];
    let context = native_context(6, b"abc");

    let hash = compute_full_sighash(FullSighashRequest {
        tx_version: 1,
        inputs: &inputs,
        input_index: 0,
        outputs: &outputs,
        context: &context,
        sighash_type: 0x01,
    })
    .expect("valid native payload sighash");

    assert_eq!(
        hex::encode(hash),
        "6560ebb918d6082936a3b90ccde07bbab0ea582889c19e1602abdcafb2adbd6f"
    );
}
