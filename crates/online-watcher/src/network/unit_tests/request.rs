use crate::network::{
    codec::requests::subscription,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
    },
};

#[test]
fn request_encoding_is_stable() {
    let encoded = request::encode(&WrpcRequest {
        id: 0x0102_0304_0506_0708,
        operation: Operation::GetSink,
        payload: &[0xaa, 0xbb],
    })
    .expect("request should encode");

    assert_eq!(hex::encode(encoded), "0108070605040302017802000000aabb");
}

#[test]
fn block_subscription_vector_is_stable() {
    let encoded = subscription::block_added(7).expect("subscription should encode");
    assert_eq!(
        hex::encode(encoded),
        "010700000000000000030c000000010000000000020000000100"
    );
}

#[test]
fn all_request_codec_boundaries_are_covered() {
    use crate::network::codec::{
        primitives::WireWriter,
        requests::{address, block, fee, subscription, utxo},
    };

    let mainnet = crate::account::address::encode_p2pk_address(&[0x11; 32], "kaspa");
    let testnet = crate::account::address::encode_p2pk_address(&[0x12; 32], "kaspatest");
    let simnet = crate::account::address::encode_p2pk_address(&[0x13; 32], "kaspasim");
    let devnet = crate::account::address::encode_p2pk_address(&[0x14; 32], "kaspadev");

    for candidate in [&mainnet, &testnet, &simnet, &devnet] {
        let mut writer = WireWriter::new();
        address::write_address(&mut writer, candidate).expect("address request encoding");
        assert!(!writer.into_vec().is_empty());
    }

    let encoded = utxo::encode(&[mainnet.clone(), testnet.clone()]).expect("UTXO query");
    assert!(encoded.len() > 4);
    assert!(utxo::encode(&["not-an-address".to_string()]).is_err());

    let changed = subscription::utxos_changed(&mainnet, 9).expect("UTXO subscription");
    assert_eq!(changed.len(), 68);
    assert_eq!(changed[0], 1);
    assert_eq!(&changed[1..9], &9u64.to_le_bytes());
    assert_eq!(changed[9], Operation::Subscribe.code());
    assert_eq!(&changed[10..14], &54u32.to_le_bytes());
    assert_eq!(&changed[14..16], &1u16.to_le_bytes());
    assert_eq!(&changed[16..20], &4u32.to_le_bytes());
    assert_eq!(&changed[20..24], &44u32.to_le_bytes());

    assert_eq!(fee::encode(), vec![1, 0]);
    assert_eq!(block::encode_empty_query(), vec![1, 0]);
    let block_query = block::encode_get_block(&[0x22; 32]);
    assert_eq!(block_query.len(), 35);
    assert_eq!(&block_query[2..34], &[0x22; 32]);
}
