use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

use super::crowdfund::{fetch_contributions, summarize_contributions, ContributionRef};
use crate::account::utxo::UtxoEntry;

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test future unexpectedly required network progress"),
    }
}

fn reference(address: &str) -> ContributionRef {
    ContributionRef {
        address: address.to_string(),
        contributor_pubkey_hex: "11".repeat(32),
        redeem_script_hex: "51".to_string(),
        crowdfund_salt_hex: "22".repeat(8),
    }
}

fn utxo(byte: u8, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: vec![0, 0, 0x51],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn crowdfund_helpers_have_host_native_coverage() {
    let summary = summarize_contributions(vec![
        (reference("kaspa:one"), vec![utxo(1, 4), utxo(2, 5)]),
        (reference("kaspa:two"), vec![utxo(3, 6)]),
    ])
    .expect("summary");
    let value: serde_json::Value = serde_json::from_str(&summary).expect("summary json");
    assert_eq!(value["total_sompi"], "15");
    assert_eq!(value["input_count"], 3);
    assert_eq!(value["contributions"][0]["amount_sompi"], "9");

    let error = summarize_contributions(vec![
        (reference("kaspa:max"), vec![utxo(4, u64::MAX)]),
        (reference("kaspa:overflow"), vec![utxo(5, 1)]),
    ])
    .expect_err("grand total overflow");
    assert_eq!(error, "Crowdfund total overflow");

    let fetched = ready(fetch_contributions(&[], "unused")).expect("empty fetch");
    assert!(fetched.is_empty());
}
