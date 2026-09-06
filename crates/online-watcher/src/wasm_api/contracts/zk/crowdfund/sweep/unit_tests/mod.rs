use std::{
        future::Future,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };

    use super::*;

    struct NoopWake;
    impl Wake for NoopWake { fn wake(self: Arc<Self>) {} }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly required network progress"),
        }
    }

    fn reference() -> ContributionRef {
        ContributionRef {
            address: "kaspa:test".to_string(),
            contributor_pubkey_hex: "11".repeat(32),
            redeem_script_hex: "51".to_string(),
            crowdfund_salt_hex: "22".repeat(8),
        }
    }

    fn utxo(amount: u64) -> UtxoEntry {
        UtxoEntry {
            tx_id: "33".repeat(32),
            index: 0,
            amount,
            script_public_key: vec![0, 0, 0x51],
            block_daa_score: 0,
            covenant_id: None,
        }
    }

    #[test]
    fn inspection_helpers_cover_totals_overflow_empty_fetch_and_invalid_json() {
        let summary = summarize_contributions(vec![(reference(), vec![utxo(4), utxo(5)])])
            .expect("summary");
        let value: serde_json::Value = serde_json::from_str(&summary).unwrap();
        assert_eq!(value["total_sompi"], "9");
        assert_eq!(value["input_count"], 2);
        assert_eq!(checked_total(&[utxo(u64::MAX), utxo(1)]).unwrap_err(), "Crowdfunding balance overflow");
        assert!(require_nonempty_contribution(&reference(), Vec::new()).is_err());
        assert!(ready(fetch_contributions(&[], "unused")).unwrap().is_empty());
        assert!(ready(inspect_crowdfund_contributions_string("[]", "unused")).is_err());
        assert!(ready(create_crowdfund_sweep_string(
            "[]", "kaspa:test", 1, 1, "00", "00", "00", 1, "unused",
        )).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sweep_wasm_facades_and_submit_path_fail_closed_before_network() {
        assert!(ready(inspect_crowdfund_contributions("[]", "ws://unused")).is_err());
        assert!(ready(create_crowdfund_sweep(
            "[]", "bad-address", 1, 1, "00", "00", "00", 1, "ws://unused",
        )).is_err());

        let request = CrowdfundSweepRequest {
            contributions_json: "[]",
            organizer_address: "bad-address",
            goal_sompi: 1,
            locktime_daa: 1,
            verifying_key_hex: "00",
            proof_hex: "00",
            public_input_hex: "00",
            requested_fee: 1,
            fetched: Vec::new(),
        };
        assert!(ready(submit_crowdfund_sweep(request, "ws://unused")).is_err());
    }
