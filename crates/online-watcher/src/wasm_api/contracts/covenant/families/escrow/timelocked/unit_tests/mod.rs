use super::BeneficiarySweepPlan;
use crate::transaction_builder::covenant::sweep::SweepSourceKind;

#[test]
fn beneficiary_sweep_plan_construction_and_specs_are_host_testable() {
    let plan = BeneficiarySweepPlan::new("51", 42).expect("beneficiary plan");
    let selected = plan.spec("source", "destination", 7, SweepSourceKind::Selected);
    assert_eq!(selected.fee, 7);
    assert_eq!(selected.config.lock_time, 42);
    assert_eq!(selected.config.branch, Some("beneficiary"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn timelocked_wasm_sweep_facades_fail_closed_before_network() {
    use crate::wasm_api::test_support::ready;
    assert!(ready(super::create_covenant_timeout_refund(
        "bad",
        "bad",
        "zz",
        1,
        1,
        "ws://unused",
    ))
    .is_err());
    assert!(ready(super::create_covenant_beneficiary_spend(
        "bad",
        "bad",
        "zz",
        1,
        1,
        "ws://unused",
    ))
    .is_err());
}
