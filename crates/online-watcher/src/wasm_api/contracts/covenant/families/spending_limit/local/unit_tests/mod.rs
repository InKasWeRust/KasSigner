use super::OwnerSpendPlan;

#[test]
fn owner_spend_plan_construction_is_host_testable() {
    let plan = OwnerSpendPlan::new("51", "owner").expect("owner plan");
    assert_eq!(plan.redeem_script, vec![0x51]);
    assert_eq!(plan.branch, "owner");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn owner_spend_wasm_facade_rejects_bad_redeem_before_transport() {
    let result = crate::wasm_api::test_support::ready(super::create_covenant_owner_spend(
        "bad",
        "bad",
        "zz",
        1,
        "ws://unused",
        "owner",
    ));
    assert!(result.is_err());
}
