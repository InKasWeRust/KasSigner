#[test]
fn covenant_locktime_wasm_adapters_are_host_testable() {
    let owner = [0x11; 32];
    let beneficiary = [0x22; 32];
    let csv = crate::contracts::covenant::script::build_dms_csv_script(&owner, &beneficiary, 42);
    assert_eq!(super::extract_csv_sequence(&csv).unwrap(), 42);

    let cltv = crate::contracts::covenant::script::build_timelocked_savings_script(
        &owner,
        &beneficiary,
        99,
    );
    assert_eq!(super::extract_cltv_locktime(&cltv).unwrap(), 99);
    assert_eq!(super::extract_csv_sequence(&[0x51]).unwrap(), 0);
    assert_eq!(super::extract_cltv_locktime(&[0x51]).unwrap(), 0);
}
