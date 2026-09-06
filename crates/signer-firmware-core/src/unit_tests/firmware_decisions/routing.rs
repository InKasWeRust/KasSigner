use crate::storage::routing::{import_route, import_scan_plan, ImportRoute, ImportScanPlan};

#[test]
fn every_import_menu_slot_has_one_stable_route_and_scan_plan() {
    let expected = [
        (ImportRoute::WalletBackup, ImportScanPlan::Rule(0)),
        (ImportRoute::Transaction, ImportScanPlan::Rule(1)),
        (ImportRoute::Kpub, ImportScanPlan::Rule(2)),
        (ImportRoute::MultisigAddress, ImportScanPlan::Rule(3)),
        (ImportRoute::MultisigDescriptor, ImportScanPlan::Rule(4)),
        (ImportRoute::CovenantBackup, ImportScanPlan::Rule(5)),
    ];
    for (item, (route, plan)) in expected.into_iter().enumerate() {
        assert_eq!(import_route(item as u8), Some(route));
        assert_eq!(import_scan_plan(item as u8), Some(plan));
        assert_eq!(plan.handler_index(), 0);
        assert_eq!(plan.rule_index(), item);
    }
    assert_eq!(import_route(6), None);
    assert_eq!(import_scan_plan(6), None);
    assert_eq!(import_route(u8::MAX), None);
    assert_eq!(import_scan_plan(u8::MAX), None);
}
