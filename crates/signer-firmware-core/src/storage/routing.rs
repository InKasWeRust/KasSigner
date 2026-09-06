//! Pure route selection for firmware SD import menus.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportRoute {
    WalletBackup,
    Transaction,
    Kpub,
    MultisigAddress,
    MultisigDescriptor,
    CovenantBackup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportScanPlan {
    Rule(usize),
}

impl ImportScanPlan {
    pub const fn handler_index(self) -> usize {
        0
    }
    pub const fn rule_index(self) -> usize {
        match self {
            Self::Rule(index) => index,
        }
    }
}

pub const fn import_route(item: u8) -> Option<ImportRoute> {
    match item {
        0 => Some(ImportRoute::WalletBackup),
        1 => Some(ImportRoute::Transaction),
        2 => Some(ImportRoute::Kpub),
        3 => Some(ImportRoute::MultisigAddress),
        4 => Some(ImportRoute::MultisigDescriptor),
        5 => Some(ImportRoute::CovenantBackup),
        _ => None,
    }
}

pub const fn import_scan_plan(item: u8) -> Option<ImportScanPlan> {
    match import_route(item) {
        Some(ImportRoute::WalletBackup) => Some(ImportScanPlan::Rule(0)),
        Some(ImportRoute::Transaction) => Some(ImportScanPlan::Rule(1)),
        Some(ImportRoute::Kpub) => Some(ImportScanPlan::Rule(2)),
        Some(ImportRoute::MultisigAddress) => Some(ImportScanPlan::Rule(3)),
        Some(ImportRoute::MultisigDescriptor) => Some(ImportScanPlan::Rule(4)),
        Some(ImportRoute::CovenantBackup) => Some(ImportScanPlan::Rule(5)),
        None => None,
    }
}
