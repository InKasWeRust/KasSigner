use crate::WalletData;

pub(crate) const KIP9_MIN_CHANGE_SOMPI: u64 = 10_000_000;

#[derive(Clone, Copy)]
pub(crate) enum CovenantEncoding<'a> {
    Payload {
        payload_hex: &'a str,
        tag_genesis: bool,
    },
    BoundGenesis,
}

impl<'a> CovenantEncoding<'a> {
    pub(crate) fn tag_genesis(self) -> bool {
        match self {
            Self::Payload { tag_genesis, .. } => tag_genesis,
            Self::BoundGenesis => true,
        }
    }

    pub(crate) fn uses_tagged_genesis_policy(self) -> bool {
        matches!(
            self,
            Self::Payload {
                tag_genesis: true,
                ..
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CovenantDustPolicy {
    Preserve,
    FoldSubKip9Change,
}

impl CovenantDustPolicy {
    pub(crate) fn for_type(covenant_type: &str) -> Self {
        const FOLD_SUB_KIP9_TYPES: [&str; 5] = [
            "additive",
            "timelocked-savings",
            "dms",
            "global-spending-limit",
            "global-allowance",
        ];
        if FOLD_SUB_KIP9_TYPES.contains(&covenant_type) {
            Self::FoldSubKip9Change
        } else {
            Self::Preserve
        }
    }
}

pub(crate) struct CovenantBuildRequest<'a> {
    pub(crate) wallet: &'a WalletData,
    pub(crate) covenant_address: &'a str,
    pub(crate) covenant_type: &'a str,
    pub(crate) send_amount: u64,
    pub(crate) fee: u64,
    pub(crate) change_address: &'a str,
    pub(crate) utxo_indices_csv: &'a str,
    pub(crate) websocket_url: &'a str,
    pub(crate) encoding: CovenantEncoding<'a>,
}
