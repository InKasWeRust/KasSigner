#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Subscribe,
    #[cfg(any(target_arch = "wasm32", test))]
    GetSink,
    SubmitTransaction,
    GetBlock,
    GetBlockDagInfo,
    GetUtxosByAddresses,
    GetFeeEstimate,
}

impl Operation {
    pub const fn code(self) -> u8 {
        match self {
            Self::Subscribe => 3,
            #[cfg(any(target_arch = "wasm32", test))]
            Self::GetSink => 120,
            Self::SubmitTransaction => 125,
            Self::GetBlock => 126,
            Self::GetBlockDagInfo => 131,
            Self::GetUtxosByAddresses => 135,
            Self::GetFeeEstimate => 147,
        }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            3 => Some(Self::Subscribe),
            120 => Some(Self::GetSink),
            125 => Some(Self::SubmitTransaction),
            126 => Some(Self::GetBlock),
            131 => Some(Self::GetBlockDagInfo),
            135 => Some(Self::GetUtxosByAddresses),
            147 => Some(Self::GetFeeEstimate),
            _ => None,
        }
    }
}
