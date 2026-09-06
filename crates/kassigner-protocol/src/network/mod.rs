use core::fmt;
use serde::{Deserialize, Serialize};

use crate::error::ProtocolError;

#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    Mainnet,
    Testnet10,
    Testnet11,
    Testnet12,
    Devnet,
    Simnet,
}

impl Network {
    const NAMES: [&'static str; 6] = [
        "mainnet",
        "testnet-10",
        "testnet-11",
        "testnet-12",
        "devnet",
        "simnet",
    ];
    const ADDRESS_PREFIXES: [&'static str; 6] = [
        "kaspa",
        "kaspatest",
        "kaspatest",
        "kaspatest",
        "kaspadev",
        "kaspasim",
    ];
    const KSPT_CODES: [u8; 6] = [1, 2, 2, 2, 3, 4];
    const PARSE_TABLE: [(&'static str, Network); 6] = [
        ("mainnet", Network::Mainnet),
        ("testnet-10", Network::Testnet10),
        ("testnet-11", Network::Testnet11),
        ("testnet-12", Network::Testnet12),
        ("devnet", Network::Devnet),
        ("simnet", Network::Simnet),
    ];

    #[must_use]
    pub const fn address_prefix(self) -> &'static str {
        Self::ADDRESS_PREFIXES[self as usize]
    }

    #[must_use]
    pub const fn kspt_code(self) -> u8 {
        Self::KSPT_CODES[self as usize]
    }

    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        Self::try_from(value)
    }

    const fn name(self) -> &'static str {
        Self::NAMES[self as usize]
    }
}

impl TryFrom<&str> for Network {
    type Error = ProtocolError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::PARSE_TABLE
            .iter()
            .find_map(|(name, network)| (*name == value).then_some(*network))
            .ok_or_else(|| {
                ProtocolError::wrong_network(format!("unsupported Kaspa network: {value}"))
            })
    }
}

impl fmt::Display for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
