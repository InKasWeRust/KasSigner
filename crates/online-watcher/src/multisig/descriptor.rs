use k256::elliptic_curve::sec1::ToEncodedPoint;
use kassigner_protocol::wire::multisig_descriptor::{
    parse_multisig_descriptor, MultisigDescriptorError, MultisigDescriptorKind,
    ParsedMultisigDescriptor,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hd45AccountKey {
    pub public_key: [u8; 33],
    pub chain_code: [u8; 32],
    pub parent_fingerprint: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultisigDescriptor {
    Static {
        threshold: u8,
        public_keys: Vec<[u8; 32]>,
    },
    HierarchicalDeterministic44 {
        threshold: u8,
        account_keys: Vec<([u8; 33], [u8; 32])>,
    },
    HierarchicalDeterministic45 {
        threshold: u8,
        account_keys: Vec<Hd45AccountKey>,
    },
}

impl MultisigDescriptor {
    pub fn parse(value: &str) -> Result<Self, String> {
        let parsed = parse_multisig_descriptor(value.as_bytes())
            .map_err(|error| descriptor_error(value, error))?;
        Self::from_canonical(parsed)
    }

    fn from_canonical(parsed: ParsedMultisigDescriptor) -> Result<Self, String> {
        let count = usize::from(parsed.participant_count);
        match parsed.kind {
            MultisigDescriptorKind::Static => Ok(Self::Static {
                threshold: parsed.threshold,
                public_keys: parsed.static_public_keys[..count].to_vec(),
            }),
            MultisigDescriptorKind::Hd44 => {
                let mut account_keys = Vec::with_capacity(count);
                for (&public_key, &chain_code) in parsed.public_keys[..count]
                    .iter()
                    .zip(&parsed.chain_codes[..count])
                {
                    k256::PublicKey::from_sec1_bytes(&public_key)
                        .map_err(|error| format!("Invalid compressed pubkey: {error}"))?;
                    account_keys.push((public_key, chain_code));
                }
                Ok(Self::HierarchicalDeterministic44 {
                    threshold: parsed.threshold,
                    account_keys,
                })
            }
            MultisigDescriptorKind::Hd45 => {
                let mut account_keys = Vec::with_capacity(count);
                for ((&public_key, &chain_code), &parent_fingerprint) in parsed.public_keys[..count]
                    .iter()
                    .zip(&parsed.chain_codes[..count])
                    .zip(&parsed.parent_fingerprints[..count])
                {
                    k256::PublicKey::from_sec1_bytes(&public_key)
                        .map_err(|error| format!("Invalid compressed pubkey: {error}"))?;
                    account_keys.push(Hd45AccountKey {
                        public_key,
                        chain_code,
                        parent_fingerprint,
                    });
                }
                Ok(Self::HierarchicalDeterministic45 {
                    threshold: parsed.threshold,
                    account_keys,
                })
            }
        }
    }

    #[must_use]
    pub fn is_hd(&self) -> bool {
        !matches!(self, Self::Static { .. })
    }
    #[must_use]
    pub fn is_hd45(&self) -> bool {
        matches!(self, Self::HierarchicalDeterministic45 { .. })
    }
    #[must_use]
    pub fn participant_count(&self) -> usize {
        match self {
            Self::Static { public_keys, .. } => public_keys.len(),
            Self::HierarchicalDeterministic44 { account_keys, .. } => account_keys.len(),
            Self::HierarchicalDeterministic45 { account_keys, .. } => account_keys.len(),
        }
    }
    #[must_use]
    pub fn threshold(&self) -> u8 {
        match self {
            Self::Static { threshold, .. }
            | Self::HierarchicalDeterministic44 { threshold, .. }
            | Self::HierarchicalDeterministic45 { threshold, .. } => *threshold,
        }
    }

    pub fn public_keys_at(
        &self,
        address_index: u32,
        cosigner: u32,
        chain: u32,
    ) -> Result<Vec<[u8; 32]>, String> {
        match self {
            Self::Static { public_keys, .. } => {
                let mut keys = public_keys.clone();
                keys.sort();
                Ok(keys)
            }
            Self::HierarchicalDeterministic44 { account_keys, .. } => {
                let mut keys = account_keys
                    .iter()
                    .map(|(pk, cc)| derive_44(pk, cc, address_index))
                    .collect::<Result<Vec<_>, _>>()?;
                keys.sort();
                Ok(keys)
            }
            Self::HierarchicalDeterministic45 { account_keys, .. } => {
                if chain > 1 {
                    return Err("45' multisig chain must be 0 or 1".into());
                }
                account_keys
                    .iter()
                    .map(|entry| derive_45(entry, cosigner, chain, address_index))
                    .collect()
            }
        }
    }

    pub fn bip32_derivations(
        &self,
        address_index: u32,
        cosigner: u32,
        chain: u32,
    ) -> Result<serde_json::Value, String> {
        let Self::HierarchicalDeterministic45 { account_keys, .. } = self else {
            return Ok(serde_json::json!({}));
        };
        let path = format!("m/45'/111111'/0'/{cosigner}/{chain}/{address_index}");
        let mut map = serde_json::Map::new();
        for entry in account_keys {
            let compressed = derived_45_compressed(entry, cosigner, chain, address_index)?;
            map.insert(
                hex::encode(compressed),
                serde_json::json!({
                    "keyFingerprint": hex::encode(entry.parent_fingerprint),
                    "derivationPath": path,
                }),
            );
        }
        Ok(serde_json::Value::Object(map))
    }
}

fn descriptor_error(value: &str, error: MultisigDescriptorError) -> String {
    match error {
        MultisigDescriptorError::InvalidParticipantLength => participant_length_error(value),
        MultisigDescriptorError::InvalidHex => invalid_hex_error(value),
        MultisigDescriptorError::InvalidCompressedPublicKey => "Invalid compressed pubkey".into(),
        MultisigDescriptorError::DuplicateParticipant => {
            "Duplicate cosigner kpub in descriptor".into()
        }
        other => other.message().into(),
    }
}

fn participant_length_error(value: &str) -> String {
    let length = descriptor_participant_length(value);
    if value.contains("multi_hd45(") {
        format!("45' cosigner kpub must be 111 characters, got {length}")
    } else if value.contains("multi_hd(") {
        format!("Cosigner xpub must be 130 hex chars, got {length}")
    } else {
        format!("Pubkey must be 64 hex chars, got {length}")
    }
}

fn invalid_hex_error(value: &str) -> String {
    if value.contains("multi_hd(") {
        "Invalid xpub hex".into()
    } else {
        "Invalid pubkey hex".into()
    }
}

fn descriptor_participant_length(value: &str) -> usize {
    let line = value
        .lines()
        .find(|line| line.trim_start().starts_with("multi"))
        .map(str::trim)
        .unwrap_or(value.trim());
    let Some(comma) = line.find(',') else {
        return 0;
    };
    let rest = &line[comma + 1..];
    rest.split([',', ')'])
        .next()
        .map(str::trim)
        .map(str::len)
        .unwrap_or(0)
}

fn parent(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
) -> Result<crate::account::bip32::ExtPubKey, String> {
    Ok(crate::account::bip32::ExtPubKey {
        key: k256::PublicKey::from_sec1_bytes(public_key)
            .map_err(|error| format!("Invalid compressed pubkey: {error}"))?,
        chain_code: *chain_code,
        depth: 3,
    })
}
fn derive_44(
    public_key: &[u8; 33],
    chain_code: &[u8; 32],
    address_index: u32,
) -> Result<[u8; 32], String> {
    let child = parent(public_key, chain_code)?
        .derive_child(0)?
        .derive_child(address_index)?;
    xonly(&child.key)
}
fn derived_45_compressed(
    entry: &Hd45AccountKey,
    cosigner: u32,
    chain: u32,
    address_index: u32,
) -> Result<[u8; 33], String> {
    let child = parent(&entry.public_key, &entry.chain_code)?
        .derive_child(cosigner)?
        .derive_child(chain)?
        .derive_child(address_index)?;
    child
        .key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| "Derived public key has invalid length".to_string())
}
fn derive_45(
    entry: &Hd45AccountKey,
    cosigner: u32,
    chain: u32,
    address_index: u32,
) -> Result<[u8; 32], String> {
    let compressed = derived_45_compressed(entry, cosigner, chain, address_index)?;
    compressed[1..33]
        .try_into()
        .map_err(|_| "Derived public key has invalid length".to_string())
}
fn xonly(key: &k256::PublicKey) -> Result<[u8; 32], String> {
    key.to_encoded_point(true).as_bytes()[1..33]
        .try_into()
        .map_err(|_| "Derived public key has invalid length".to_string())
}
