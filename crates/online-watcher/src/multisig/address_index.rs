use super::{build_redeem_script, MultisigDescriptor};

const MAX_DISCOVERY_INDEX: u32 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedMultisigPath {
    pub index: u32,
    pub cosigner: u32,
    pub chain: u32,
}

pub fn resolve_address_path(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    requested_index: u32,
) -> Result<ResolvedMultisigPath, String> {
    if !descriptor.is_hd() {
        return Ok(ResolvedMultisigPath {
            index: requested_index,
            cosigner: 0,
            chain: 0,
        });
    }
    scan_hierarchical_path(descriptor, source_address)
}

fn scan_hierarchical_path(
    descriptor: &MultisigDescriptor,
    source_address: &str,
) -> Result<ResolvedMultisigPath, String> {
    let prefix = address_prefix(source_address);
    let (cosigners, chains) = scan_shape(descriptor);
    for chain in 0..chains {
        for cosigner in 0..cosigners {
            if let Some(path) = scan_family(descriptor, source_address, prefix, cosigner, chain)? {
                return Ok(path);
            }
        }
    }
    Err(format!("Could not find address index for multisig source address {source_address} within supported derivation scan"))
}

fn scan_shape(descriptor: &MultisigDescriptor) -> (u32, u32) {
    if descriptor.is_hd45() {
        return (descriptor.participant_count() as u32, 2);
    }
    (1, 1)
}

fn scan_family(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    prefix: &str,
    cosigner: u32,
    chain: u32,
) -> Result<Option<ResolvedMultisigPath>, String> {
    for index in 0..MAX_DISCOVERY_INDEX {
        if address_at(descriptor, prefix, cosigner, chain, index)? == source_address {
            return Ok(Some(ResolvedMultisigPath {
                index,
                cosigner,
                chain,
            }));
        }
    }
    Ok(None)
}

fn address_at(
    descriptor: &MultisigDescriptor,
    prefix: &str,
    cosigner: u32,
    chain: u32,
    index: u32,
) -> Result<String, String> {
    let public_keys = descriptor.public_keys_at(index, cosigner, chain)?;
    let script = build_redeem_script(descriptor.threshold(), &public_keys)?;
    crate::protocol::script::p2sh::script_to_address(&script, prefix)
}

fn address_prefix(address: &str) -> &str {
    match address.split_once(':') {
        Some((prefix, _)) => prefix,
        None => "kaspa",
    }
}
