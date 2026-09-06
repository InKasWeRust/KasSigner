#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactKsptSignature {
    pub(crate) pubkey_pos: u8,
    pub(crate) sighash_type: u8,
    pub(crate) signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactKsptInput {
    pub(crate) previous_tx_id: [u8; 32],
    pub(crate) previous_index: u32,
    pub(crate) amount: u64,
    pub(crate) sequence: u64,
    pub(crate) sig_op_count: u8,
    pub(crate) script_version: u16,
    pub(crate) script: Vec<u8>,
    pub(crate) signatures: Vec<CompactKsptSignature>,
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) derivation: Option<(u8, u32)>,
    pub(crate) ms45_derivation: Option<(u32, u32, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactKsptOutput {
    pub(crate) value: u64,
    pub(crate) script_version: u16,
    pub(crate) script: Vec<u8>,
    pub(crate) covenant: Option<(u16, [u8; 32])>,
    pub(crate) derivation: Option<(u8, u32)>,
    pub(crate) ms45_derivation: Option<(u32, u32, u32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompactKsptTransaction {
    pub(crate) generation: u8,
    pub(crate) flags: u8,
    pub(crate) version: u16,
    pub(crate) locktime: u64,
    pub(crate) subnetwork_id: [u8; 20],
    pub(crate) gas: u64,
    pub(crate) payload: Vec<u8>,
    pub(crate) network: u8,
    pub(crate) inputs: Vec<CompactKsptInput>,
    pub(crate) outputs: Vec<CompactKsptOutput>,
    pub(crate) stealth_tweak: Option<[u8; 32]>,
}
