#[derive(Clone, Debug)]
pub struct ConsensusInput {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub sig_script: Vec<u8>,
    pub sequence: u64,
    pub sig_op_count: u8,
}

#[derive(Clone, Debug)]
pub struct ConsensusOutput {
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEncoding {
    Compact,
    Budgeted,
}

#[derive(Clone, Debug)]
pub struct ConsensusTransaction {
    pub tx_version: u16,
    pub input_encoding: InputEncoding,
    pub inputs: Vec<ConsensusInput>,
    pub outputs: Vec<ConsensusOutput>,
    pub locktime: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
    /// KIP-9 storage-mass commitment submitted to kaspad.
    pub storage_mass: u64,
}
