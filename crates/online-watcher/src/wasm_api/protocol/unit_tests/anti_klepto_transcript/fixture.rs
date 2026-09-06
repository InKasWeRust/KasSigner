use offline_signer::{
    derivation::bip32::compressed_pubkey_from_raw_key,
    transaction::{
        kspt::{
            finalize_raw_key_signatures, initial_signature_counts, nonce_commitment_records,
            parse_compact_kspt, proof_records, serialize_compact_kspt_vec,
            sign_transaction_in_place_with_entropy,
        },
        model::{SigHashType, Transaction},
        sighash::sign_input_with_entropy,
    },
};
use shared_signer::anti_klepto::{self, NonceCommitment, SignatureProof};

#[derive(Clone, Copy)]
enum InputScript {
    P2pk,
    P2shMultisig,
}

pub(super) struct TranscriptFixture {
    pub(super) request_wire: Vec<u8>,
    pub(super) commitment_records: Vec<NonceCommitment>,
    pub(super) proofs: Vec<SignatureProof>,
    pub(super) provisional_tx_wire: Vec<u8>,
    pub(super) signed_tx_wire: Vec<u8>,
    pub(super) host_secret: [u8; 32],
    session_id: [u8; anti_klepto::SESSION_ID_LEN],
    transaction_digest: [u8; anti_klepto::HASH_LEN],
}

impl TranscriptFixture {
    pub(super) fn p2pk_two_inputs() -> Self {
        Self::new(InputScript::P2pk, 2)
    }

    pub(super) fn p2sh_multisig() -> Self {
        Self::new(InputScript::P2shMultisig, 1)
    }

    pub(super) fn p2pk_unexpected_none_sighash() -> Self {
        Self::new_with_sighash(InputScript::P2pk, 1, SigHashType::None)
    }

    pub(super) fn p2sh_with_existing_none_signature() -> Self {
        let first_key = [1u8; 32];
        let added_key = [2u8; 32];
        let host_secret = [0x42u8; 32];
        let mut original = anti_klepto_transaction(&first_key, InputScript::P2shMultisig, 1);
        add_existing_signature(&mut original, &first_key, SigHashType::None);
        let original_wire = serialize_compact_kspt_vec(&original).expect("original compact KSPT");
        let begin = crate::wasm_api::protocol::anti_klepto::anti_klepto_begin_with_secret_string(
            &hex::encode(&original_wire),
            &host_secret,
        )
        .expect("anti-klepto begin");
        let begin: serde_json::Value = serde_json::from_str(&begin).expect("begin JSON");
        let request_wire =
            hex::decode(begin["requestHex"].as_str().expect("request hex")).expect("request wire");
        let request = anti_klepto::parse_request(&request_wire).expect("request parse");

        let mut signed = test_transaction();
        parse_compact_kspt(request.transaction, &mut signed).expect("request transaction");
        let initial_counts = initial_signature_counts(&signed);
        assert_eq!(&initial_counts[..signed.num_inputs], &[1]);
        add_provisional_signature(&mut signed, &added_key, SigHashType::None);
        let commitment_records =
            nonce_commitment_records(&signed, &initial_counts).expect("nonce commitments");
        assert_eq!(commitment_records.len(), 1);
        assert_eq!(commitment_records[0].signature_slot, 1);
        let provisional_tx_wire =
            serialize_compact_kspt_vec(&signed).expect("provisional compact KSPT");

        let session_id = request.session_id;
        let transaction_digest = request.transaction_digest;
        let commitment_hex =
            encode_commitment_hex(&session_id, &transaction_digest, &commitment_records);
        crate::wasm_api::protocol::anti_klepto::anti_klepto_accept_commitment_string(
            begin["requestHex"].as_str().expect("request hex"),
            &commitment_hex,
            begin["hostSecretHex"].as_str().expect("host secret hex"),
        )
        .expect("valid signer commitment");

        finalize_raw_key_signatures(
            &mut signed,
            &added_key,
            &initial_counts,
            &session_id,
            &host_secret,
        )
        .expect("final signatures");
        let proofs = proof_records(&signed, &initial_counts).expect("signature proofs");
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].signature_slot, 1);
        let signed_tx_wire = serialize_compact_kspt_vec(&signed).expect("signed compact KSPT");

        Self {
            request_wire,
            commitment_records,
            proofs,
            provisional_tx_wire,
            signed_tx_wire,
            host_secret,
            session_id,
            transaction_digest,
        }
    }

    fn new(script_kind: InputScript, input_count: usize) -> Self {
        Self::new_with_sighash(script_kind, input_count, SigHashType::All)
    }

    fn new_with_sighash(
        script_kind: InputScript,
        input_count: usize,
        signing_sighash: SigHashType,
    ) -> Self {
        let private_key = [1u8; 32];
        let host_secret = [0x42u8; 32];
        let original = anti_klepto_transaction(&private_key, script_kind, input_count);
        let original_wire = serialize_compact_kspt_vec(&original).expect("original compact KSPT");
        let begin = crate::wasm_api::protocol::anti_klepto::anti_klepto_begin_with_secret_string(
            &hex::encode(&original_wire),
            &host_secret,
        )
        .expect("anti-klepto begin");
        let begin: serde_json::Value = serde_json::from_str(&begin).expect("begin JSON");
        let request_wire =
            hex::decode(begin["requestHex"].as_str().expect("request hex")).expect("request wire");
        let request = anti_klepto::parse_request(&request_wire).expect("request parse");

        let mut signed = test_transaction();
        parse_compact_kspt(request.transaction, &mut signed).expect("request transaction");
        let initial_counts = initial_signature_counts(&signed);
        sign_transaction_in_place_with_entropy(
            &mut signed,
            &private_key,
            signing_sighash,
            &[0x71; 32],
        )
        .expect("provisional signatures");
        let commitment_records =
            nonce_commitment_records(&signed, &initial_counts).expect("nonce commitments");
        assert_eq!(commitment_records.len(), input_count);
        let provisional_tx_wire =
            serialize_compact_kspt_vec(&signed).expect("provisional compact KSPT");

        let session_id = request.session_id;
        let transaction_digest = request.transaction_digest;
        let commitment_hex =
            encode_commitment_hex(&session_id, &transaction_digest, &commitment_records);
        crate::wasm_api::protocol::anti_klepto::anti_klepto_accept_commitment_string(
            begin["requestHex"].as_str().expect("request hex"),
            &commitment_hex,
            begin["hostSecretHex"].as_str().expect("host secret hex"),
        )
        .expect("valid signer commitment");

        finalize_raw_key_signatures(
            &mut signed,
            &private_key,
            &initial_counts,
            &session_id,
            &host_secret,
        )
        .expect("final signatures");
        let proofs = proof_records(&signed, &initial_counts).expect("signature proofs");
        assert_eq!(proofs.len(), input_count);
        let signed_tx_wire = serialize_compact_kspt_vec(&signed).expect("signed compact KSPT");

        Self {
            request_wire,
            commitment_records,
            proofs,
            provisional_tx_wire,
            signed_tx_wire,
            host_secret,
            session_id,
            transaction_digest,
        }
    }

    pub(super) fn request_hex(&self) -> String {
        hex::encode(&self.request_wire)
    }

    pub(super) fn original_transaction(&self) -> &[u8] {
        anti_klepto::parse_request(&self.request_wire)
            .expect("request parse")
            .transaction
    }

    pub(super) fn host_secret_hex(&self) -> String {
        hex::encode(self.host_secret)
    }

    pub(super) fn commitment_hex(&self, records: &[NonceCommitment]) -> String {
        encode_commitment_hex(&self.session_id, &self.transaction_digest, records)
    }

    pub(super) fn signed_message_hex(
        &self,
        proofs: &[SignatureProof],
        transaction: &[u8],
    ) -> String {
        let mut output = vec![0u8; transaction.len().saturating_add(512)];
        let length = anti_klepto::encode_signed(
            &self.session_id,
            &self.transaction_digest,
            proofs,
            transaction,
            &mut output,
        )
        .expect("signed response encode");
        hex::encode(&output[..length])
    }

    pub(super) fn verify_public(&self) -> Result<String, String> {
        self.verify_public_with(&self.commitment_records, &self.proofs, &self.signed_tx_wire)
    }

    pub(super) fn verify_public_with(
        &self,
        records: &[NonceCommitment],
        proofs: &[SignatureProof],
        transaction: &[u8],
    ) -> Result<String, String> {
        crate::wasm_api::protocol::anti_klepto::anti_klepto_verify_signed_string(
            &self.request_hex(),
            &self.commitment_hex(records),
            &self.signed_message_hex(proofs, transaction),
            &self.host_secret_hex(),
        )
    }

    pub(super) fn accept_commitment(&self, records: &[NonceCommitment]) -> Result<String, String> {
        crate::wasm_api::protocol::anti_klepto::anti_klepto_accept_commitment_string(
            &self.request_hex(),
            &self.commitment_hex(records),
            &self.host_secret_hex(),
        )
    }

    pub(super) fn mutate_signed_transaction(&self, mutate: fn(&mut Transaction)) -> Vec<u8> {
        let mut transaction = test_transaction();
        parse_compact_kspt(&self.signed_tx_wire, &mut transaction)
            .expect("signed transaction parse");
        mutate(&mut transaction);
        serialize_compact_kspt_vec(&transaction).expect("mutated signed transaction")
    }

    pub(super) fn mutate_original_transaction(&self, mutate: fn(&mut Transaction)) -> Vec<u8> {
        let request = anti_klepto::parse_request(&self.request_wire).expect("request parse");
        let mut transaction = test_transaction();
        parse_compact_kspt(request.transaction, &mut transaction)
            .expect("original transaction parse");
        mutate(&mut transaction);
        serialize_compact_kspt_vec(&transaction).expect("mutated original transaction")
    }

    pub(super) fn validate_commitment_against(
        &self,
        transaction: &[u8],
        records: &[NonceCommitment],
    ) -> Result<(), String> {
        let commitment_wire = hex::decode(self.commitment_hex(records)).expect("commitment wire");
        let commitment = anti_klepto::parse_commitment(&commitment_wire).expect("commitment parse");
        crate::protocol::pskt::validate_host_commitment_wire(transaction, &commitment)
    }
}

fn add_existing_signature(tx: &mut Transaction, private_key: &[u8; 32], sighash_type: SigHashType) {
    let signature = sign_input_with_entropy(tx, 0, private_key, sighash_type, &[0x61; 32])
        .expect("existing signature");
    let compressed = compressed_pubkey_from_raw_key(private_key).expect("existing public key");
    let input = &mut tx.inputs[0];
    input.sigs[0].signature = signature.bytes;
    input.sigs[0].sighash_type = sighash_type.to_byte();
    input.sigs[0].pubkey_pos = 0;
    input.sigs[0].present = true;
    input.sigs[0].pubkey_compressed = compressed;
    input.sig_count = 1;
    input.sighash_type = sighash_type.to_byte();
}

fn add_provisional_signature(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    sighash_type: SigHashType,
) {
    let signature = sign_input_with_entropy(tx, 0, private_key, sighash_type, &[0x72; 32])
        .expect("provisional signature");
    let compressed = compressed_pubkey_from_raw_key(private_key).expect("provisional public key");
    let input = &mut tx.inputs[0];
    input.sigs[1].signature = signature.bytes;
    input.sigs[1].sighash_type = sighash_type.to_byte();
    input.sigs[1].pubkey_pos = 1;
    input.sigs[1].present = true;
    input.sigs[1].pubkey_compressed = compressed;
    input.sig_count = 2;
    input.sighash_type = sighash_type.to_byte();
}

fn test_transaction() -> Transaction {
    Transaction::try_new().expect("transaction allocation")
}

pub(super) fn canonical_public_key(private_key: [u8; 32]) -> [u8; 33] {
    let compressed = compressed_pubkey_from_raw_key(&private_key).expect("compressed public key");
    let mut public_key = [0u8; 33];
    public_key[0] = 0x02;
    public_key[1..].copy_from_slice(&compressed[1..33]);
    public_key
}

fn anti_klepto_transaction(
    private_key: &[u8; 32],
    script_kind: InputScript,
    input_count: usize,
) -> Transaction {
    let public_key = canonical_public_key(*private_key);
    let mut tx = test_transaction();
    tx.version = 1;
    tx.network = offline_signer::address::KaspaNetwork::Mainnet;
    tx.ensure_input_slots(input_count).expect("input slots");
    tx.num_inputs = input_count;
    tx.num_outputs = 1;
    for input_index in 0..input_count {
        {
            let input = &mut tx.inputs[input_index];
            input.previous_outpoint.transaction_id = [0x11u8.wrapping_add(input_index as u8); 32];
            input.previous_outpoint.index = 7 + input_index as u32;
            input.utxo_entry.amount = 100_000 + input_index as u64;
            input.sequence = u64::MAX - input_index as u64;
            input.sig_op_count = 1;
            input.sighash_type = SigHashType::All.to_byte();
        }
        match script_kind {
            InputScript::P2pk => set_p2pk_script(&mut tx, input_index, &public_key[1..33]),
            InputScript::P2shMultisig => {
                set_p2sh_multisig_script(&mut tx, input_index, &public_key[1..33]);
            }
        }
    }
    tx.outputs[0].value = 99_000;
    let output_script = &mut tx.outputs[0].script_public_key;
    output_script.script[0] = 0x20;
    output_script.script[1..33].fill(0x33);
    output_script.script[33] = 0xac;
    output_script.script_len = 34;
    tx
}

fn set_p2pk_script(tx: &mut Transaction, input_index: usize, xonly: &[u8]) {
    let script = &mut tx.inputs[input_index].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].copy_from_slice(xonly);
    script.script[33] = 0xac;
    script.script_len = 34;
}

fn set_p2sh_multisig_script(tx: &mut Transaction, input_index: usize, first_key: &[u8]) {
    let second_key = canonical_public_key([2u8; 32]);
    let script = &mut tx.inputs[input_index].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x55);
    script.script[34] = 0x87;
    script.script_len = 35;

    let mut redeem = Vec::with_capacity(69);
    redeem.push(0x52);
    redeem.push(0x20);
    redeem.extend_from_slice(first_key);
    redeem.push(0x20);
    redeem.extend_from_slice(&second_key[1..33]);
    redeem.extend_from_slice(&[0x52, 0xae]);
    tx.store_redeem(input_index, &redeem)
        .expect("multisig redeem script");
}

fn encode_commitment_hex(
    session_id: &[u8; anti_klepto::SESSION_ID_LEN],
    transaction_digest: &[u8; anti_klepto::HASH_LEN],
    records: &[NonceCommitment],
) -> String {
    let mut output = vec![0u8; 128usize.saturating_add(records.len().saturating_mul(80))];
    let length =
        anti_klepto::encode_commitment(session_id, transaction_digest, records, &mut output)
            .expect("commitment encode");
    hex::encode(&output[..length])
}

pub(super) fn minimal_compact_transaction(
    input_count: u32,
    output_count: u8,
    flags: u8,
) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(b"KSPT");
    wire.push(0x04);
    wire.push(flags);
    wire.extend_from_slice(&1u16.to_le_bytes());
    wire.extend_from_slice(&input_count.to_le_bytes());
    wire.push(output_count);
    wire.extend_from_slice(&0u64.to_le_bytes());
    wire.extend_from_slice(&[0u8; 20]);
    wire.extend_from_slice(&0u64.to_le_bytes());
    wire.extend_from_slice(&0u16.to_le_bytes());
    for index in 0..input_count {
        wire.extend_from_slice(&[0x10u8.wrapping_add(index as u8); 32]);
        wire.extend_from_slice(&index.to_le_bytes());
        wire.extend_from_slice(&100u64.to_le_bytes());
        wire.extend_from_slice(&u64::MAX.to_le_bytes());
        wire.push(1);
        wire.extend_from_slice(&0u16.to_le_bytes());
        wire.push(1);
        wire.push(0x51);
        wire.push(0);
        wire.extend_from_slice(&0u16.to_le_bytes());
    }
    for index in 0..output_count {
        wire.extend_from_slice(&(90 + u64::from(index)).to_le_bytes());
        wire.extend_from_slice(&0u16.to_le_bytes());
        wire.push(1);
        wire.push(0x51);
    }
    wire.extend_from_slice(&[b'N', 1]);
    wire
}
