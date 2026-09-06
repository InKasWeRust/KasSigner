// KasSee Web — typed covenant routing context
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

use serde_json::{Map, Value};

pub(crate) struct SignerBranch {
    pub(crate) is_owner: bool,
    pub(crate) is_beneficiary: bool,
}

impl SignerBranch {
    pub(crate) fn detect(
        redeem_body: &[u8],
        partial_signatures: &Map<String, Value>,
        force_beneficiary: bool,
    ) -> Self {
        let owner_public_key = if redeem_body.len() >= 34 && redeem_body[1] == 0x20 {
            Some(hex::encode(&redeem_body[2..34]))
        } else {
            None
        };
        let beneficiary_public_key = find_beneficiary_public_key(redeem_body);
        let is_owner = if force_beneficiary {
            false
        } else {
            owner_public_key
                .as_deref()
                .is_some_and(|key| contains_signer(partial_signatures, key))
        };

        let is_beneficiary = if force_beneficiary {
            !partial_signatures.is_empty()
        } else {
            beneficiary_public_key
                .as_deref()
                .is_some_and(|key| contains_signer(partial_signatures, key))
        };

        Self {
            is_owner,
            is_beneficiary,
        }
    }
}

fn find_beneficiary_public_key(redeem_body: &[u8]) -> Option<String> {
    for offset in 34..redeem_body.len().saturating_sub(33) {
        if redeem_body[offset] != 0x67 {
            continue;
        }
        // The loop upper bound guarantees at least 34 bytes remain at `offset`.
        if redeem_body[offset + 1] == 0x20 {
            return Some(hex::encode(&redeem_body[offset + 2..offset + 34]));
        }
        if offset + 35 <= redeem_body.len()
            && redeem_body[offset + 1] == 0x63
            && redeem_body[offset + 2] == 0x20
        {
            return Some(hex::encode(&redeem_body[offset + 3..offset + 35]));
        }
    }
    None
}

fn contains_signer(partial_signatures: &Map<String, Value>, xonly_public_key: &str) -> bool {
    partial_signatures
        .keys()
        .any(|key| key.len() == 66 && key[2..] == xonly_public_key[..])
}

pub(crate) struct SignaturePolicy {
    pub(crate) minimum_signatures: u64,
}

pub(crate) struct PrivateSwapContext {
    pub(crate) claim: bool,
}

pub(crate) struct OracleContext {
    pub(crate) v1: OracleV1Context,
    pub(crate) model_b: OracleModelBContext,
}

pub(crate) struct OracleV1Context {
    pub(crate) claim: bool,
    pub(crate) signature: Option<Vec<u8>>,
}

pub(crate) struct OracleModelBContext {
    pub(crate) risc0: bool,
    pub(crate) passthrough: bool,
    pub(crate) heartbeat: bool,
    pub(crate) consumer: bool,
}

pub(crate) struct ProofContext {
    pub(crate) zk_proof: Option<Vec<u8>>,
    pub(crate) zk_public_inputs: Option<Vec<Vec<u8>>>,
    pub(crate) zk_verification_key: Option<Vec<u8>>,
    pub(crate) risc0_seal: Option<Vec<u8>>,
    pub(crate) risc0_fields: Option<Map<String, Value>>,
    pub(crate) risc0_bridge: bool,
    pub(crate) groth16_bridge: bool,
}

pub(crate) struct CommitRevealContext {
    pub(crate) part_a: Option<Vec<u8>>,
    pub(crate) part_b: Option<Vec<u8>>,
    pub(crate) preimage: Option<Vec<u8>>,
}

pub(crate) struct MerkleContext {
    pub(crate) proof: Option<String>,
    pub(crate) destination_script: Option<Vec<u8>>,
}

pub(crate) struct BridgeContext {
    pub(crate) withdrawal_script: Option<Vec<u8>>,
}

pub(crate) struct RollupContext {
    pub(crate) state_advance: bool,
    pub(crate) state_refund: bool,
    pub(crate) proof: Option<Vec<u8>>,
    pub(crate) prefix: Option<Vec<u8>>,
    pub(crate) suffix: Option<Vec<u8>>,
    pub(crate) deposit_advance: bool,
    pub(crate) unified_advance: bool,
    pub(crate) forced_exit: bool,
    pub(crate) deposit_holding_credit: bool,
    pub(crate) deposit_holding_refund: bool,
}

pub(crate) struct CovenantContext {
    pub(crate) signatures: SignaturePolicy,
    pub(crate) private_swap: PrivateSwapContext,
    pub(crate) oracle: OracleContext,
    pub(crate) proofs: ProofContext,
    pub(crate) commit_reveal: CommitRevealContext,
    pub(crate) merkle: MerkleContext,
    pub(crate) bridge: BridgeContext,
    pub(crate) rollup: RollupContext,
}

impl CovenantContext {
    pub(crate) fn parse(input: &Map<String, Value>) -> Self {
        let proprietary = input.get("proprietaries").and_then(Value::as_object);
        Self {
            signatures: SignaturePolicy {
                minimum_signatures: input
                    .get("minimumSignatures")
                    .and_then(Value::as_u64)
                    .unwrap_or(1),
            },
            private_swap: PrivateSwapContext {
                claim: bool_value(proprietary, "privateSwapClaim"),
            },
            oracle: OracleContext {
                v1: OracleV1Context {
                    claim: bool_value(proprietary, "oracleV1Claim"),
                    signature: decode_hex(proprietary, "oracleV1Signature"),
                },
                model_b: OracleModelBContext {
                    risc0: bool_value(proprietary, "risc0OracleMb"),
                    passthrough: bool_value(proprietary, "oracleMbPassthrough"),
                    heartbeat: bool_value(proprietary, "oracleMbHeartbeat"),
                    consumer: bool_value(proprietary, "oracleMbConsumer"),
                },
            },
            proofs: ProofContext {
                zk_proof: decode_hex(proprietary, "zkProof"),
                zk_public_inputs: decode_hex_array(proprietary, "zkPublicInputs"),
                zk_verification_key: decode_hex(proprietary, "zkVk"),
                risc0_seal: decode_hex(proprietary, "risc0Seal"),
                risc0_fields: object_value(proprietary, "risc0Fields"),
                risc0_bridge: bool_value(proprietary, "risc0Bridge"),
                groth16_bridge: bool_value(proprietary, "groth16Bridge"),
            },
            commit_reveal: CommitRevealContext {
                part_a: decode_hex(proprietary, "commitPartA"),
                part_b: decode_hex(proprietary, "commitPartB"),
                preimage: decode_hex(proprietary, "commitPreimage"),
            },
            merkle: MerkleContext {
                proof: string_value(proprietary, "merkleProof"),
                destination_script: decode_hex(proprietary, "merkleDestSpk"),
            },
            bridge: BridgeContext {
                withdrawal_script: decode_hex(proprietary, "withdrawalSpk"),
            },
            rollup: RollupContext {
                state_advance: bool_value(proprietary, "rollupStateAdvance"),
                state_refund: bool_value(proprietary, "rollupStateRefund"),
                proof: decode_hex(proprietary, "rollupProof"),
                prefix: decode_hex(proprietary, "rollupPrefix"),
                suffix: decode_hex(proprietary, "rollupSuffix"),
                deposit_advance: bool_value(proprietary, "rollupDepositAdvance"),
                unified_advance: bool_value(proprietary, "rollupUnifiedAdvance"),
                forced_exit: bool_value(proprietary, "rollupForcedExit"),
                deposit_holding_credit: bool_value(proprietary, "depositHoldingCredit"),
                deposit_holding_refund: bool_value(proprietary, "depositHoldingRefund"),
            },
        }
    }
}

fn decode_hex(proprietary: Option<&Map<String, Value>>, key: &str) -> Option<Vec<u8>> {
    proprietary
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
}

fn decode_hex_array(proprietary: Option<&Map<String, Value>>, key: &str) -> Option<Vec<Vec<u8>>> {
    proprietary
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|value| hex::decode(value).ok())
                .collect()
        })
}

fn string_value(proprietary: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    proprietary
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn object_value(proprietary: Option<&Map<String, Value>>, key: &str) -> Option<Map<String, Value>> {
    proprietary
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_object)
        .cloned()
}

fn bool_value(proprietary: Option<&Map<String, Value>>, key: &str) -> bool {
    proprietary
        .and_then(|fields| fields.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
