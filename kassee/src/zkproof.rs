// KasSee Web — ZK Proof Module (Groth16 over BN254)
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// zkproof.rs — Groth16 proof generation for Kaspa OP_ZK_PRECOMPILE (0xa6).
//
// The Kaspa TN12 node verifier uses arkworks (ark-bn254, ark-groth16) with
// CanonicalSerialize compressed format. This module uses the exact same
// crates and serialization so proof/VK bytes are bit-compatible.
//
// Demo circuit: "I know a, b such that a * b = c" (c = public input).
// This is intentionally minimal to prove the full pipeline:
//   KasSee prover → sig_script → P2SH → node OpZkPrecompile → verified.
// Production circuits (SHA256 preimage, confidential amounts) swap in here.
//
// Stack layout expected by OpZkPrecompile (bottom → top):
//   input_{n-1} ... input_0 | n_inputs | proof | vk | tag | opcode
//
// Tag 0x20 = Groth16, cost = Gram(1000 * 140) = 14M script units.

//! Groth16 zero-knowledge proving and verification (arkworks BN254) for the
//! crowdfunding covenant.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

/// Build a seeded RNG from browser crypto.getRandomValues via getrandom crate.
/// getrandom with "js" feature uses wasm-bindgen to call crypto.getRandomValues.
fn wasm_rng() -> ark_std::rand::rngs::StdRng {
    use ark_std::rand::SeedableRng;
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    ark_std::rand::rngs::StdRng::from_seed(seed)
}

/// Groth16 tag byte for Kaspa OpZkPrecompile.
pub const ZK_TAG_GROTH16: u8 = 0x20;

// ═══════════════════════════════════════════════════════════════════
// Circuit definition: a * b = c  (c is public, a and b are private)
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// Trusted setup (key generation)
// ═══════════════════════════════════════════════════════════════════

/// Deserialize a proving key from compressed bytes.
pub fn deserialize_pk(bytes: &[u8]) -> Result<ProvingKey<Bn254>, String> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes).map_err(|e| format!("Bad PK: {}", e))
}

/// Deserialize a verifying key from compressed bytes.
pub fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, String> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes).map_err(|e| format!("Bad VK: {}", e))
}

// ═══════════════════════════════════════════════════════════════════
// Proof generation
// ═══════════════════════════════════════════════════════════════════

/// Verify a proof locally (optional sanity check before broadcast).
pub fn verify_proof(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_input_bytes: &[u8],
) -> Result<bool, String> {
    let vk = deserialize_vk(vk_bytes)?;

    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| format!("Bad proof: {}", e))?;

    let c = Fr::deserialize_compressed(public_input_bytes)
        .map_err(|e| format!("Bad public input: {}", e))?;

    let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|e| format!("Process VK failed: {}", e))?;

    let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[c])
        .map_err(|e| format!("Verify failed: {}", e))?;

    Ok(valid)
}

// ═══════════════════════════════════════════════════════════════════
// Crowdfunding circuit: sum of N contributions = S (public)
// ═══════════════════════════════════════════════════════════════════

/// Max contributors for the crowdfunding PoC. Unused slots filled with 0.
pub const CROWDFUND_MAX_CONTRIBUTORS: usize = 8;

/// Crowdfunding circuit: proves knowledge of amounts[0..8] that sum to S.
///
/// Public input:  total_sum (the sum of all contributions)
/// Private witness: amounts[0..8] (each contributor's amount in sompi)
/// Constraint: amounts[0] + amounts[1] + ... + amounts[7] = total_sum
#[derive(Clone)]
pub struct CrowdfundCircuit {
    pub amounts: [Option<Fr>; CROWDFUND_MAX_CONTRIBUTORS],
}

impl ConstraintSynthesizer<Fr> for CrowdfundCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::LinearCombination;

        // Allocate private witnesses for each amount
        let mut amount_vars = Vec::new();
        let mut running_sum: Option<Fr> = Some(Fr::from(0u64));

        for i in 0..CROWDFUND_MAX_CONTRIBUTORS {
            let a_val = self.amounts[i];
            let a_var =
                cs.new_witness_variable(|| a_val.ok_or(SynthesisError::AssignmentMissing))?;
            amount_vars.push(a_var);

            if let (Some(sum), Some(a)) = (running_sum, a_val) {
                running_sum = Some(sum + a);
            } else {
                running_sum = None;
            }
        }

        // Allocate public input: total_sum
        let sum_var =
            cs.new_input_variable(|| running_sum.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce: amounts[0] + amounts[1] + ... + amounts[7] = total_sum
        // R1CS: (sum_of_amounts) * (1) = (total_sum)
        let mut sum_lc = LinearCombination::zero();
        for v in &amount_vars {
            sum_lc = sum_lc + *v;
        }

        cs.enforce_constraint(
            sum_lc,
            LinearCombination::from(ark_relations::r1cs::Variable::One),
            LinearCombination::from(sum_var),
        )?;

        Ok(())
    }
}

/// Trusted setup for the crowdfunding circuit.
pub fn crowdfund_trusted_setup() -> Result<(Vec<u8>, Vec<u8>), String> {
    let circuit = CrowdfundCircuit {
        amounts: [None; CROWDFUND_MAX_CONTRIBUTORS],
    };

    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut wasm_rng())
        .map_err(|e| format!("CF setup failed: {}", e))?;

    let vk_bytes = serialize_compressed(&pk.vk)?;
    let pk_bytes = serialize_compressed(&pk)?;

    Ok((pk_bytes, vk_bytes))
}

/// Generate a crowdfunding proof.
/// `amounts_sompi`: array of up to 8 contribution amounts in sompi (u64).
/// Unused slots must be 0.
/// Returns (proof_bytes, public_input_bytes) where public_input = total_sum.
pub fn crowdfund_generate_proof(
    pk_bytes: &[u8],
    amounts_sompi: &[u64],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if amounts_sompi.len() > CROWDFUND_MAX_CONTRIBUTORS {
        return Err(format!("Max {} contributors", CROWDFUND_MAX_CONTRIBUTORS));
    }

    let pk = deserialize_pk(pk_bytes)?;

    let mut amounts = [Some(Fr::from(0u64)); CROWDFUND_MAX_CONTRIBUTORS];
    let mut total: u64 = 0;
    for (i, &a) in amounts_sompi.iter().enumerate() {
        amounts[i] = Some(Fr::from(a));
        total = total.checked_add(a).ok_or("Amount overflow")?;
    }

    let circuit = CrowdfundCircuit { amounts };

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut wasm_rng())
        .map_err(|e| format!("CF prove failed: {}", e))?;

    let proof_bytes = serialize_compressed(&proof)?;
    let sum_field = Fr::from(total);
    let sum_bytes = serialize_field_element(&sum_field)?;

    Ok((proof_bytes, sum_bytes))
}

// ═══════════════════════════════════════════════════════════════════
// Serialization helpers (arkworks CanonicalSerialize compressed)
// ═══════════════════════════════════════════════════════════════════

fn serialize_compressed<T: CanonicalSerialize>(val: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    val.serialize_compressed(&mut buf)
        .map_err(|e| format!("Serialize failed: {}", e))?;
    Ok(buf)
}

/// Serialize a field element to 32 bytes (arkworks compressed format).
///
/// The Kaspa node's `build_groth_script` test shows public inputs as 32-byte
/// little-endian field elements. arkworks `CanonicalSerialize` for `Fr`
/// produces exactly this format.
fn serialize_field_element(f: &Fr) -> Result<Vec<u8>, String> {
    serialize_compressed(f)
}

// ═══════════════════════════════════════════════════════════════════
// Script-level helpers (for building sig_script data items)
// ═══════════════════════════════════════════════════════════════════
