//! Groth16/BN254 crowdfunding proof generation compatible with Kaspa OP_ZK_PRECOMPILE.
//!
//! The proof preserves the original KasSigner crowdfunding witness semantics: up to
//! eight private contribution amounts sum to one public total. The covenant does
//! not trust this witness for fund safety; it independently enforces the real
//! transaction input total, goal, destination, and fee on-chain.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

pub const CROWDFUND_MAX_CONTRIBUTORS: usize = 8;

fn wasm_rng() -> Result<StdRng, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| format!("Browser RNG failed: {error}"))?;
    let rng = StdRng::from_seed(seed);
    seed.fill(0);
    Ok(rng)
}

#[derive(Clone)]
pub struct CrowdfundCircuit {
    pub amounts: [Option<Fr>; CROWDFUND_MAX_CONTRIBUTORS],
}

impl ConstraintSynthesizer<Fr> for CrowdfundCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::LinearCombination;

        let mut amount_vars = Vec::with_capacity(CROWDFUND_MAX_CONTRIBUTORS);
        let mut running_sum = Some(Fr::from(0u64));
        for amount in self.amounts {
            let variable =
                cs.new_witness_variable(|| amount.ok_or(SynthesisError::AssignmentMissing))?;
            amount_vars.push(variable);
            running_sum = match (running_sum, amount) {
                (Some(sum), Some(value)) => Some(sum + value),
                _ => None,
            };
        }

        let sum_var =
            cs.new_input_variable(|| running_sum.ok_or(SynthesisError::AssignmentMissing))?;
        let mut sum_lc = LinearCombination::zero();
        for variable in amount_vars {
            sum_lc = sum_lc + variable;
        }
        cs.enforce_constraint(
            sum_lc,
            LinearCombination::from(ark_relations::r1cs::Variable::One),
            LinearCombination::from(sum_var),
        )?;
        Ok(())
    }
}

pub fn crowdfund_trusted_setup() -> Result<(Vec<u8>, Vec<u8>), String> {
    let circuit = CrowdfundCircuit {
        amounts: [None; CROWDFUND_MAX_CONTRIBUTORS],
    };
    let mut rng = wasm_rng()?;
    let proving_key =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
            .map_err(|error| format!("Crowdfund setup failed: {error}"))?;
    Ok((
        serialize_compressed(&proving_key)?,
        serialize_compressed(&proving_key.vk)?,
    ))
}

pub fn crowdfund_generate_proof(
    proving_key_bytes: &[u8],
    amounts_sompi: &[u64],
) -> Result<(Vec<u8>, Vec<u8>, u64), String> {
    if amounts_sompi.is_empty() {
        return Err("At least one contribution is required".to_string());
    }
    if amounts_sompi.len() > CROWDFUND_MAX_CONTRIBUTORS {
        return Err(format!(
            "At most {CROWDFUND_MAX_CONTRIBUTORS} proof contributions are supported"
        ));
    }
    let proving_key = deserialize_pk(proving_key_bytes)?;
    let mut amounts = [Some(Fr::from(0u64)); CROWDFUND_MAX_CONTRIBUTORS];
    let mut total = 0u64;
    for (index, amount) in amounts_sompi.iter().copied().enumerate() {
        total = total
            .checked_add(amount)
            .ok_or_else(|| "Crowdfund contribution total overflow".to_string())?;
        amounts[index] = Some(Fr::from(amount));
    }
    let circuit = CrowdfundCircuit { amounts };
    let mut rng = wasm_rng()?;
    let proof =
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &proving_key, &mut rng)
            .map_err(|error| format!("Crowdfund proof generation failed: {error}"))?;
    let public_input = serialize_field_element(&Fr::from(total))?;
    Ok((serialize_compressed(&proof)?, public_input, total))
}

pub fn verify_proof(
    verifying_key_bytes: &[u8],
    proof_bytes: &[u8],
    public_input_bytes: &[u8],
) -> Result<bool, String> {
    let verifying_key = deserialize_vk(verifying_key_bytes)?;
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|error| format!("Bad crowdfunding proof: {error}"))?;
    let public_input = Fr::deserialize_compressed(public_input_bytes)
        .map_err(|error| format!("Bad crowdfunding public input: {error}"))?;
    let prepared = Groth16::<Bn254>::process_vk(&verifying_key)
        .map_err(|error| format!("Crowdfund verifying-key processing failed: {error}"))?;
    Groth16::<Bn254>::verify_proof(&prepared, &proof, &[public_input])
        .map_err(|error| format!("Crowdfund proof verification failed: {error}"))
}

pub fn serialize_total(total: u64) -> Result<Vec<u8>, String> {
    serialize_field_element(&Fr::from(total))
}

fn deserialize_pk(bytes: &[u8]) -> Result<ProvingKey<Bn254>, String> {
    ProvingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|error| format!("Bad crowdfunding proving key: {error}"))
}

fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, String> {
    VerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|error| format!("Bad crowdfunding verifying key: {error}"))
}

fn serialize_compressed<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|error| format!("Crowdfund serialization failed: {error}"))?;
    Ok(bytes)
}

fn serialize_field_element(value: &Fr) -> Result<Vec<u8>, String> {
    serialize_compressed(value)
}
