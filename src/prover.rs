//! Groth16 proving and verification.
//!
//! This module provides the main proving and verification functionality
//! for the Groth16 backend.
//!
//! # Usage
//!
//! ```ignore
//! use acvm_backend_groth16::{Groth16Prover, Bn254};
//!
//! // Create a prover for BN254 curve
//! let prover = Groth16Prover::<Bn254>::new();
//!
//! // Generate keys (for development only - use MPC ceremony keys in production)
//! let (pk, vk) = prover.generate_keys(&circuit)?;
//!
//! // Generate a proof
//! let proof = prover.prove(&circuit, &witness_map, &pk)?;
//!
//! // Verify the proof
//! let is_valid = prover.verify(&proof, &public_inputs, &vk)?;
//! ```
//!
//! # Security Warning
//!
//! The `generate_keys` method uses local randomness and is NOT suitable for
//! production use. For production deployments, you must use keys generated
//! through a proper multi-party computation (MPC) trusted setup ceremony.

use crate::errors::{Groth16Result, KeyError, ProofGenerationError, VerificationError};
use crate::keys::{compute_circuit_hash, Groth16ProvingKey, Groth16VerificationKey};
use crate::proof::{Groth16Proof, PublicInputs};
use crate::r1cs::{extract_public_inputs, AcirCircuit};

use acir::{circuit::Circuit, native_types::WitnessMap, AcirField};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

/// The Groth16 prover for ACIR circuits.
///
/// # Type Parameters
/// * `E` - The pairing-friendly elliptic curve to use (e.g., BN254, BLS12-381)
pub struct Groth16Prover<E: Pairing> {
    _marker: PhantomData<E>,
}

impl<E: Pairing> Default for Groth16Prover<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Pairing> Groth16Prover<E> {
    /// Creates a new Groth16 prover.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Generates proving and verification keys for a circuit.
    ///
    /// # Security Warning
    ///
    /// This method uses local randomness and is **NOT** suitable for production use.
    /// For production deployments, you must use keys generated through a proper
    /// multi-party computation (MPC) trusted setup ceremony.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit to generate keys for
    ///
    /// # Returns
    /// A tuple of (proving_key, verification_key), or an error
    ///
    /// # Type Parameters
    /// * `AF` - The ACIR field type
    pub fn generate_keys<AF: AcirField>(
        &self,
        circuit: &Circuit<AF>,
    ) -> Groth16Result<(Groth16ProvingKey<E>, Groth16VerificationKey<E>)>
    where
        E::ScalarField: PrimeField,
    {
        self.generate_keys_with_rng(circuit, &mut ark_std::rand::thread_rng())
    }

    /// Generates proving and verification keys with a specified RNG.
    ///
    /// # Security Warning
    ///
    /// Unless your RNG comes from an MPC ceremony, these keys are **NOT**
    /// suitable for production use.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit to generate keys for
    /// * `rng` - The random number generator to use
    ///
    /// # Returns
    /// A tuple of (proving_key, verification_key), or an error
    pub fn generate_keys_with_rng<AF: AcirField, R: RngCore + CryptoRng>(
        &self,
        circuit: &Circuit<AF>,
        rng: &mut R,
    ) -> Groth16Result<(Groth16ProvingKey<E>, Groth16VerificationKey<E>)>
    where
        E::ScalarField: PrimeField,
    {
        // Create the R1CS circuit (without witness values for setup)
        let r1cs_circuit = AcirCircuit::new(circuit.clone());

        // Validate that the circuit is R1CS-compatible
        r1cs_circuit.validate_for_r1cs()?;

        // Compute circuit hash
        let circuit_hash = compute_circuit_hash(circuit);

        // Generate keys using arkworks Groth16
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(r1cs_circuit, rng)
            .map_err(|e| KeyError::GenerationFailed {
                message: e.to_string(),
            })?;

        let num_public_inputs = circuit.public_inputs().0.len();

        Ok((
            Groth16ProvingKey::new(pk, circuit_hash),
            Groth16VerificationKey::new(vk, circuit_hash, num_public_inputs),
        ))
    }

    /// Generates a proof for a circuit with the given witness values.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    /// * `witness_map` - The witness values
    /// * `proving_key` - The proving key
    ///
    /// # Returns
    /// The generated proof, or an error
    pub fn prove<AF: AcirField>(
        &self,
        circuit: &Circuit<AF>,
        witness_map: &WitnessMap<AF>,
        proving_key: &Groth16ProvingKey<E>,
    ) -> Groth16Result<Groth16Proof<E>>
    where
        E::ScalarField: PrimeField,
    {
        self.prove_with_rng(circuit, witness_map, proving_key, &mut ark_std::rand::thread_rng())
    }

    /// Generates a proof with a specified RNG.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    /// * `witness_map` - The witness values
    /// * `proving_key` - The proving key
    /// * `rng` - The random number generator to use
    ///
    /// # Returns
    /// The generated proof, or an error
    pub fn prove_with_rng<AF: AcirField, R: RngCore + CryptoRng>(
        &self,
        circuit: &Circuit<AF>,
        witness_map: &WitnessMap<AF>,
        proving_key: &Groth16ProvingKey<E>,
        rng: &mut R,
    ) -> Groth16Result<Groth16Proof<E>>
    where
        E::ScalarField: PrimeField,
    {
        // Create the R1CS circuit with witness values
        let r1cs_circuit = AcirCircuit::with_witness(circuit.clone(), witness_map.clone());

        // Validate that the circuit is R1CS-compatible
        r1cs_circuit.validate_for_r1cs()?;

        // Generate the proof
        let proof = Groth16::<E>::prove(&proving_key.key, r1cs_circuit, rng)
            .map_err(|e| ProofGenerationError::ProverFailed {
                message: e.to_string(),
            })?;

        Ok(Groth16Proof::new(proof))
    }

    /// Verifies a proof against public inputs.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    /// * `public_inputs` - The public input values
    /// * `verification_key` - The verification key
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(
        &self,
        proof: &Groth16Proof<E>,
        public_inputs: &PublicInputs<E::ScalarField>,
        verification_key: &Groth16VerificationKey<E>,
    ) -> Groth16Result<bool>
    where
        E::ScalarField: PrimeField,
    {
        // Check that the number of public inputs matches
        if public_inputs.len() != verification_key.num_public_inputs {
            return Err(VerificationError::MalformedPublicInputs {
                message: format!(
                    "Expected {} public inputs, got {}",
                    verification_key.num_public_inputs,
                    public_inputs.len()
                ),
            }
            .into());
        }

        // Verify the proof
        let result = Groth16::<E>::verify_with_processed_vk(
            verification_key.prepared(),
            &public_inputs.values,
            &proof.proof,
        )
        .map_err(|e| VerificationError::VerifierError {
            message: e.to_string(),
        })?;

        Ok(result)
    }

    /// Extracts public inputs from a witness map according to the circuit specification.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    /// * `witness_map` - The witness values
    ///
    /// # Returns
    /// The public inputs extracted from the witness map
    pub fn extract_public_inputs<AF: AcirField>(
        &self,
        circuit: &Circuit<AF>,
        witness_map: &WitnessMap<AF>,
    ) -> PublicInputs<E::ScalarField>
    where
        E::ScalarField: PrimeField,
    {
        let values = extract_public_inputs(circuit, witness_map);
        PublicInputs::new(values)
    }

    /// Convenience method to prove and return both the proof and public inputs.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    /// * `witness_map` - The witness values
    /// * `proving_key` - The proving key
    ///
    /// # Returns
    /// A tuple of (proof, public_inputs), or an error
    pub fn prove_with_public_inputs<AF: AcirField>(
        &self,
        circuit: &Circuit<AF>,
        witness_map: &WitnessMap<AF>,
        proving_key: &Groth16ProvingKey<E>,
    ) -> Groth16Result<(Groth16Proof<E>, PublicInputs<E::ScalarField>)>
    where
        E::ScalarField: PrimeField,
    {
        let proof = self.prove(circuit, witness_map, proving_key)?;
        let public_inputs = self.extract_public_inputs(circuit, witness_map);
        Ok((proof, public_inputs))
    }
}

/// Convenience function to generate keys for a circuit.
///
/// # Security Warning
///
/// This function uses local randomness and is **NOT** suitable for production use.
pub fn generate_keys<E: Pairing, AF: AcirField>(
    circuit: &Circuit<AF>,
) -> Groth16Result<(Groth16ProvingKey<E>, Groth16VerificationKey<E>)>
where
    E::ScalarField: PrimeField,
{
    Groth16Prover::<E>::new().generate_keys(circuit)
}

/// Convenience function to generate a proof.
pub fn prove<E: Pairing, AF: AcirField>(
    circuit: &Circuit<AF>,
    witness_map: &WitnessMap<AF>,
    proving_key: &Groth16ProvingKey<E>,
) -> Groth16Result<Groth16Proof<E>>
where
    E::ScalarField: PrimeField,
{
    Groth16Prover::<E>::new().prove(circuit, witness_map, proving_key)
}

/// Convenience function to verify a proof.
pub fn verify<E: Pairing>(
    proof: &Groth16Proof<E>,
    public_inputs: &PublicInputs<E::ScalarField>,
    verification_key: &Groth16VerificationKey<E>,
) -> Groth16Result<bool>
where
    E::ScalarField: PrimeField,
{
    Groth16Prover::<E>::new().verify(proof, public_inputs, verification_key)
}

#[cfg(test)]
mod tests {
    // Tests will be added for proving and verification
}
