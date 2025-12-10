//! # acvm-backend-groth16
//!
//! A production-ready Groth16 proving backend for [Noir](https://noir-lang.org/)'s
//! Abstract Circuit Virtual Machine (ACVM).
//!
//! This crate provides functionality to generate and verify Groth16 zero-knowledge proofs
//! for ACIR circuits compiled from Noir programs.
//!
//! ## Features
//!
//! - **Groth16 Proving**: Generate succinct zero-knowledge proofs using the Groth16 proving system
//! - **Multiple Curves**: Support for BN254 and BLS12-381 curves
//! - **Solidity Verification**: Generate Solidity smart contracts for on-chain proof verification
//! - **Production Ready**: Comprehensive error handling, key serialization, and integrity checks
//!
//! ## Security Warning
//!
//! The key generation functions in this crate use local randomness and are **NOT**
//! suitable for production use. For production deployments, you must use keys
//! generated through a proper multi-party computation (MPC) trusted setup ceremony.
//!
//! ## Usage
//!
//! ### Basic Proving and Verification
//!
//! ```ignore
//! use acvm_backend_groth16::{Groth16Prover, Bn254};
//! use acir::circuit::Circuit;
//! use acir::native_types::WitnessMap;
//!
//! // Load your ACIR circuit and witness
//! let circuit: Circuit<acir::FieldElement> = /* ... */;
//! let witness_map: WitnessMap<acir::FieldElement> = /* ... */;
//!
//! // Create a prover
//! let prover = Groth16Prover::<Bn254>::new();
//!
//! // Generate keys (DEVELOPMENT ONLY - use MPC keys in production)
//! let (proving_key, verification_key) = prover.generate_keys(&circuit)?;
//!
//! // Generate a proof
//! let (proof, public_inputs) = prover.prove_with_public_inputs(
//!     &circuit,
//!     &witness_map,
//!     &proving_key
//! )?;
//!
//! // Verify the proof
//! let is_valid = prover.verify(&proof, &public_inputs, &verification_key)?;
//! assert!(is_valid);
//! ```
//!
//! ### Generating a Solidity Verifier
//!
//! ```ignore
//! use acvm_backend_groth16::solidity::SolidityVerifierGenerator;
//!
//! // Generate a Solidity verifier contract
//! let generator = SolidityVerifierGenerator::new()
//!     .with_contract_name("MyVerifier");
//!
//! let contract = generator.generate(&verification_key)?;
//! std::fs::write("MyVerifier.sol", contract)?;
//! ```
//!
//! ### Serializing Keys and Proofs
//!
//! ```ignore
//! // Save keys to files
//! proving_key.save_to_file("proving_key.bin")?;
//! verification_key.save_to_file("verification_key.bin")?;
//!
//! // Load keys from files
//! let pk = Groth16ProvingKey::<Bn254>::load_from_file("proving_key.bin")?;
//! let vk = Groth16VerificationKey::<Bn254>::load_from_file("verification_key.bin")?;
//!
//! // Serialize proof to hex
//! let proof_hex = proof.to_hex()?;
//! let loaded_proof = Groth16Proof::<Bn254>::from_hex(&proof_hex)?;
//! ```
//!
//! ## R1CS Constraint System
//!
//! This backend converts ACIR circuits to R1CS (Rank-1 Constraint System) format.
//! Only circuits using `AssertZero` opcodes (arithmetic constraints) are supported.
//!
//! The following ACIR opcodes are **NOT** supported and will result in an error:
//! - `BlackBoxFuncCall` - Use a PLONK-based backend for black box functions
//! - `MemoryOp` / `MemoryInit` - Memory should be flattened before proving
//! - `BrilligCall` - Brillig functions should be evaluated before proving
//! - `Call` - ACIR function calls should be inlined
//!
//! ## Feature Flags
//!
//! - `bn254` (default): Enable BN254 curve support
//! - `bls12_381`: Enable BLS12-381 curve support
//! - `parallel`: Enable parallel computation using rayon

#![warn(missing_docs)]
#![warn(unused_crate_dependencies)]
#![warn(unreachable_pub)]
#![deny(unsafe_code)]

pub mod errors;
pub mod keys;
pub mod proof;
pub mod prover;
pub mod r1cs;
pub mod solidity;

// Explicitly use these crates to silence unused_crate_dependencies warnings
// These are transitive dependencies needed by our code
#[allow(unused_imports)]
use acir_field as _;
#[allow(unused_imports)]
use serde as _;

// Re-export curve types for convenience
pub use ark_bn254::Bn254;
pub use ark_bls12_381::Bls12_381;

// Re-export main types
pub use errors::{Groth16Error, Groth16Result};
pub use keys::{Groth16ProvingKey, Groth16VerificationKey};
pub use proof::{Groth16Proof, PublicInputs};
pub use prover::Groth16Prover;

// Re-export ACIR types for convenience
pub use acir;
pub use acir::circuit::Circuit;
pub use acir::native_types::WitnessMap;
pub use acir::AcirField;
pub use acir::FieldElement;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::errors::{Groth16Error, Groth16Result};
    pub use crate::keys::{Groth16ProvingKey, Groth16VerificationKey};
    pub use crate::proof::{Groth16Proof, PublicInputs};
    pub use crate::prover::Groth16Prover;
    pub use crate::solidity::SolidityVerifierGenerator;
    pub use crate::{Bn254, Bls12_381};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_compiles() {
        // Basic smoke test to ensure the library compiles
        let _prover = Groth16Prover::<Bn254>::new();
    }
}
