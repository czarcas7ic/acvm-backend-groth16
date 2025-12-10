//! Error types for the Groth16 backend.
//!
//! This module provides comprehensive error handling for all operations
//! in the Groth16 proving system, including circuit compilation, proof
//! generation, verification, and serialization.

use thiserror::Error;

/// The main error type for the Groth16 backend.
#[derive(Debug, Error)]
pub enum Groth16Error {
    /// Error during ACIR to R1CS conversion.
    #[error("Circuit conversion error: {0}")]
    CircuitConversion(#[from] CircuitConversionError),

    /// Error during proof generation.
    #[error("Proof generation error: {0}")]
    ProofGeneration(#[from] ProofGenerationError),

    /// Error during proof verification.
    #[error("Verification error: {0}")]
    Verification(#[from] VerificationError),

    /// Error during key operations.
    #[error("Key error: {0}")]
    Key(#[from] KeyError),

    /// Error during serialization/deserialization.
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Error during Solidity contract generation.
    #[error("Contract generation error: {0}")]
    ContractGeneration(#[from] ContractGenerationError),
}

/// Errors that can occur during ACIR to R1CS circuit conversion.
#[derive(Debug, Error)]
pub enum CircuitConversionError {
    /// An unsupported opcode was encountered.
    #[error("Unsupported opcode: {opcode_name}. Groth16/R1CS only supports arithmetic constraints (AssertZero opcodes)")]
    UnsupportedOpcode {
        /// Name of the unsupported opcode.
        opcode_name: String,
    },

    /// An unsupported black box function was encountered.
    #[error("Unsupported black box function: {function_name}. Consider using a PLONK-based backend for this function")]
    UnsupportedBlackBoxFunction {
        /// Name of the unsupported function.
        function_name: String,
    },

    /// A witness value is missing from the witness map.
    #[error("Missing witness value for witness index {witness_index}")]
    MissingWitness {
        /// Index of the missing witness.
        witness_index: u32,
    },

    /// The circuit has no constraints.
    #[error("Circuit has no constraints. Cannot generate a valid proof for an empty circuit")]
    EmptyCircuit,

    /// Field element conversion failed.
    #[error("Field element conversion failed: {message}")]
    FieldConversion {
        /// Description of the conversion failure.
        message: String,
    },

    /// The constraint system is not satisfiable.
    #[error("Constraint system is not satisfiable: {message}")]
    UnsatisfiableConstraints {
        /// Description of why constraints are unsatisfiable.
        message: String,
    },

    /// Memory operations are not supported in R1CS.
    #[error("Memory operations (MemoryOp/MemoryInit) are not directly supported in R1CS. These should be flattened before proving")]
    UnsupportedMemoryOperation,

    /// Brillig calls are not supported in R1CS.
    #[error("Brillig calls are not supported in R1CS proving. Brillig functions should be evaluated before proving")]
    UnsupportedBrilligCall,

    /// ACIR function calls require preprocessing.
    #[error("ACIR function calls should be inlined or handled separately")]
    UnsupportedAcirCall,
}

/// Errors that can occur during proof generation.
#[derive(Debug, Error)]
pub enum ProofGenerationError {
    /// The proving key is invalid or corrupted.
    #[error("Invalid proving key: {message}")]
    InvalidProvingKey {
        /// Description of why the key is invalid.
        message: String,
    },

    /// Witness generation failed.
    #[error("Witness generation failed: {message}")]
    WitnessGenerationFailed {
        /// Description of the failure.
        message: String,
    },

    /// The arkworks Groth16 prover failed.
    #[error("Groth16 prover failed: {message}")]
    ProverFailed {
        /// Description of the prover failure.
        message: String,
    },

    /// Random number generation failed.
    #[error("Random number generation failed: {message}")]
    RngFailed {
        /// Description of the RNG failure.
        message: String,
    },

    /// Circuit synthesis failed.
    #[error("Circuit synthesis failed: {message}")]
    SynthesisFailed {
        /// Description of the synthesis failure.
        message: String,
    },

    /// Public inputs do not match the circuit.
    #[error("Public input mismatch: expected {expected} public inputs, got {actual}")]
    PublicInputMismatch {
        /// Expected number of public inputs.
        expected: usize,
        /// Actual number of public inputs provided.
        actual: usize,
    },
}

/// Errors that can occur during proof verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The verification key is invalid or corrupted.
    #[error("Invalid verification key: {message}")]
    InvalidVerificationKey {
        /// Description of why the key is invalid.
        message: String,
    },

    /// The proof is invalid or corrupted.
    #[error("Invalid proof: {message}")]
    InvalidProof {
        /// Description of why the proof is invalid.
        message: String,
    },

    /// The proof verification failed (proof is valid but does not verify).
    #[error("Proof verification failed: the proof does not verify against the given public inputs")]
    ProofVerificationFailed,

    /// The arkworks Groth16 verifier encountered an error.
    #[error("Groth16 verifier error: {message}")]
    VerifierError {
        /// Description of the verifier error.
        message: String,
    },

    /// Public inputs are malformed.
    #[error("Malformed public inputs: {message}")]
    MalformedPublicInputs {
        /// Description of the malformation.
        message: String,
    },
}

/// Errors related to proving and verification keys.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Key generation failed.
    #[error("Key generation failed: {message}")]
    GenerationFailed {
        /// Description of the generation failure.
        message: String,
    },

    /// Key serialization failed.
    #[error("Key serialization failed: {message}")]
    SerializationFailed {
        /// Description of the serialization failure.
        message: String,
    },

    /// Key deserialization failed.
    #[error("Key deserialization failed: {message}")]
    DeserializationFailed {
        /// Description of the deserialization failure.
        message: String,
    },

    /// Key is not compatible with the circuit.
    #[error("Key incompatible with circuit: {message}")]
    IncompatibleKey {
        /// Description of the incompatibility.
        message: String,
    },

    /// Key file not found.
    #[error("Key file not found: {path}")]
    FileNotFound {
        /// Path to the missing file.
        path: String,
    },

    /// Key file I/O error.
    #[error("Key file I/O error: {message}")]
    IoError {
        /// Description of the I/O error.
        message: String,
    },
}

/// Errors related to serialization and deserialization.
#[derive(Debug, Error)]
pub enum SerializationError {
    /// Binary serialization failed.
    #[error("Binary serialization failed: {message}")]
    BinarySerializationFailed {
        /// Description of the failure.
        message: String,
    },

    /// Binary deserialization failed.
    #[error("Binary deserialization failed: {message}")]
    BinaryDeserializationFailed {
        /// Description of the failure.
        message: String,
    },

    /// Hex encoding failed.
    #[error("Hex encoding failed: {message}")]
    HexEncodingFailed {
        /// Description of the failure.
        message: String,
    },

    /// Hex decoding failed.
    #[error("Hex decoding failed: {message}")]
    HexDecodingFailed {
        /// Description of the failure.
        message: String,
    },

    /// Invalid data format.
    #[error("Invalid data format: {message}")]
    InvalidFormat {
        /// Description of the format error.
        message: String,
    },

    /// Data integrity check failed.
    #[error("Data integrity check failed: computed hash {computed} does not match expected {expected}")]
    IntegrityCheckFailed {
        /// Computed hash.
        computed: String,
        /// Expected hash.
        expected: String,
    },
}

/// Errors related to Solidity contract generation.
#[derive(Debug, Error)]
pub enum ContractGenerationError {
    /// Template rendering failed.
    #[error("Template rendering failed: {message}")]
    TemplateRenderingFailed {
        /// Description of the failure.
        message: String,
    },

    /// Invalid verification key format for contract generation.
    #[error("Verification key format invalid for contract generation: {message}")]
    InvalidKeyFormat {
        /// Description of the format error.
        message: String,
    },

    /// Contract output failed.
    #[error("Contract output failed: {message}")]
    OutputFailed {
        /// Description of the output failure.
        message: String,
    },
}

/// Result type alias for Groth16 operations.
pub type Groth16Result<T> = Result<T, Groth16Error>;

impl From<std::io::Error> for KeyError {
    fn from(err: std::io::Error) -> Self {
        KeyError::IoError {
            message: err.to_string(),
        }
    }
}

impl From<hex::FromHexError> for SerializationError {
    fn from(err: hex::FromHexError) -> Self {
        SerializationError::HexDecodingFailed {
            message: err.to_string(),
        }
    }
}
