//! Proof structures and serialization.
//!
//! This module provides structures for Groth16 proofs, including
//! serialization and deserialization functionality.

use crate::errors::SerializationError;
use ark_ec::pairing::Pairing;
use ark_groth16::Proof as ArkProof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

/// Magic bytes for proof files.
const PROOF_MAGIC: &[u8; 4] = b"G16R";

/// Current version of the proof serialization format.
pub const PROOF_FORMAT_VERSION: u32 = 1;

/// A wrapper around a Groth16 proof with metadata.
#[derive(Clone)]
pub struct Groth16Proof<E: Pairing> {
    /// The underlying arkworks proof.
    pub proof: ArkProof<E>,
    /// Version identifier for the proof format.
    pub version: u32,
}

impl<E: Pairing> Groth16Proof<E> {
    /// Creates a new proof wrapper.
    ///
    /// # Arguments
    /// * `proof` - The arkworks Groth16 proof
    pub fn new(proof: ArkProof<E>) -> Self {
        Self {
            proof,
            version: PROOF_FORMAT_VERSION,
        }
    }

    /// Serializes the proof to bytes.
    ///
    /// # Returns
    /// The serialized proof bytes, or an error
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();

        // Write magic bytes
        bytes.extend_from_slice(PROOF_MAGIC);

        // Write version
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Serialize the proof
        let mut proof_bytes = Vec::new();
        self.proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|e| SerializationError::BinarySerializationFailed {
                message: e.to_string(),
            })?;

        // Write proof length and proof data
        let proof_len = proof_bytes.len() as u64;
        bytes.extend_from_slice(&proof_len.to_le_bytes());
        bytes.extend_from_slice(&proof_bytes);

        // Compute and append integrity hash
        let hash = compute_integrity_hash(&bytes);
        bytes.extend_from_slice(&hash);

        Ok(bytes)
    }

    /// Deserializes a proof from bytes.
    ///
    /// # Arguments
    /// * `bytes` - The serialized proof bytes
    ///
    /// # Returns
    /// The deserialized proof, or an error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() < 4 + 4 + 8 + 32 {
            return Err(SerializationError::BinaryDeserializationFailed {
                message: "Data too short to be a valid proof".to_string(),
            });
        }

        // Verify integrity hash
        let data_len = bytes.len() - 32;
        let expected_hash = &bytes[data_len..];
        let computed_hash = compute_integrity_hash(&bytes[..data_len]);
        if expected_hash != computed_hash {
            return Err(SerializationError::IntegrityCheckFailed {
                computed: hex::encode(computed_hash),
                expected: hex::encode(expected_hash),
            });
        }

        let mut cursor = 0;

        // Read and verify magic bytes
        if &bytes[cursor..cursor + 4] != PROOF_MAGIC {
            return Err(SerializationError::InvalidFormat {
                message: "Invalid proof file format".to_string(),
            });
        }
        cursor += 4;

        // Read version
        let version = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;

        if version != PROOF_FORMAT_VERSION {
            return Err(SerializationError::InvalidFormat {
                message: format!(
                    "Unsupported proof format version: {} (expected {})",
                    version, PROOF_FORMAT_VERSION
                ),
            });
        }

        // Read proof length
        let proof_len = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        // Deserialize the proof
        let proof_data = &bytes[cursor..cursor + proof_len];
        let proof = ArkProof::deserialize_compressed_unchecked(proof_data).map_err(|e| {
            SerializationError::BinaryDeserializationFailed {
                message: e.to_string(),
            }
        })?;

        Ok(Self { proof, version })
    }

    /// Serializes the proof to a hex string.
    pub fn to_hex(&self) -> Result<String, SerializationError> {
        let bytes = self.to_bytes()?;
        Ok(hex::encode(bytes))
    }

    /// Deserializes a proof from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, SerializationError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the raw arkworks proof.
    pub fn into_inner(self) -> ArkProof<E> {
        self.proof
    }

    /// Returns a reference to the raw arkworks proof.
    pub fn inner(&self) -> &ArkProof<E> {
        &self.proof
    }

    /// Saves the proof to a file.
    pub fn save_to_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<(), SerializationError> {
        let bytes = self.to_bytes()?;
        std::fs::write(path.as_ref(), bytes).map_err(|e| {
            SerializationError::BinarySerializationFailed {
                message: e.to_string(),
            }
        })
    }

    /// Loads a proof from a file.
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, SerializationError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| {
            SerializationError::BinaryDeserializationFailed {
                message: e.to_string(),
            }
        })?;
        Self::from_bytes(&bytes)
    }
}

/// Public inputs for proof verification.
#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    /// The public input values as field elements.
    pub values: Vec<F>,
}

impl<F: ark_ff::PrimeField> PublicInputs<F> {
    /// Creates new public inputs from field elements.
    pub fn new(values: Vec<F>) -> Self {
        Self { values }
    }

    /// Creates empty public inputs.
    pub fn empty() -> Self {
        Self { values: Vec::new() }
    }

    /// Returns the number of public inputs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if there are no public inputs.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Serializes the public inputs to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();

        // Write number of inputs
        bytes.extend_from_slice(&(self.values.len() as u64).to_le_bytes());

        // Serialize each field element
        for value in &self.values {
            let mut value_bytes = Vec::new();
            value
                .serialize_compressed(&mut value_bytes)
                .map_err(|e| SerializationError::BinarySerializationFailed {
                    message: e.to_string(),
                })?;
            bytes.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&value_bytes);
        }

        Ok(bytes)
    }

    /// Deserializes public inputs from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        if bytes.len() < 8 {
            return Err(SerializationError::BinaryDeserializationFailed {
                message: "Data too short for public inputs".to_string(),
            });
        }

        let mut cursor = 0;

        // Read number of inputs
        let num_inputs = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        let mut values = Vec::with_capacity(num_inputs);

        for _ in 0..num_inputs {
            // Read value length
            let value_len =
                u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;

            // Deserialize value
            let value_data = &bytes[cursor..cursor + value_len];
            let value = F::deserialize_compressed_unchecked(value_data).map_err(|e| {
                SerializationError::BinaryDeserializationFailed {
                    message: e.to_string(),
                }
            })?;
            cursor += value_len;

            values.push(value);
        }

        Ok(Self { values })
    }

    /// Serializes the public inputs to a hex string.
    pub fn to_hex(&self) -> Result<String, SerializationError> {
        let bytes = self.to_bytes()?;
        Ok(hex::encode(bytes))
    }

    /// Deserializes public inputs from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, SerializationError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }
}

/// Computes an integrity hash of the given data.
fn compute_integrity_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    // Tests will be added for proof serialization/deserialization
}
