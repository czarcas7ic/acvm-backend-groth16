# acvm-backend-groth16

A production-ready [Groth16](https://eprint.iacr.org/2016/260) proving backend for [Noir](https://noir-lang.org/)'s Abstract Circuit Virtual Machine (ACVM).

This crate provides functionality to generate and verify Groth16 zero-knowledge proofs for ACIR circuits compiled from Noir programs.

## Features

- **Groth16 Proving**: Generate succinct zero-knowledge proofs using the Groth16 proving system
- **Multiple Curves**: Support for BN254 and BLS12-381 pairing-friendly elliptic curves
- **Solidity Verification**: Generate Solidity smart contracts for on-chain proof verification
- **Production Ready**: Comprehensive error handling, key serialization with integrity checks, and file I/O
- **Type Safe**: Strongly typed API with compile-time curve selection

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
acvm-backend-groth16 = { git = "https://github.com/czarcas7ic/acvm-backend-groth16", features = ["parallel"] }
```

## Security Warning

**IMPORTANT**: The key generation functions in this crate use local randomness and are **NOT** suitable for production use. For production deployments, you **must** use keys generated through a proper multi-party computation (MPC) trusted setup ceremony.

The Groth16 proving system requires a circuit-specific trusted setup. If the toxic waste from this setup is compromised, an attacker can generate fake proofs. See [Vitalik's explanation of trusted setups](https://vitalik.ca/general/2022/03/14/trustedsetup.html) for more information.

> **Tracking Issue**: [#1 - Implement MPC Trusted Setup Ceremony Support](https://github.com/czarcas7ic/acvm-backend-groth16/issues/1)

## Quick Start

### Basic Proving and Verification

```rust
use acvm_backend_groth16::prelude::*;
use acir::circuit::Circuit;
use acir::native_types::WitnessMap;
use acir::FieldElement;

// Load your ACIR circuit and witness
let circuit: Circuit<FieldElement> = /* ... */;
let witness_map: WitnessMap<FieldElement> = /* ... */;

// Create a prover for BN254 curve
let prover = Groth16Prover::<Bn254>::new();

// Generate keys (DEVELOPMENT ONLY - use MPC keys in production)
let (proving_key, verification_key) = prover.generate_keys(&circuit)?;

// Generate a proof with public inputs
let (proof, public_inputs) = prover.prove_with_public_inputs(
    &circuit,
    &witness_map,
    &proving_key
)?;

// Verify the proof
let is_valid = prover.verify(&proof, &public_inputs, &verification_key)?;
assert!(is_valid);
```

### Generating a Solidity Verifier

```rust
use acvm_backend_groth16::solidity::SolidityVerifierGenerator;

// Generate a Solidity verifier contract
let generator = SolidityVerifierGenerator::new()
    .with_contract_name("MyVerifier");

let contract = generator.generate(&verification_key)?;
std::fs::write("MyVerifier.sol", contract)?;
```

### Serializing Keys and Proofs

```rust
// Save keys to files
proving_key.save_to_file("proving_key.bin")?;
verification_key.save_to_file("verification_key.bin")?;

// Load keys from files
let pk = Groth16ProvingKey::<Bn254>::load_from_file("proving_key.bin")?;
let vk = Groth16VerificationKey::<Bn254>::load_from_file("verification_key.bin")?;

// Serialize proof to hex
let proof_hex = proof.to_hex()?;
let loaded_proof = Groth16Proof::<Bn254>::from_hex(&proof_hex)?;

// Serialize public inputs
let inputs_hex = public_inputs.to_hex()?;
let loaded_inputs = PublicInputs::<ark_bn254::Fr>::from_hex(&inputs_hex)?;
```

### Formatting for Solidity Verification

```rust
use acvm_backend_groth16::solidity::{format_proof_for_solidity, format_public_inputs_for_solidity};

// Format proof for Solidity verifyProof function
let (a, b, c) = format_proof_for_solidity(&proof)?;
let inputs = format_public_inputs_for_solidity(&public_inputs);

// Use these values in your Solidity contract call:
// verifier.verifyProof(a, b, c, inputs)
```

## R1CS Constraint System

This backend converts ACIR circuits to R1CS (Rank-1 Constraint System) format. Only circuits using `AssertZero` opcodes (arithmetic constraints) are supported.

The following ACIR opcodes are **NOT** supported and will result in an error:
- `BlackBoxFuncCall` - Use a PLONK-based backend for black box functions
- `MemoryOp` / `MemoryInit` - Memory should be flattened before proving
- `BrilligCall` - Brillig functions should be evaluated before proving
- `Call` - ACIR function calls should be inlined

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `bn254` | Yes | Enable BN254 curve support |
| `bls12_381` | No | Enable BLS12-381 curve support |
| `parallel` | No | Enable parallel computation using rayon |

### Using BLS12-381

```toml
[dependencies]
acvm-backend-groth16 = { git = "...", default-features = false, features = ["bls12_381"] }
```

```rust
use acvm_backend_groth16::prelude::*;

let prover = Groth16Prover::<Bls12_381>::new();
// ... rest is the same
```

### Enabling Parallel Computation

```toml
[dependencies]
acvm-backend-groth16 = { git = "...", features = ["parallel"] }
```

## API Reference

### Main Types

| Type | Description |
|------|-------------|
| `Groth16Prover<E>` | Main prover/verifier for curve `E` |
| `Groth16ProvingKey<E>` | Proving key with metadata and serialization |
| `Groth16VerificationKey<E>` | Verification key with metadata |
| `Groth16Proof<E>` | Zero-knowledge proof |
| `PublicInputs<F>` | Public inputs for verification |
| `SolidityVerifierGenerator` | Generates Solidity verifier contracts |

### Error Types

| Error | Description |
|-------|-------------|
| `Groth16Error` | Top-level error enum |
| `CircuitConversionError` | ACIR to R1CS conversion errors |
| `ProofGenerationError` | Proof generation failures |
| `VerificationError` | Proof verification failures |
| `KeyError` | Key generation/serialization errors |
| `SerializationError` | Data serialization errors |
| `ContractGenerationError` | Solidity contract generation errors |

## File Formats

### Key Files

Keys are serialized with:
- 4-byte magic number (`G16P` for proving key, `G16V` for verification key)
- 4-byte version number
- 32-byte circuit hash (for compatibility checking)
- Compressed arkworks serialization
- 32-byte SHA-256 integrity hash

### Proof Files

Proofs are serialized with:
- 4-byte magic number (`G16R`)
- 4-byte version number
- Compressed arkworks serialization
- 32-byte SHA-256 integrity hash

## Integration with Noir

This backend is designed to work with ACIR circuits generated by the Noir compiler. Typical workflow:

1. Compile your Noir program to ACIR using `nargo compile`
2. Load the compiled circuit and generate/load proving keys
3. Execute the circuit to generate a witness
4. Generate a proof using this backend
5. Verify the proof or deploy a Solidity verifier for on-chain verification

## Compatibility

- **Noir**: v1.0.0-beta.16
- **Arkworks**: 0.5.0
- **Rust**: 1.85.0+

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
