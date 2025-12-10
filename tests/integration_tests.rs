//! Integration tests for the acvm-backend-groth16 library.
//!
//! These tests verify the complete workflow from ACIR circuit to proof verification.

use acir::circuit::{Circuit, Opcode, PublicInputs as AcirPublicInputs};
use acir::native_types::{Expression, Witness, WitnessMap};
use acir::{AcirField, FieldElement};
use acvm_backend_groth16::prelude::*;
use acvm_backend_groth16::r1cs::{acir_field_to_ark, AcirCircuit, count_constraints, extract_public_inputs};
use acvm_backend_groth16::solidity::{format_proof_for_solidity, format_public_inputs_for_solidity, SolidityVerifierGenerator};
use ark_bn254::{Bn254, Fr};
use std::collections::BTreeSet;

/// Helper to create a simple circuit: w0 * w1 = w2 (all private)
fn create_multiplication_circuit() -> Circuit<FieldElement> {
    // Constraint: w0 * w1 - w2 = 0
    // In ACIR Expression form: mul_terms = [(1, w0, w1)], linear = [(-1, w2)], q_c = 0
    let mul_term = (FieldElement::one(), Witness(0), Witness(1));
    let linear_term = (-FieldElement::one(), Witness(2));

    let expr = Expression {
        mul_terms: vec![mul_term],
        linear_combinations: vec![linear_term],
        q_c: FieldElement::zero(),
    };

    Circuit {
        function_name: "test_mul".to_string(),
        current_witness_index: 2,
        opcodes: vec![Opcode::AssertZero(expr)],
        private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2)]),
        public_parameters: AcirPublicInputs(BTreeSet::new()),
        return_values: AcirPublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

/// Helper to create a circuit with public inputs: w0 * w1 = w2, where w2 is public
fn create_circuit_with_public_input() -> Circuit<FieldElement> {
    // Constraint: w0 * w1 - w2 = 0
    let mul_term = (FieldElement::one(), Witness(0), Witness(1));
    let linear_term = (-FieldElement::one(), Witness(2));

    let expr = Expression {
        mul_terms: vec![mul_term],
        linear_combinations: vec![linear_term],
        q_c: FieldElement::zero(),
    };

    Circuit {
        function_name: "test_mul_public".to_string(),
        current_witness_index: 2,
        opcodes: vec![Opcode::AssertZero(expr)],
        private_parameters: BTreeSet::from([Witness(0), Witness(1)]),
        public_parameters: AcirPublicInputs(BTreeSet::from([Witness(2)])),
        return_values: AcirPublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

/// Helper to create a linear constraint circuit: 2*w0 + 3*w1 - w2 = 0
fn create_linear_circuit() -> Circuit<FieldElement> {
    let two = FieldElement::from(2u64);
    let three = FieldElement::from(3u64);

    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (two, Witness(0)),
            (three, Witness(1)),
            (-FieldElement::one(), Witness(2)),
        ],
        q_c: FieldElement::zero(),
    };

    Circuit {
        function_name: "test_linear".to_string(),
        current_witness_index: 2,
        opcodes: vec![Opcode::AssertZero(expr)],
        private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2)]),
        public_parameters: AcirPublicInputs(BTreeSet::new()),
        return_values: AcirPublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

/// Helper to create a constant constraint: w0 = 42
fn create_constant_circuit() -> Circuit<FieldElement> {
    let forty_two = FieldElement::from(42u64);

    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0))],
        q_c: -forty_two,
    };

    Circuit {
        function_name: "test_constant".to_string(),
        current_witness_index: 0,
        opcodes: vec![Opcode::AssertZero(expr)],
        private_parameters: BTreeSet::from([Witness(0)]),
        public_parameters: AcirPublicInputs(BTreeSet::new()),
        return_values: AcirPublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

/// Helper to create a circuit with multiple constraints
fn create_multi_constraint_circuit() -> Circuit<FieldElement> {
    // w0 * w1 = w2
    let expr1 = Expression {
        mul_terms: vec![(FieldElement::one(), Witness(0), Witness(1))],
        linear_combinations: vec![(-FieldElement::one(), Witness(2))],
        q_c: FieldElement::zero(),
    };

    // w2 + w3 = w4 (where w4 is public)
    let expr2 = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(2)),
            (FieldElement::one(), Witness(3)),
            (-FieldElement::one(), Witness(4)),
        ],
        q_c: FieldElement::zero(),
    };

    Circuit {
        function_name: "test_multi".to_string(),
        current_witness_index: 4,
        opcodes: vec![Opcode::AssertZero(expr1), Opcode::AssertZero(expr2)],
        private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2), Witness(3)]),
        public_parameters: AcirPublicInputs(BTreeSet::from([Witness(4)])),
        return_values: AcirPublicInputs(BTreeSet::new()),
        assert_messages: Vec::new(),
    }
}

// =============================================================================
// PROVER TESTS
// =============================================================================

#[test]
fn test_basic_key_generation() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let result = prover.generate_keys(&circuit);
    assert!(result.is_ok(), "Key generation should succeed: {:?}", result.err());

    let (pk, vk) = result.unwrap();
    assert_eq!(pk.version, acvm_backend_groth16::keys::KEY_FORMAT_VERSION);
    assert_eq!(vk.version, acvm_backend_groth16::keys::KEY_FORMAT_VERSION);
    assert_eq!(vk.num_public_inputs, 0);
}

#[test]
fn test_key_generation_with_public_inputs() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (_, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");
    assert_eq!(vk.num_public_inputs, 1);
}

#[test]
fn test_prove_and_verify_multiplication() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    // Generate keys
    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Create witness: 3 * 4 = 12
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(3u64));
    witness_map.insert(Witness(1), FieldElement::from(4u64));
    witness_map.insert(Witness(2), FieldElement::from(12u64));

    // Generate proof
    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    // Verify proof
    let is_valid = prover.verify(&proof, &public_inputs, &vk).expect("Verification should not error");
    assert!(is_valid, "Valid proof should verify");
}

#[test]
fn test_prove_and_verify_with_public_input() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    // Generate keys
    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Create witness: 5 * 7 = 35 (35 is public)
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    // Generate proof
    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    assert_eq!(public_inputs.len(), 1, "Should have 1 public input");

    // Verify proof
    let is_valid = prover.verify(&proof, &public_inputs, &vk).expect("Verification should not error");
    assert!(is_valid, "Valid proof should verify");
}

#[test]
fn test_prove_and_verify_linear_constraint() {
    let circuit = create_linear_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // 2*5 + 3*10 = 40
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(10u64));
    witness_map.insert(Witness(2), FieldElement::from(40u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk).expect("Verification should not error");
    assert!(is_valid, "Linear constraint proof should verify");
}

#[test]
fn test_prove_and_verify_constant_constraint() {
    let circuit = create_constant_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // w0 = 42
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(42u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk).expect("Verification should not error");
    assert!(is_valid, "Constant constraint proof should verify");
}

#[test]
fn test_prove_and_verify_multi_constraint() {
    let circuit = create_multi_constraint_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // w0 * w1 = w2: 3 * 4 = 12
    // w2 + w3 = w4: 12 + 8 = 20
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(3u64));
    witness_map.insert(Witness(1), FieldElement::from(4u64));
    witness_map.insert(Witness(2), FieldElement::from(12u64));
    witness_map.insert(Witness(3), FieldElement::from(8u64));
    witness_map.insert(Witness(4), FieldElement::from(20u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    assert_eq!(public_inputs.len(), 1);

    let is_valid = prover.verify(&proof, &public_inputs, &vk).expect("Verification should not error");
    assert!(is_valid, "Multi-constraint proof should verify");
}

#[test]
fn test_invalid_proof_fails_verification() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Create valid witness
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    let (proof, _) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    // Try to verify with wrong public inputs
    let wrong_inputs = PublicInputs::new(vec![Fr::from(999u64)]);

    let is_valid = prover.verify(&proof, &wrong_inputs, &vk).expect("Verification should not error");
    assert!(!is_valid, "Proof with wrong public inputs should not verify");
}

#[test]
fn test_public_input_count_mismatch() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    let (proof, _) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    // Wrong number of public inputs
    let wrong_inputs = PublicInputs::new(vec![Fr::from(35u64), Fr::from(999u64)]);

    let result = prover.verify(&proof, &wrong_inputs, &vk);
    assert!(result.is_err(), "Should error with wrong number of public inputs");
}

// =============================================================================
// KEY SERIALIZATION TESTS
// =============================================================================

#[test]
fn test_proving_key_serialization() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, _) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Serialize
    let bytes = pk.to_bytes().expect("Serialization should succeed");

    // Deserialize
    let pk_restored = Groth16ProvingKey::<Bn254>::from_bytes(&bytes)
        .expect("Deserialization should succeed");

    assert_eq!(pk.circuit_hash, pk_restored.circuit_hash);
    assert_eq!(pk.version, pk_restored.version);
}

#[test]
fn test_verification_key_serialization() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (_, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Serialize
    let bytes = vk.to_bytes().expect("Serialization should succeed");

    // Deserialize
    let vk_restored = Groth16VerificationKey::<Bn254>::from_bytes(&bytes)
        .expect("Deserialization should succeed");

    assert_eq!(vk.circuit_hash, vk_restored.circuit_hash);
    assert_eq!(vk.version, vk_restored.version);
    assert_eq!(vk.num_public_inputs, vk_restored.num_public_inputs);
}

#[test]
fn test_verification_key_hex_serialization() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (_, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let hex = vk.to_hex().expect("Hex encoding should succeed");
    let vk_restored = Groth16VerificationKey::<Bn254>::from_hex(&hex)
        .expect("Hex decoding should succeed");

    assert_eq!(vk.circuit_hash, vk_restored.circuit_hash);
}

#[test]
fn test_key_file_io() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Use temp files
    let pk_path = std::env::temp_dir().join("test_pk.bin");
    let vk_path = std::env::temp_dir().join("test_vk.bin");

    // Save
    pk.save_to_file(&pk_path).expect("Saving proving key should succeed");
    vk.save_to_file(&vk_path).expect("Saving verification key should succeed");

    // Load
    let pk_loaded = Groth16ProvingKey::<Bn254>::load_from_file(&pk_path)
        .expect("Loading proving key should succeed");
    let vk_loaded = Groth16VerificationKey::<Bn254>::load_from_file(&vk_path)
        .expect("Loading verification key should succeed");

    assert_eq!(pk.circuit_hash, pk_loaded.circuit_hash);
    assert_eq!(vk.circuit_hash, vk_loaded.circuit_hash);

    // Cleanup
    let _ = std::fs::remove_file(pk_path);
    let _ = std::fs::remove_file(vk_path);
}

#[test]
fn test_keys_work_after_serialization() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Serialize and deserialize keys
    let pk_bytes = pk.to_bytes().expect("PK serialization should succeed");
    let vk_bytes = vk.to_bytes().expect("VK serialization should succeed");

    let pk_restored = Groth16ProvingKey::<Bn254>::from_bytes(&pk_bytes)
        .expect("PK deserialization should succeed");
    let vk_restored = Groth16VerificationKey::<Bn254>::from_bytes(&vk_bytes)
        .expect("VK deserialization should succeed");

    // Use restored keys to prove and verify
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(6u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(42u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk_restored)
        .expect("Proof with restored key should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk_restored)
        .expect("Verification should not error");
    assert!(is_valid, "Proof should verify with restored keys");
}

// =============================================================================
// PROOF SERIALIZATION TESTS
// =============================================================================

#[test]
fn test_proof_serialization() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, _) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(3u64));
    witness_map.insert(Witness(1), FieldElement::from(4u64));
    witness_map.insert(Witness(2), FieldElement::from(12u64));

    let proof = prover.prove(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    // Serialize
    let bytes = proof.to_bytes().expect("Serialization should succeed");

    // Deserialize
    let proof_restored = Groth16Proof::<Bn254>::from_bytes(&bytes)
        .expect("Deserialization should succeed");

    assert_eq!(proof.version, proof_restored.version);
}

#[test]
fn test_proof_hex_serialization() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, _) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(3u64));
    witness_map.insert(Witness(1), FieldElement::from(4u64));
    witness_map.insert(Witness(2), FieldElement::from(12u64));

    let proof = prover.prove(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let hex = proof.to_hex().expect("Hex encoding should succeed");
    let proof_restored = Groth16Proof::<Bn254>::from_hex(&hex)
        .expect("Hex decoding should succeed");

    assert_eq!(proof.version, proof_restored.version);
}

#[test]
fn test_proof_file_io() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, _) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(3u64));
    witness_map.insert(Witness(1), FieldElement::from(4u64));
    witness_map.insert(Witness(2), FieldElement::from(12u64));

    let proof = prover.prove(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let proof_path = std::env::temp_dir().join("test_proof.bin");

    proof.save_to_file(&proof_path).expect("Saving proof should succeed");
    let proof_loaded = Groth16Proof::<Bn254>::load_from_file(&proof_path)
        .expect("Loading proof should succeed");

    assert_eq!(proof.version, proof_loaded.version);

    let _ = std::fs::remove_file(proof_path);
}

#[test]
fn test_restored_proof_verifies() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    // Serialize and restore
    let proof_hex = proof.to_hex().expect("Proof hex should succeed");
    let inputs_hex = public_inputs.to_hex().expect("Inputs hex should succeed");

    let proof_restored = Groth16Proof::<Bn254>::from_hex(&proof_hex)
        .expect("Proof restore should succeed");
    let inputs_restored = PublicInputs::<Fr>::from_hex(&inputs_hex)
        .expect("Inputs restore should succeed");

    let is_valid = prover.verify(&proof_restored, &inputs_restored, &vk)
        .expect("Verification should not error");
    assert!(is_valid, "Restored proof should verify");
}

// =============================================================================
// PUBLIC INPUTS TESTS
// =============================================================================

#[test]
fn test_public_inputs_serialization() {
    let inputs = PublicInputs::new(vec![
        Fr::from(42u64),
        Fr::from(123u64),
        Fr::from(456u64),
    ]);

    let bytes = inputs.to_bytes().expect("Serialization should succeed");
    let restored = PublicInputs::<Fr>::from_bytes(&bytes)
        .expect("Deserialization should succeed");

    assert_eq!(inputs.len(), restored.len());
    for (a, b) in inputs.values.iter().zip(restored.values.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn test_public_inputs_empty() {
    let inputs = PublicInputs::<Fr>::empty();
    assert!(inputs.is_empty());
    assert_eq!(inputs.len(), 0);
}

// =============================================================================
// R1CS CONVERSION TESTS
// =============================================================================

#[test]
fn test_count_constraints() {
    let circuit = create_multiplication_circuit();
    let count = count_constraints(&circuit);
    assert_eq!(count, 1, "Single multiplication should have 1 constraint");

    let linear_circuit = create_linear_circuit();
    let linear_count = count_constraints(&linear_circuit);
    assert_eq!(linear_count, 1, "Linear constraint should have 1 constraint");

    let multi_circuit = create_multi_constraint_circuit();
    let multi_count = count_constraints(&multi_circuit);
    assert_eq!(multi_count, 2, "Multi-constraint circuit should have 2 constraints");
}

#[test]
fn test_extract_public_inputs() {
    let circuit = create_circuit_with_public_input();

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    let public_inputs: Vec<Fr> = extract_public_inputs(&circuit, &witness_map);
    assert_eq!(public_inputs.len(), 1);
    assert_eq!(public_inputs[0], Fr::from(35u64));
}

#[test]
fn test_acir_field_to_ark() {
    let acir_val = FieldElement::from(12345u64);
    let ark_val: Fr = acir_field_to_ark(&acir_val);
    assert_eq!(ark_val, Fr::from(12345u64));
}

#[test]
fn test_acir_circuit_validation() {
    let circuit = create_multiplication_circuit();
    let acir_circuit = AcirCircuit::new(circuit);

    let result = acir_circuit.validate_for_r1cs();
    assert!(result.is_ok(), "Valid circuit should pass validation");
}

// =============================================================================
// SOLIDITY VERIFIER TESTS
// =============================================================================

#[test]
fn test_solidity_verifier_generation() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (_, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let generator = SolidityVerifierGenerator::new();
    let contract = generator.generate(&vk).expect("Contract generation should succeed");

    // Basic sanity checks
    assert!(contract.contains("pragma solidity"));
    assert!(contract.contains("Groth16Verifier"));
    assert!(contract.contains("verifyProof"));
    assert!(contract.contains("Pairing"));
}

#[test]
fn test_solidity_verifier_custom_name() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (_, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let generator = SolidityVerifierGenerator::new()
        .with_contract_name("MyCustomVerifier");
    let contract = generator.generate(&vk).expect("Contract generation should succeed");

    assert!(contract.contains("contract MyCustomVerifier"));
}

#[test]
fn test_format_proof_for_solidity() {
    let circuit = create_circuit_with_public_input();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, _) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::from(5u64));
    witness_map.insert(Witness(1), FieldElement::from(7u64));
    witness_map.insert(Witness(2), FieldElement::from(35u64));

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let (a, b, c) = format_proof_for_solidity(&proof)
        .expect("Formatting should succeed");

    // Check format
    assert!(a.starts_with('['));
    assert!(b.starts_with("[["));
    assert!(c.starts_with('['));

    let formatted_inputs = format_public_inputs_for_solidity(&public_inputs);
    assert_eq!(formatted_inputs.len(), 1);
}

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

#[test]
fn test_corrupted_proof_fails_deserialization() {
    let mut bad_bytes = vec![0u8; 100];
    bad_bytes[0..4].copy_from_slice(b"G16R"); // Valid magic

    let result = Groth16Proof::<Bn254>::from_bytes(&bad_bytes);
    assert!(result.is_err(), "Corrupted proof should fail to deserialize");
}

#[test]
fn test_corrupted_key_fails_deserialization() {
    let mut bad_bytes = vec![0u8; 200];
    bad_bytes[0..4].copy_from_slice(b"G16P"); // Valid magic

    let result = Groth16ProvingKey::<Bn254>::from_bytes(&bad_bytes);
    assert!(result.is_err(), "Corrupted key should fail to deserialize");
}

#[test]
fn test_invalid_magic_bytes() {
    let mut bad_bytes = vec![0u8; 100];
    bad_bytes[0..4].copy_from_slice(b"XXXX"); // Invalid magic

    let proof_result = Groth16Proof::<Bn254>::from_bytes(&bad_bytes);
    assert!(proof_result.is_err());

    let pk_result = Groth16ProvingKey::<Bn254>::from_bytes(&bad_bytes);
    assert!(pk_result.is_err());

    let vk_result = Groth16VerificationKey::<Bn254>::from_bytes(&bad_bytes);
    assert!(vk_result.is_err());
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

#[test]
fn test_large_field_values() {
    // Test with larger field values
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // Use larger values
    let a = FieldElement::from(1234567890u64);
    let b = FieldElement::from(9876543210u64);
    let c = a * b;

    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), a);
    witness_map.insert(Witness(1), b);
    witness_map.insert(Witness(2), c);

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk)
        .expect("Verification should not error");
    assert!(is_valid, "Proof with large values should verify");
}

#[test]
fn test_zero_values() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // 0 * 5 = 0
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::zero());
    witness_map.insert(Witness(1), FieldElement::from(5u64));
    witness_map.insert(Witness(2), FieldElement::zero());

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk)
        .expect("Verification should not error");
    assert!(is_valid, "Proof with zero values should verify");
}

#[test]
fn test_one_values() {
    let circuit = create_multiplication_circuit();
    let prover = Groth16Prover::<Bn254>::new();

    let (pk, vk) = prover.generate_keys(&circuit).expect("Key generation should succeed");

    // 1 * 1 = 1
    let mut witness_map = WitnessMap::new();
    witness_map.insert(Witness(0), FieldElement::one());
    witness_map.insert(Witness(1), FieldElement::one());
    witness_map.insert(Witness(2), FieldElement::one());

    let (proof, public_inputs) = prover
        .prove_with_public_inputs(&circuit, &witness_map, &pk)
        .expect("Proof generation should succeed");

    let is_valid = prover.verify(&proof, &public_inputs, &vk)
        .expect("Verification should not error");
    assert!(is_valid, "Proof with one values should verify");
}
