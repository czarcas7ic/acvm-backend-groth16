//! ACIR to R1CS conversion module.
//!
//! This module provides functionality to convert ACIR (Abstract Circuit Intermediate Representation)
//! circuits into R1CS (Rank-1 Constraint System) format compatible with the arkworks Groth16 prover.
//!
//! # R1CS Overview
//!
//! R1CS represents constraints as: A * B = C, where A, B, C are linear combinations of variables.
//! ACIR's `AssertZero` opcode expresses constraints as quadratic polynomials equal to zero:
//!
//! ```text
//! Σ q_M[i,j] * w_i * w_j + Σ q_L[i] * w_i + q_c = 0
//! ```
//!
//! We convert these to R1CS form by introducing auxiliary variables when necessary.

use crate::errors::CircuitConversionError;
use acir::{
    circuit::{Circuit, Opcode},
    native_types::{Expression, Witness, WitnessMap},
    AcirField,
};
use ark_ff::{BigInteger, PrimeField};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};
use std::collections::BTreeMap;

/// Converts an ACIR field element to an arkworks field element.
///
/// # Type Parameters
/// * `AF` - The ACIR field type
/// * `F` - The arkworks field type
///
/// # Arguments
/// * `acir_field` - The ACIR field element to convert
///
/// # Returns
/// The equivalent arkworks field element
pub fn acir_field_to_ark<AF: AcirField, F: PrimeField>(acir_field: &AF) -> F {
    // Convert via big-endian bytes
    let bytes = acir_field.to_be_bytes();
    F::from_be_bytes_mod_order(&bytes)
}

/// Converts an arkworks field element to an ACIR field element.
///
/// # Type Parameters
/// * `F` - The arkworks field type
/// * `AF` - The ACIR field type
///
/// # Arguments
/// * `ark_field` - The arkworks field element to convert
///
/// # Returns
/// The equivalent ACIR field element
#[allow(dead_code)]
pub fn ark_field_to_acir<F: PrimeField, AF: AcirField>(ark_field: &F) -> AF {
    let bigint = ark_field.into_bigint();
    let bytes = bigint.to_bytes_be();
    // AcirField has from_be_bytes_reduce, not from_be_bytes_mod_order
    AF::from_be_bytes_reduce(&bytes)
}

/// An R1CS circuit synthesized from an ACIR circuit.
///
/// This struct implements `ConstraintSynthesizer` for use with arkworks' Groth16 prover.
#[derive(Clone)]
pub struct AcirCircuit<AF: AcirField> {
    /// The ACIR circuit to convert.
    circuit: Circuit<AF>,
    /// Witness values (only needed during proving, not during setup).
    witness_values: Option<WitnessMap<AF>>,
}

impl<AF: AcirField> AcirCircuit<AF> {
    /// Creates a new ACIR circuit wrapper.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    ///
    /// # Returns
    /// A new `AcirCircuit` without witness values (for setup)
    pub fn new(circuit: Circuit<AF>) -> Self {
        Self {
            circuit,
            witness_values: None,
        }
    }

    /// Creates a new ACIR circuit wrapper with witness values.
    ///
    /// # Arguments
    /// * `circuit` - The ACIR circuit
    /// * `witness_values` - The witness values for proving
    ///
    /// # Returns
    /// A new `AcirCircuit` with witness values (for proving)
    pub fn with_witness(circuit: Circuit<AF>, witness_values: WitnessMap<AF>) -> Self {
        Self {
            circuit,
            witness_values: Some(witness_values),
        }
    }

    /// Gets the number of public inputs in the circuit.
    pub fn num_public_inputs(&self) -> usize {
        self.circuit.public_inputs().0.len()
    }

    /// Gets the public input witness indices.
    pub fn public_input_indices(&self) -> Vec<u32> {
        self.circuit.public_inputs().indices()
    }

    /// Gets the private input witness indices.
    pub fn private_input_indices(&self) -> Vec<u32> {
        self.circuit
            .private_parameters
            .iter()
            .map(|w| w.witness_index())
            .collect()
    }

    /// Validates that the circuit is compatible with R1CS/Groth16.
    pub fn validate_for_r1cs(&self) -> Result<(), CircuitConversionError> {
        for opcode in &self.circuit.opcodes {
            match opcode {
                Opcode::AssertZero(_) => {
                    // AssertZero opcodes are supported
                }
                Opcode::BlackBoxFuncCall(func) => {
                    return Err(CircuitConversionError::UnsupportedBlackBoxFunction {
                        function_name: format!("{:?}", func),
                    });
                }
                Opcode::MemoryOp { .. } | Opcode::MemoryInit { .. } => {
                    return Err(CircuitConversionError::UnsupportedMemoryOperation);
                }
                Opcode::BrilligCall { .. } => {
                    return Err(CircuitConversionError::UnsupportedBrilligCall);
                }
                Opcode::Call { .. } => {
                    return Err(CircuitConversionError::UnsupportedAcirCall);
                }
            }
        }
        Ok(())
    }
}

impl<AF: AcirField, F: PrimeField> ConstraintSynthesizer<F> for AcirCircuit<AF> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // First validate the circuit is R1CS-compatible
        self.validate_for_r1cs()
            .map_err(|_| SynthesisError::Unsatisfiable)?;

        // Create a mapping from ACIR witness indices to R1CS variables
        let mut witness_to_var: BTreeMap<u32, Variable> = BTreeMap::new();

        // Get the total number of witnesses
        let num_witnesses = self.circuit.current_witness_index as usize + 1;

        // Determine which witnesses are public inputs
        let public_inputs = self.circuit.public_inputs();

        // Allocate all witness variables
        for witness_idx in 0..num_witnesses as u32 {
            let witness = Witness(witness_idx);
            let is_public = public_inputs.0.contains(&witness);

            let value = self.witness_values.as_ref().and_then(|wm| wm.get(&witness));

            let var = if is_public {
                // Allocate as public input
                cs.new_input_variable(|| {
                    value
                        .map(|v| acir_field_to_ark::<AF, F>(v))
                        .ok_or(SynthesisError::AssignmentMissing)
                })?
            } else {
                // Allocate as private witness
                cs.new_witness_variable(|| {
                    value
                        .map(|v| acir_field_to_ark::<AF, F>(v))
                        .ok_or(SynthesisError::AssignmentMissing)
                })?
            };

            witness_to_var.insert(witness_idx, var);
        }

        // Process each opcode
        for opcode in &self.circuit.opcodes {
            match opcode {
                Opcode::AssertZero(expr) => {
                    // Convert the expression to R1CS constraints
                    synthesize_expression(&cs, expr, &witness_to_var)?;
                }
                _ => {
                    // Other opcodes should have been caught by validate_for_r1cs
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }

        Ok(())
    }
}

/// Synthesizes an ACIR expression as R1CS constraints.
///
/// An ACIR expression has the form:
/// ```text
/// Σ q_M[i] * w_l[i] * w_r[i] + Σ q_L[i] * w[i] + q_c = 0
/// ```
///
/// For R1CS, we need constraints of the form A * B = C.
///
/// # Strategy
/// - If there are no multiplication terms: the expression is linear, we add a single
///   constraint: (linear_combination) * 1 = 0
/// - If there is exactly one multiplication term: we can express it directly
/// - If there are multiple multiplication terms: we introduce auxiliary variables
fn synthesize_expression<AF: AcirField, F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    expr: &Expression<AF>,
    witness_to_var: &BTreeMap<u32, Variable>,
) -> Result<(), SynthesisError> {
    if expr.is_const() {
        // Constant expression: q_c = 0
        // This is either trivially satisfied (q_c == 0) or unsatisfiable (q_c != 0)
        let q_c: F = acir_field_to_ark(&expr.q_c);
        if !q_c.is_zero() {
            return Err(SynthesisError::Unsatisfiable);
        }
        return Ok(());
    }

    if expr.mul_terms.is_empty() {
        // Linear expression: Σ q_L[i] * w[i] + q_c = 0
        // Express as: (linear_combination + q_c) * 1 = 0
        // Which means: linear_combination = -q_c
        // Or equivalently: linear_combination + q_c = 0

        let lc = build_linear_combination::<AF, F>(
            &expr.linear_combinations,
            &expr.q_c,
            witness_to_var,
        );

        // Constraint: lc * 1 = 0
        // This enforces that the linear combination equals zero
        let one = lc!() + Variable::One;
        cs.enforce_constraint(lc, one, lc!())?;
    } else if expr.mul_terms.len() == 1 {
        // Single multiplication term: q_M * w_l * w_r + Σ q_L[i] * w[i] + q_c = 0
        // Rearrange to: q_M * w_l * w_r = -(Σ q_L[i] * w[i] + q_c)

        let (q_m, w_l, w_r) = &expr.mul_terms[0];
        let q_m_f: F = acir_field_to_ark(q_m);

        let var_l = witness_to_var
            .get(&w_l.witness_index())
            .ok_or(SynthesisError::AssignmentMissing)?;
        let var_r = witness_to_var
            .get(&w_r.witness_index())
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Build A = q_M * w_l
        let a = lc!() + (q_m_f, *var_l);

        // Build B = w_r
        let b = lc!() + *var_r;

        // Build C = -(Σ q_L[i] * w[i] + q_c)
        let neg_q_c = -acir_field_to_ark::<AF, F>(&expr.q_c);
        let mut c = lc!() + (neg_q_c, Variable::One);

        for (coeff, witness) in &expr.linear_combinations {
            let coeff_f: F = -acir_field_to_ark::<AF, F>(coeff);
            let var = witness_to_var
                .get(&witness.witness_index())
                .ok_or(SynthesisError::AssignmentMissing)?;
            c = c + (coeff_f, *var);
        }

        // Constraint: A * B = C
        cs.enforce_constraint(a, b, c)?;
    } else {
        // Multiple multiplication terms: need to introduce auxiliary variables
        // For each multiplication term q_M[i] * w_l[i] * w_r[i], we create an
        // auxiliary variable aux[i] = w_l[i] * w_r[i], then constrain the sum.

        let mut sum_lc = lc!();

        for (q_m, w_l, w_r) in &expr.mul_terms {
            let q_m_f: F = acir_field_to_ark(q_m);

            let var_l = witness_to_var
                .get(&w_l.witness_index())
                .ok_or(SynthesisError::AssignmentMissing)?;
            let var_r = witness_to_var
                .get(&w_r.witness_index())
                .ok_or(SynthesisError::AssignmentMissing)?;

            // Create auxiliary variable for w_l * w_r
            let aux = cs.new_witness_variable(|| {
                // This closure is only called during proving when we have values
                Err(SynthesisError::AssignmentMissing)
            })?;

            // Constraint: w_l * w_r = aux
            cs.enforce_constraint(lc!() + *var_l, lc!() + *var_r, lc!() + aux)?;

            // Add q_M * aux to the sum
            sum_lc = sum_lc + (q_m_f, aux);
        }

        // Add linear terms
        for (coeff, witness) in &expr.linear_combinations {
            let coeff_f: F = acir_field_to_ark(coeff);
            let var = witness_to_var
                .get(&witness.witness_index())
                .ok_or(SynthesisError::AssignmentMissing)?;
            sum_lc = sum_lc + (coeff_f, *var);
        }

        // Add constant term
        let q_c_f: F = acir_field_to_ark(&expr.q_c);
        sum_lc = sum_lc + (q_c_f, Variable::One);

        // Constraint: sum = 0
        // This enforces that the sum of all terms equals zero
        let one = lc!() + Variable::One;
        cs.enforce_constraint(sum_lc, one, lc!())?;
    }

    Ok(())
}

/// Builds a linear combination from ACIR expression components.
fn build_linear_combination<AF: AcirField, F: PrimeField>(
    linear_terms: &[(AF, Witness)],
    constant: &AF,
    witness_to_var: &BTreeMap<u32, Variable>,
) -> LinearCombination<F> {
    let mut lc = lc!();

    // Add constant term
    let const_f: F = acir_field_to_ark(constant);
    lc = lc + (const_f, Variable::One);

    // Add linear terms
    for (coeff, witness) in linear_terms {
        let coeff_f: F = acir_field_to_ark(coeff);
        if let Some(var) = witness_to_var.get(&witness.witness_index()) {
            lc = lc + (coeff_f, *var);
        }
    }

    lc
}

/// Extracts the public inputs from a witness map according to a circuit's public input specification.
pub fn extract_public_inputs<AF: AcirField, F: PrimeField>(
    circuit: &Circuit<AF>,
    witness_map: &WitnessMap<AF>,
) -> Vec<F> {
    let public_inputs = circuit.public_inputs();
    let mut inputs = Vec::with_capacity(public_inputs.0.len());

    for witness in &public_inputs.0 {
        if let Some(value) = witness_map.get(witness) {
            inputs.push(acir_field_to_ark(value));
        }
    }

    inputs
}

/// Computes the number of R1CS constraints for an ACIR circuit.
pub fn count_constraints<AF: AcirField>(circuit: &Circuit<AF>) -> usize {
    let mut count = 0;

    for opcode in &circuit.opcodes {
        if let Opcode::AssertZero(expr) = opcode {
            if expr.is_const() {
                // Constant expressions don't add constraints (they're either trivially true or false)
                continue;
            }

            if expr.mul_terms.is_empty() {
                // Linear expression: 1 constraint
                count += 1;
            } else if expr.mul_terms.len() == 1 {
                // Single multiplication: 1 constraint
                count += 1;
            } else {
                // Multiple multiplications: 1 constraint per multiplication + 1 for the sum
                count += expr.mul_terms.len() + 1;
            }
        }
    }

    count
}

#[cfg(test)]
mod tests {
    // Tests will be added in the test module
}
