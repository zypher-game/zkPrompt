use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

pub fn enforce_equals<F: PrimeField>(a: &[UInt8<F>], b: &[UInt8<F>]) -> Result<(), SynthesisError> {
    for (v0, v1) in a.iter().zip(b.iter()) {
        v0.enforce_equal(v1)?
    }
    Ok(())
}
