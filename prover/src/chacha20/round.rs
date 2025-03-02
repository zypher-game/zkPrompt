use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::ToBytesGadget, uint32::UInt32, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

use super::quarter_round::QuarterRound;

pub struct Round<F: PrimeField> {
    pub state_vars: Vec<UInt32<F>>,
    pub key_stream: Vec<UInt8<F>>,
}

impl<F: PrimeField> Round<F> {
    pub fn new(state_vars: &[UInt32<F>]) -> Self {
        assert_eq!(state_vars.len(), 16);
        Self {
            state_vars: state_vars.to_vec(),
            key_stream: vec![],
        }
    }

    pub fn generate_constraints(&mut self) -> Result<(), SynthesisError> {
        let mut quarter_round = QuarterRound::new(&self.state_vars);

        for _ in 0..10 {
            quarter_round.generate_constraints(0, 4, 8, 12);
            quarter_round.generate_constraints(1, 5, 9, 13);
            quarter_round.generate_constraints(2, 6, 10, 14);
            quarter_round.generate_constraints(3, 7, 11, 15);
            quarter_round.generate_constraints(0, 5, 10, 15);
            quarter_round.generate_constraints(1, 6, 11, 12);
            quarter_round.generate_constraints(2, 7, 8, 13);
            quarter_round.generate_constraints(3, 4, 9, 14);
        }

        let mut key_stream = vec![];
        for (before, after) in self.state_vars.iter().zip(quarter_round.state_vars.iter()) {
            let new_var = before.wrapping_add(after);
            key_stream.extend(new_var.to_bytes_le()?);
        }

        self.key_stream = key_stream;

        Ok(())
    }
}
