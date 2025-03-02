use ark_ff::PrimeField;
use ark_r1cs_std::uint32::UInt32;

pub struct QuarterRound<F: PrimeField> {
    pub state_vars: Vec<UInt32<F>>,
}

impl<F: PrimeField> QuarterRound<F> {
    pub fn new(state_vars: &[UInt32<F>]) -> Self {
        assert_eq!(state_vars.len(), 16);
        Self {
            state_vars: state_vars.to_vec(),
        }
    }

    pub fn generate_constraints(&mut self, a: usize, b: usize, c: usize, d: usize) {
        self.state_vars[a] = self.state_vars[a].wrapping_add(&self.state_vars[b]);
        self.state_vars[d] = self.state_vars[d].clone() ^ self.state_vars[a].clone();
        self.state_vars[d] = self.state_vars[d].rotate_left(16);

        self.state_vars[c] = self.state_vars[c].wrapping_add(&self.state_vars[d]);
        self.state_vars[b] = self.state_vars[b].clone() ^ self.state_vars[c].clone();
        self.state_vars[b] = self.state_vars[b].rotate_left(12);

        self.state_vars[a] = self.state_vars[a].wrapping_add(&self.state_vars[b]);
        self.state_vars[d] = self.state_vars[a].clone() ^ self.state_vars[d].clone();
        self.state_vars[d] = self.state_vars[d].rotate_left(8);

        self.state_vars[c] = self.state_vars[c].wrapping_add(&self.state_vars[d]);
        self.state_vars[b] = self.state_vars[c].clone() ^ self.state_vars[b].clone();
        self.state_vars[b] = self.state_vars[b].rotate_left(7);
    }
}
