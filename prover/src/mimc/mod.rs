use std::marker::PhantomData;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use params::Mimc5_220Bn254Params;

pub mod params;

pub type MiMcBn254 = MiMC<Fr, Mimc5_220Bn254Params>;

pub trait MiMCParameters: Clone + Default {
    const ROUNDS: usize;
    const EXPONENT: usize;
}

#[derive(Default, Clone)]
pub struct MiMC<F: PrimeField, P: MiMCParameters> {
    pub num_outputs: usize,
    pub k: F,
    pub round_keys: Vec<F>,
    _p: PhantomData<P>,
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    pub fn new(num_outputs: usize, k: F, round_keys: &[F]) -> Self {
        assert_eq!(round_keys.len(), P::ROUNDS);
        Self {
            num_outputs,
            k,
            round_keys: round_keys.to_vec(),
            _p: PhantomData,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMC<F, P> {
    pub fn permute_feistel(&self, state: &[F]) -> Vec<F> {
        let mut r = F::zero();
        let mut c = F::zero();
        for s in state.iter() {
            r += s;
            (r, c) = self.feistel(r, c);
        }
        let mut outputs = vec![r];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    (r, c) = self.feistel(r, c);
                    outputs.push(r);
                }
                outputs
            }
        }
    }

    fn feistel(&self, left: F, right: F) -> (F, F) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => self.k + x_l,
                false => self.k + x_l + self.round_keys[i],
            };
            let mut tn = F::one();
            (0..P::EXPONENT).for_each(|_| tn *= t);
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (x_r + tn, x_l),
                false => (x_l, x_r + tn),
            };
        }
        (x_l, x_r)
    }
}

#[cfg(test)]
mod test {
    use super::{
        params::{round_keys_contants, MIMC_5_220_BN254_ROUND_KEYS},
        MiMcBn254,
    };
    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use std::str::FromStr;

    #[test]
    fn test_mimc() {
        let round_key = round_keys_contants::<Fr>(&MIMC_5_220_BN254_ROUND_KEYS);
        let mimc = MiMcBn254::new(1, Fr::ZERO, &round_key);
        let r = mimc.permute_feistel(&[
            Fr::ZERO,
            Fr::ONE,
            Fr::from_str("567778336660098848776366662228888333").unwrap(),
        ]);
        assert_eq!(
            r[0].to_string(),
            "12525131868496031425744154881744336661020056362076131525086600857748260152186"
        );
    }
}
