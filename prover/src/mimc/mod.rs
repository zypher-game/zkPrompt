use ark_ff::PrimeField;

pub mod bn254;

pub trait MiMC<F: PrimeField, const ROUNDS: usize, const EXPONENT: usize> {
    const K: F;
    const ROUND_KEYS: [F; ROUNDS];

    fn permute_feistel(state: &[F], num_outputs: usize) -> Vec<F> {
        let mut r = F::zero();
        let mut c = F::zero();
        for s in state.iter() {
            r = r + s;
            (r, c) = Self::feistel(r, c);
        }
        let mut outputs = vec![r];
        match num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..num_outputs {
                    (r, c) = Self::feistel(r, c);
                    outputs.push(r);
                }
                outputs
            }
        }
    }

    fn feistel(left: F, right: F) -> (F, F) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..ROUNDS {
            let t = match i == 0 {
                true => Self::K + x_l,
                false => Self::K + x_l + Self::ROUND_KEYS[i],
            };
            let mut tn = F::one();
            (0..EXPONENT).for_each(|_| tn *= t);
            (x_l, x_r) = match i < ROUNDS - 1 {
                true => (x_r + tn, x_l),
                false => (x_l, x_r + tn),
            };
        }
        (x_l, x_r)
    }

    fn rounds() -> usize {
        ROUNDS
    }

    fn exponent() -> usize {
        EXPONENT
    }
}
