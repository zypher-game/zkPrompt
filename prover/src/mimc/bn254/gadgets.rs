use super::MiMC;
use super::MimcBn254;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};

#[derive(Debug, Clone)]
pub struct MimcBn254Var<F: PrimeField> {
    pub num_outputs: usize,
    pub k: FpVar<F>,
    pub round_keys: Vec<FpVar<F>>,
}

impl<F: PrimeField> MimcBn254Var<F> {
    pub fn new(num_outputs: usize, round_keys: &[FpVar<F>]) -> Self {
        assert_eq!(
            round_keys.len(),
            MimcBn254::rounds(),
            "Invalid round keys length"
        );
        Self {
            num_outputs,
            k: FpVar::zero(),
            round_keys: round_keys.to_vec(),
        }
    }
}

impl<F: PrimeField> MimcBn254Var<F> {
    pub fn permute_feistel(&self, state: &[FpVar<F>]) -> Vec<FpVar<F>> {
        let mut r = FpVar::zero();
        let mut c = FpVar::zero();
        for s in state.iter() {
            r = r + s;
            (r, c) = self.feistel(r, c);
        }
        let mut outputs = vec![r.clone()];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    (r, c) = self.feistel(r.clone(), c);
                    outputs.push(r.clone());
                }
                outputs
            }
        }
    }

    fn feistel(&self, left: FpVar<F>, right: FpVar<F>) -> (FpVar<F>, FpVar<F>) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..MimcBn254::rounds() {
            let t = match i == 0 {
                true => &self.k + &x_l,
                false => &self.k + &x_l + &self.round_keys[i],
            };
            let mut tn = FpVar::one();
            (0..MimcBn254::exponent()).for_each(|_| tn = &tn * &t);
            (x_l, x_r) = match i < MimcBn254::rounds() - 1 {
                true => (&x_r + &tn, x_l),
                false => (x_l, &x_r + &tn),
            };
        }
        (x_l, x_r)
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::{ns, r1cs::ConstraintSystem};
    use ark_std::test_rng;

    use crate::mimc::{
        bn254::{gadgets::MimcBn254Var, MimcBn254},
        MiMC,
    };

    #[test]
    fn test_mimc() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rand = test_rng();

        let mut round_constant_vars = vec![];
        for c in MimcBn254::ROUND_KEYS {
            round_constant_vars.push(FpVar::new_constant(ns!(cs, "alloc round keys"), c).unwrap());
        }

        let mimc = MimcBn254Var::new(1, &round_constant_vars);
        let input = Fr::rand(&mut rand);
        let input_var = FpVar::new_witness(ns!(cs, "alloc input"), || Ok(input)).unwrap();

        let output_var = mimc.permute_feistel(&[input_var]);
        assert_eq!(
            output_var[0].value().unwrap().to_string().as_str(),
            "16222109634343783365645707049387040728067039469929484045209032231701032088716"
        );
        assert!(cs.is_satisfied().unwrap());
    }
}
