use ark_ff::PrimeField;
use ark_r1cs_std::{uint32::UInt32, uint8::UInt8, R1CSVar};
use ark_relations::r1cs::SynthesisError;
use round::Round;

pub mod quarter_round;
pub mod round;

pub struct ChaCha20Var<F: PrimeField> {
    pub qr_constant_vars: Vec<UInt32<F>>,
    pub key_vars: Vec<UInt32<F>>,
    pub nonce_vars: Vec<UInt32<F>>,
    pub count_var: UInt32<F>,
    pub input_vars: Vec<UInt8<F>>,
    pub output_vars: Vec<UInt8<F>>,
}

impl<F: PrimeField> ChaCha20Var<F> {
    pub fn new(
        qr_constant_vars: &[UInt32<F>],
        key_vars: &[UInt32<F>],
        nonce_vars: &[UInt32<F>],
        count_var: UInt32<F>,
        input_vars: &[UInt8<F>],
    ) -> Self {
        assert_eq!(qr_constant_vars.len(), 4);
        assert_eq!(key_vars.len(), 8);
        assert_eq!(nonce_vars.len(), 3);

        Self {
            qr_constant_vars: qr_constant_vars.to_vec(),
            key_vars: key_vars.to_vec(),
            nonce_vars: nonce_vars.to_vec(),
            count_var,
            input_vars: input_vars.to_vec(),
            output_vars: vec![],
        }
    }

    pub fn generate_constraints(&mut self) -> Result<(), SynthesisError> {
        let mut state_vars = self.qr_constant_vars.clone();
        state_vars.extend_from_slice(&self.key_vars);
        state_vars.push(self.count_var.clone());
        state_vars.extend_from_slice(&self.nonce_vars);

        let mut cipher_vars = vec![];

        for chunk_vars in self.input_vars.chunks(64) {
            let mut round = Round::new(&state_vars);
            round.generate_constraints()?;

            for (msg, key) in chunk_vars.iter().zip(round.key_stream.iter()) {
                cipher_vars.push(key ^ msg);
            }

            state_vars[12] = state_vars[12].wrapping_add(&UInt32::constant(1))
        }

        self.output_vars = cipher_vars;

        Ok(())
    }

    pub fn consistency_check(&self, expect: Vec<u8>) {
        let output = self
            .output_vars
            .iter()
            .map(|v| v.value().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(output, expect);
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, uint8::UInt8};
    use ark_relations::{ns, r1cs::ConstraintSystem};

    use super::ChaCha20Var;

    #[test]
    fn test_chacha20_constraint_case0() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars = vec![
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc key"), || Ok(0)).unwrap(),
        ];
        let nonce_vars = vec![
            UInt32::new_witness(ns!(cs, "alloc nonce"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc nonce"), || Ok(0)).unwrap(),
            UInt32::new_witness(ns!(cs, "alloc nonce"), || Ok(0)).unwrap(),
        ];
        let count_vars = UInt32::new_witness(ns!(cs, "alloc counter"), || Ok(1)).unwrap();
        let qr_constant_vars = vec![
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x61707865).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x3320646e).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x79622d32).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x6b206574).unwrap(),
        ];

        let input_vars = vec![
            UInt8::new_witness(ns!(cs, "alloc input"), || Ok(49)).unwrap(),
            UInt8::new_witness(ns!(cs, "alloc input"), || Ok(50)).unwrap(),
            UInt8::new_witness(ns!(cs, "alloc input"), || Ok(51)).unwrap(),
            UInt8::new_witness(ns!(cs, "alloc input"), || Ok(52)).unwrap(),
        ];

        let mut chacha20 = ChaCha20Var::new(
            &qr_constant_vars,
            &key_vars,
            &nonce_vars,
            count_vars,
            &input_vars,
        );
        chacha20.generate_constraints().unwrap();

        chacha20.consistency_check(vec![174, 53, 212, 138]);
    }

    #[test]
    fn test_chacha20_constraint_case1() {
        let key = hex::decode("2d1dd3fe94156f0063372d1523a10b542348f3ad7491fec44390ad24a2f3edc7")
            .unwrap();
        let key_chunks = key
            .chunks(4)
            .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
            .collect::<Vec<_>>();

        let nonce = hex::decode("4a1f503da88baa6e582a2fe1").unwrap();
        let nonce_chunks = nonce
            .chunks(4)
            .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
            .collect::<Vec<_>>();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars = key_chunks
            .iter()
            .map(|x| UInt32::new_witness(ns!(cs, "alloc key"), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();
        let nonce_vars = nonce_chunks
            .iter()
            .map(|x| UInt32::new_witness(ns!(cs, "alloc nonce"), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();
        let count_vars = UInt32::new_witness(ns!(cs, "alloc counter"), || Ok(1)).unwrap();
        let qr_constant_vars = vec![
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x61707865).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x3320646e).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x79622d32).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x6b206574).unwrap(),
        ];

        let input = hex::decode( "546f6d6f72726f772077696c6c20626520626574746572212121212121212121546f6d6f72726f772077696c6c20626520626574746572212121212121212121").unwrap();
        let input_vars = input
            .iter()
            .map(|x| UInt8::new_witness(ns!(cs, "alloc input"), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let mut chacha20 = ChaCha20Var::new(
            &qr_constant_vars,
            &key_vars,
            &nonce_vars,
            count_vars,
            &input_vars,
        );
        chacha20.generate_constraints().unwrap();

        let output = hex::decode( "8160bef4ce75a63610b85375619fe20c3bcc2e154389b74741755681dd0ad37b2201671a36852729da74b958182bafb4d9bd6c2b348ae3277aaa056e1230ef9d").unwrap();
        chacha20.consistency_check(output);

        assert_eq!(cs.num_constraints(), 23106);
    }
}
