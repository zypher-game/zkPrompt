use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

pub fn enforce_equals<F: PrimeField>(a: &[UInt8<F>], b: &[UInt8<F>]) -> Result<(), SynthesisError> {
    for (v0, v1) in a.iter().zip(b.iter()) {
        v0.enforce_equal(v1)?
    }
    Ok(())
}

pub fn compress_var<F: PrimeField>(
    vars: &[Boolean<F>],
    chunk_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut compress_vars = vec![];
    for chunk in vars.chunks(chunk_len) {
        let var = Boolean::le_bits_to_fp(chunk)?;
        compress_vars.push(var);
    }
    Ok(compress_vars)
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_r1cs_std::prelude::Boolean;
    use ark_r1cs_std::R1CSVar;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    use super::compress_var;

    fn u8_to_le_bits(n: u8) -> [bool; 8] {
        let mut bits = [false; 8];
        for i in 0..8 {
            bits[i] = (n >> i) & 1 == 1;
        }
        bits
    }

    #[test]
    fn test_compress() {
        let mut rng = test_rng();
        let data = (0..1000).map(|_| u8::rand(&mut rng)).collect::<Vec<_>>();
        let data_bytes = data
            .iter()
            .map(|x| u8_to_le_bits(*x))
            .flatten()
            .collect::<Vec<_>>();

        let data_var = data_bytes
            .iter()
            .map(|d| Boolean::constant(*d))
            .collect::<Vec<Boolean<Fr>>>();
        let output_vars = compress_var(&data_var, 248).unwrap();
        let output = output_vars
            .iter()
            .map(|x| x.value().unwrap())
            .collect::<Vec<_>>();

        let expect = data
            .chunks(31)
            .map(|x| Fr::from_le_bytes_mod_order(x))
            .collect::<Vec<_>>();
        assert_eq!(output, expect);
    }
}
