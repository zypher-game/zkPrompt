use std::env;

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::ToBitsGadget,
    uint32::UInt32,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use crate::{
    chacha20::ChaCha20Var,
    mimc::{
        bn254::{constraint::MimcBn254Var, MimcBn254},
        MiMC,
    },
    openai::req::{traits::ReqConstraint, ReqVar},
    utils::compress_var,
};

pub struct ZkPrompt {
    pub cipher_texts: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub count: u32,
}

impl ConstraintSynthesizer<Fr> for ZkPrompt {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut key_vars = vec![];
        for chunk in self.key.chunks(4) {
            let val = u32::from_le_bytes(chunk.try_into().unwrap());
            let var = UInt32::new_witness(ns!(cs, "alloc key"), || Ok(val))?;
            key_vars.push(var);
        }

        let mut nonce_vars = vec![];
        for chunk in self.nonce.chunks(4) {
            let val = u32::from_le_bytes(chunk.try_into().unwrap());
            let var = UInt32::new_witness(ns!(cs, "alloc key"), || Ok(val))?;
            nonce_vars.push(var);
        }

        let qr_constant_vars = vec![
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x61707865).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x3320646e).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x79622d32).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x6b206574).unwrap(),
        ];

        let count_var = UInt32::new_witness(ns!(cs, "alloc count"), || Ok(self.count))?;
        let cipher_vars = self
            .cipher_texts
            .iter()
            .map(|x| UInt8::new_witness(ns!(cs, "alloc cipher"), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let mut chacha20 = ChaCha20Var::new(
            &qr_constant_vars,
            &key_vars,
            &nonce_vars,
            count_var,
            &cipher_vars,
        );
        chacha20.generate_constraints()?;

        let prompt_len = env::var("PROMPT_LEN").unwrap().parse().unwrap();
        let req_var = ReqVar::new(&chacha20.output_vars, prompt_len);
        req_var.generate_constraints()?;

        let start = req_var.prompt_start();
        let end = start + prompt_len;
        let prompt = &chacha20.output_vars[start..end];

        let mut round_constant_vars = vec![];
        for c in MimcBn254::ROUND_KEYS {
            round_constant_vars.push(FpVar::new_constant(ns!(cs, "alloc round keys"), c).unwrap());
        }
        let mimc_var = MimcBn254Var::new(1, &round_constant_vars, FpVar::zero());

        let mut prompt_bits = vec![];
        for p in prompt {
            prompt_bits.extend(p.to_bits_be()?);
        }
        let compress_prompt = compress_var(&prompt_bits, 250)?;
        let prompt_commitment = mimc_var.generate_constraints(&compress_prompt)[0].clone();

        let mut cipher_bits = vec![];
        for c in cipher_vars {
            cipher_bits.extend(c.to_bits_be()?);
        }
        let compress_cipher = compress_var(&cipher_bits, 250)?;
        let cipher_commitment = mimc_var.generate_constraints(&compress_cipher)[0].clone();

        let pi_prompt_commitment =
            FpVar::new_input(ns!(cs, "public prompt"), || prompt_commitment.value())?;
        pi_prompt_commitment.enforce_equal(&prompt_commitment)?;

        let pi_cipher_commitment =
            FpVar::new_input(ns!(cs, "public cipher"), || cipher_commitment.value())?;
        pi_cipher_commitment.enforce_equal(&cipher_commitment)?;

        println!("cs size:{}", cs.num_constraints());

        Ok(())
    }
}
