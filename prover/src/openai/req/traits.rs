use ark_relations::r1cs::SynthesisError;

pub trait ReqConstraint {
    fn req_line() -> Vec<u8>;

    fn host() -> Vec<u8>;

    fn authorization() -> Vec<u8>;

    fn content_type() -> Vec<u8>;

    fn content_length() -> Vec<u8>;

    fn connection() -> Vec<u8>;

    fn system_prompt_key() -> Vec<u8>;

    fn generate_constraints(&mut self) -> Result<(), SynthesisError>;
}
