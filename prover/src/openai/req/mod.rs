use std::env;

use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;
use traits::ReqConstraint;

use crate::utils::enforce_equals;

pub mod traits;

pub struct ReqVar<F: PrimeField> {
    pub data_vars: Vec<UInt8<F>>,
    pub prompt_len: usize,
}

impl<F: PrimeField> ReqVar<F> {
    pub fn new(data_vars: &[UInt8<F>], prompt_len: usize) -> Self {
        Self {
            data_vars: data_vars.to_vec(),
            prompt_len,
        }
    }

    pub fn prompt_start(&self) -> usize {
        Self::req_line().len()
            + Self::host().len()
            + Self::authorization().len()
            + Self::content_type().len()
            + Self::content_length().len()
            + Self::connection().len()
            + 2
            + 1
            + Self::system_prompt_key().len()
    }
}

impl<F: PrimeField> ReqConstraint for ReqVar<F> {
    fn req_line() -> Vec<u8> {
        format!("POST {} HTTP/1.1\r\n", env::var("URL").unwrap())
            .as_bytes()
            .to_vec()
    }

    fn host() -> Vec<u8> {
        format!("Host:{}\r\n", env::var("HOST").unwrap())
            .as_bytes()
            .to_vec()
    }

    fn authorization() -> Vec<u8> {
        format!(
            "Authorization:Bearer {}\r\n",
            env::var("OPENAI_API_KEY").unwrap()
        )
        .as_bytes()
        .to_vec()
    }

    fn content_type() -> Vec<u8> {
        "Content-Type:application/json\r\n".as_bytes().to_vec()
    }

    fn content_length() -> Vec<u8> {
        format!("Content-Length:{}\r\n", env::var("CONTENT_LENGTH").unwrap())
            .as_bytes()
            .to_vec()
    }

    fn connection() -> Vec<u8> {
        "Connection:close\r\n".as_bytes().to_vec()
    }

    fn system_prompt_key() -> Vec<u8> {
        "\"messages\":[{\"role\":\"system\",\"content\":\""
            .as_bytes()
            .to_vec()
    }

    fn generate_constraints(&self) -> Result<(), SynthesisError> {
        let req_line = Self::req_line();
        let host = Self::host();
        let authorization = Self::authorization();
        let content_type = Self::content_type();
        let content_length = Self::content_length();
        let connection = Self::connection();
        let system_prompt_key = Self::system_prompt_key();

        let req_line_vars = req_line
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let host_vars = host
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let authorization_vars = authorization
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let content_type_vars = content_type
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let content_length_vars = content_length
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let connection_vars = connection
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();
        let system_prompt_key_vars = system_prompt_key
            .iter()
            .map(|x| UInt8::constant(*x))
            .collect::<Vec<UInt8<F>>>();

        let mut start = 0;
        let mut end = req_line.len();
        enforce_equals(&req_line_vars, &self.data_vars[start..end])?;

        start = end;
        end += host.len();
        enforce_equals(&host_vars, &self.data_vars[start..end])?;

        start = end;
        end += authorization.len();
        enforce_equals(&authorization_vars, &self.data_vars[start..end])?;

        start = end;
        end += content_type.len();
        enforce_equals(&content_type_vars, &self.data_vars[start..end])?;

        start = end;
        end += content_length.len();
        enforce_equals(&content_length_vars, &self.data_vars[start..end])?;

        start = end;
        end += connection.len();
        enforce_equals(&connection_vars, &self.data_vars[start..end])?;

        // skip "\r\n"
        end += 2;

        // skip "{""
        end += 1;

        start = end;
        end += system_prompt_key.len();
        enforce_equals(&system_prompt_key_vars, &self.data_vars[start..end])?;

        // skip prompt
        end += self.prompt_len;

        start = end;
        end += 3; // "\"},"
        enforce_equals(
            &[
                UInt8::constant(34),
                UInt8::constant(125),
                UInt8::constant(39),
            ],
            &self.data_vars[start..end],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::env;

    use ark_bn254::Fr;
    use ark_r1cs_std::uint8::UInt8;

    use super::traits::ReqConstraint;
    use crate::openai::req::ReqVar;

    #[test]
    fn test_req_constraint() {
        env::set_var("HOST", "api.openai.com");
        env::set_var("URL", "/v1/chat/completions");
        env::set_var("OPENAI_API_KEY", "sk-svcacct");
        env::set_var("CONTENT_LENGTH", "1024");

        let byes = hex::decode("504f5354202f76312f636861742f636f6d706c6574696f6e7320485454502f312e310d0a486f73743a6170692e6f70656e61692e636f6d0d0a417574686f72697a6174696f6e3a42656172657220736b2d737663616363740d0a436f6e74656e742d547970653a6170706c69636174696f6e2f6a736f6e0d0a436f6e74656e742d4c656e6774683a313032340d0a436f6e6e656374696f6e3a636c6f73650d0a0d0a7b226d65737361676573223a5b7b22726f6c65223a2273797374656d222c22636f6e74656e74223a22796f75206172652061207a7970686572206769726c21227d2c7b22726f6c65223a2275736572222c22636f6e74656e74223a227768617420697320796f7572206e616d653f227d5d2c226d6f64656c223a226770742d346f2d6d696e69222c2274656d7065726174757265223a20302e377d").unwrap();
        let byte_vars = byes
            .iter()
            .map(|b| UInt8::constant(*b))
            .collect::<Vec<UInt8<Fr>>>();

        let var = ReqVar::new(&byte_vars, 22);
        var.generate_constraints().unwrap();
    }
}
