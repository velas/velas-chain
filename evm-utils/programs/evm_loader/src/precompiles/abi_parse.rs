use ethabi::Token;
use snafu::ensure;
use solana_sdk::pubkey::Pubkey;

use super::errors::*;
use super::Result;

pub trait ParseTokens: Sized {
    fn parse(tokens: Vec<Token>) -> Result<Self>;
}

impl ParseTokens for Pubkey {
    fn parse(inputs: Vec<Token>) -> Result<Self> {
        ensure!(
            inputs.len() == 1,
            ParamsCountMismatch {
                expected: 1_usize,
                got: inputs.len()
            }
        );

        let bytes = match &inputs[0] {
            Token::FixedBytes(bytes) if bytes.len() == 32 => bytes,
            t => {
                return UnexpectedInput {
                    expected: String::from("bytes32"),
                    got: t.to_string(),
                }
                .fail()
            }
        };

        Ok(Pubkey::new(bytes))
    }
}
