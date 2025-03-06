use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Base64Error {
    #[error("Failed to decode base64: {0}")]
    DecodeError(#[from] base64::DecodeError),
}

pub fn encode(data: &[u8]) -> String {
    STANDARD_NO_PAD.encode(data)
}

pub fn decode(encoded_data: String) -> Result<Vec<u8>, Base64Error> {
    Ok(STANDARD_NO_PAD.decode(encoded_data)?)
}
