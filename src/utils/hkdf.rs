use hkdf::Hkdf;
use sha2::Sha512;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HkdfError {
    #[error("Invalid length of okm - impossible")]
    InvalidLength(String),
}

pub fn string_into_256_bit_key(data: String) -> Result<Vec<u8>, HkdfError> {
    // ikm - Initial Key Material
    let ikm = data.as_bytes();

    let salt = [0u8; 32];
    let hk = Hkdf::<Sha512>::new(Some(&salt), ikm);

    // okm - Output Key Material
    let mut okm = vec![0u8; 32];

    let info = b"key-from-string";
    hk.expand(info, &mut okm)
        .map_err(|err| HkdfError::InvalidLength(err.to_string()))?;

    Ok(okm)
}
