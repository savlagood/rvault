use aes_gcm::{
    aead::{Aead, OsRng},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use rand::Rng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AesError {
    #[error("Encryption key must be 32 bytes long, but got {0} bytes")]
    InvalidKeyLength(usize),

    #[error("Ciphertext too short: expected at least 12 bytes, got {0}")]
    InvalidCiphertextLength(usize),

    #[error("Invalid ciphertext")]
    InvalidCiphertext(String),

    #[error("Failed to encrypt plaintext")]
    EncryptionFailed(String),
}

impl From<aes_gcm::Error> for AesError {
    fn from(err: aes_gcm::Error) -> Self {
        AesError::EncryptionFailed(err.to_string())
    }
}

pub struct Aes256Cipher {
    cipher: Aes256Gcm,
}

impl Aes256Cipher {
    pub fn new(encryption_key: &[u8]) -> Result<Self, AesError> {
        if encryption_key.len() != 32 {
            return Err(AesError::InvalidKeyLength(encryption_key.len()));
        }

        let key = Key::<Aes256Gcm>::from_slice(encryption_key);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AesError> {
        let nonce_bytes: [u8; 12] = OsRng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext)?;

        Ok([nonce_bytes.as_slice(), &ciphertext].concat())
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
        if ciphertext.len() < 12 {
            return Err(AesError::InvalidCiphertextLength(ciphertext.len()));
        }

        let (nonce, ciphertext) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|err| AesError::InvalidCiphertext(err.to_string()))?;
        Ok(plaintext)
    }
}
