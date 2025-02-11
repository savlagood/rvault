use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

pub fn generate_256_bit_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn hash_string_base64(data: &str) -> String {
    let hash = Sha256::digest(data.as_bytes());
    base64::encode(&hash)
}

pub fn encrypt_string_base64(data: &str, key: &[u8]) -> Result<String, aes::AesError> {
    let cipher = aes::Aes256Cipher::new(key)?;
    let encrypted_data_bytes = cipher.encrypt(data.as_bytes())?;
    let encrypted_data = base64::encode(&encrypted_data_bytes);

    Ok(encrypted_data)
}

pub mod base64 {
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
}

pub mod aes {
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
}

pub mod shared_keys {
    use crate::crypto;
    use rand::seq::IteratorRandom;
    use serde::{Deserialize, Serialize};
    use shamir::SecretData;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum SharedKeysError {
        #[error("Invalid share ID: {0} - must be greater that 0")]
        ShareId(u8),

        #[error("Invalid shared keys")]
        SharedKeys,

        #[error("Invalid shared keys settings. The inequality must be satisfied: 0 < threshold < total_keys")]
        Settings,
    }

    impl From<crypto::base64::Base64Error> for SharedKeysError {
        fn from(_err: crypto::base64::Base64Error) -> Self {
            SharedKeysError::SharedKeys
        }
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct SharedKeysSettings {
        pub threshold: u8,
        pub total_keys: u8,
    }

    impl SharedKeysSettings {
        pub fn assert_valid(&self) -> Result<(), SharedKeysError> {
            if !(1 < self.threshold && self.threshold < self.total_keys) {
                Err(SharedKeysError::Settings)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct SharedKeys {
        shares: Vec<String>,
    }

    impl SharedKeys {
        pub fn from_key(
            key: Vec<u8>,
            settings: &SharedKeysSettings,
        ) -> Result<Self, SharedKeysError> {
            let secret = crypto::base64::encode(&key);
            let secret_data = SecretData::with_secret(&secret, settings.threshold);

            let range = 1..=u8::MAX;
            let indices = choose_random_indices(range, settings.total_keys);

            let shares = indices
                .into_iter()
                .map(|id| {
                    secret_data
                        .get_share(id)
                        .map(|shared_key| crypto::base64::encode(&shared_key))
                        .map_err(|_err| SharedKeysError::ShareId(id))
                })
                .collect::<Result<Vec<String>, SharedKeysError>>()?;

            Ok(Self { shares })
        }

        pub fn into_key(self, threshold: u8) -> Result<Vec<u8>, SharedKeysError> {
            let shared_keys_bytes = self
                .shares
                .into_iter()
                .map(crypto::base64::decode)
                .collect::<Result<Vec<Vec<u8>>, _>>()?;

            let recovered_key_str = SecretData::recover_secret(threshold, shared_keys_bytes)
                .ok_or(SharedKeysError::SharedKeys)?;
            let recovered_key_bytes = crypto::base64::decode(recovered_key_str)?;

            Ok(recovered_key_bytes)
        }
    }

    fn choose_random_indices(range: std::ops::RangeInclusive<u8>, total: u8) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        range.choose_multiple(&mut rng, total as usize)
    }
}
