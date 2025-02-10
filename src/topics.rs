use crate::crypto;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/*
create_topic()
*/

#[derive(Error, Debug)]
pub enum TopicsError {
    // #[error("Checksum mismatch")]
    // ChecksumMismatch,
    #[error("Invalid storage encryption key")]
    InvalidStorageEncryptionKey,

    #[error("Invalid topic encryption key")]
    InvalidTopicEncryptionKey,
}

#[derive(Serialize, Deserialize)]
pub struct Topic {
    pub name: String,
    pub secrets: Vec<String>,
    pub checksum: String,
}

impl Topic {
    pub fn new(name: String, storage_key: &[u8], topic_key: &[u8]) -> Result<Self, TopicsError> {
        let mut topic = Self {
            name,
            secrets: Vec::new(),
            checksum: "".to_string(),
        };
        topic.update_hash(storage_key, topic_key)?;

        Ok(topic)
    }

    // TODO - future
    // pub fn ensure_integrity(
    //     &self,
    //     storage_key: &[u8],
    //     topic_key: &[u8],
    // ) -> Result<(), TopicsError> {
    //     let calculated_hash = self.calculate_hash(storage_key, topic_key)?;

    //     if calculated_hash == self.checksum {
    //         Ok(())
    //     } else {
    //         Err(TopicsError::ChecksumMismatch)
    //     }
    // }

    fn update_hash(&mut self, storage_key: &[u8], topic_key: &[u8]) -> Result<(), TopicsError> {
        self.checksum = self.calculate_hash(storage_key, topic_key)?;
        Ok(())
    }

    fn calculate_hash(&self, storage_key: &[u8], topic_key: &[u8]) -> Result<String, TopicsError> {
        let mut hasher = Sha256::new();

        hasher.update(&self.name);

        let mut sorted_secrets = self.secrets.clone();
        sorted_secrets.sort();
        for secret in sorted_secrets {
            hasher.update(secret);
        }

        let checksum_bytes = hasher.finalize().to_vec();

        let encrypted_checksum = self.encrypt_checksum(checksum_bytes, storage_key, topic_key)?;

        let checksum_base64 = crypto::base64::encode(&encrypted_checksum);
        Ok(checksum_base64)
    }

    fn encrypt_checksum(
        &self,
        checksum: Vec<u8>,
        storage_key: &[u8],
        topic_key: &[u8],
    ) -> Result<Vec<u8>, TopicsError> {
        let storage_cipher = crypto::aes::Aes256Cipher::new(storage_key)
            .map_err(|_err| TopicsError::InvalidStorageEncryptionKey)?;
        let encrypted_checksum = storage_cipher
            .encrypt(&checksum)
            .map_err(|_err| TopicsError::InvalidStorageEncryptionKey)?;

        let topic_cipher = crypto::aes::Aes256Cipher::new(topic_key)
            .map_err(|_err| TopicsError::InvalidTopicEncryptionKey)?;
        let encrypted_checksum = topic_cipher
            .encrypt(&encrypted_checksum)
            .map_err(|_err| TopicsError::InvalidTopicEncryptionKey)?;

        Ok(encrypted_checksum)
    }
}
