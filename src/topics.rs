use crate::{crypto, database::DatabaseError, state::AppState};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub async fn fetch_topic_names(state: AppState) -> Result<Vec<String>, TopicsError> {
    let storage = state.get_storage_read().await;
    let storage_key = storage
        .get_encryption_key()
        .map_err(|_| TopicsError::InvalidStorageEncryptionKey)?;

    let db = state.get_db();
    let encrypted_topic_names = db.fetch_list_of_topics_encrypted_names().await?;

    let cipher = crypto::aes::Aes256Cipher::new(storage_key)
        .map_err(|_| TopicsError::InvalidStorageEncryptionKey)?;

    let mut topic_names = Vec::with_capacity(encrypted_topic_names.capacity());
    for encrypted_name in encrypted_topic_names {
        let encrypted_bytes =
            crypto::base64::decode(encrypted_name).map_err(|_| TopicsError::TopicCorrupted)?;
        let decrypted_bytes = cipher
            .decrypt(&encrypted_bytes)
            .map_err(|_| TopicsError::TopicCorrupted)?;

        let topic_name =
            std::str::from_utf8(&decrypted_bytes).map_err(|_| TopicsError::TopicCorrupted)?;
        topic_names.push(String::from(topic_name));
    }

    // TODO - нужно все названия расшифровать и сохранить в вектор

    Ok(topic_names)
}

pub async fn create_topic(name: String, state: AppState) -> Result<Vec<u8>, TopicsError> {
    let storage = state.get_storage_read().await;

    let storage_key = storage
        .get_encryption_key()
        .map_err(|_| TopicsError::InvalidStorageEncryptionKey)?;
    let topic_key = crypto::generate_256_bit_key();

    let topic = Topic::new(name, storage_key, &topic_key)?;

    let db = state.get_db();
    db.create_topic(topic).await.map_err(|err| match err {
        DatabaseError::TopicAlreadyExists => TopicsError::TopicAlreadyExists,
        _ => TopicsError::Database(err),
    })?;

    Ok(topic_key)
}

#[derive(Error, Debug)]
pub enum TopicsError {
    // #[error("Checksum mismatch")]
    // ChecksumMismatch,
    #[error("Invalid storage encryption key")]
    InvalidStorageEncryptionKey,

    #[error("Invalid topic encryption key")]
    InvalidTopicEncryptionKey,

    #[error("Topic with such name already exists")]
    TopicAlreadyExists,

    #[error("Topic's data has been corrupted")]
    TopicCorrupted,

    #[error("Database error")]
    Database(#[from] DatabaseError),
}

#[derive(Serialize, Deserialize)]
pub struct Topic {
    pub hashed_name: String,
    pub encrypted_name: String,
    pub secrets: Vec<String>,
    pub checksum: String,
}

impl Topic {
    pub fn new(name: String, storage_key: &[u8], topic_key: &[u8]) -> Result<Self, TopicsError> {
        let hashed_name = crypto::hash_string_base64(name.as_str());
        let encrypted_name = crypto::encrypt_string_base64(name.as_str(), storage_key)
            .map_err(|_| TopicsError::InvalidStorageEncryptionKey)?;

        let mut topic = Self {
            hashed_name,
            encrypted_name,
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

        hasher.update(&self.hashed_name);
        hasher.update(&self.encrypted_name);

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
