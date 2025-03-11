use crate::{
    database::{DatabaseError, DbConn},
    models::StorageAndTopicKeys,
    storage::StorageError,
    utils::{
        aes::{Aes256Cipher, AesError},
        base64,
        common::{encrypt_string_base64, hash_string_base64},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TopicError {
    #[error("Topic with such name already exists")]
    AlreadyExists,

    #[error("Invalid storage encryption key")]
    InvalidStorageEncryptionKey(#[from] AesError),

    #[error("Storage error")]
    Storage(#[from] StorageError),

    #[error("Database error")]
    Database(#[from] DatabaseError),

    #[error("Topic's data has been corrupted")]
    TopicCorrupted,

    #[error("Topic was not found")]
    NotFound,

    #[error("Invalid topic encryption key")]
    InvalidKey,
}

fn decrypt_value(cipher: &Aes256Cipher, encrypted_value: String) -> Result<String, TopicError> {
    let encrypted_value_bytes =
        base64::decode(encrypted_value).map_err(|_| TopicError::TopicCorrupted)?;
    let decrypted_value_bytes = cipher
        .decrypt(&encrypted_value_bytes)
        .map_err(|_| TopicError::TopicCorrupted)?;

    let value =
        std::str::from_utf8(&decrypted_value_bytes).map_err(|_| TopicError::TopicCorrupted)?;

    Ok(String::from(value))
}

pub struct TopicDao {
    db: Arc<DbConn>,
}

impl TopicDao {
    pub fn new(db: Arc<DbConn>) -> Self {
        Self { db }
    }

    pub async fn create(&self, topic: TopicDto) -> Result<(), TopicError> {
        self.db.create_topic(topic).await.map_err(|err| match err {
            DatabaseError::AlreadyExists => TopicError::AlreadyExists,
            _ => TopicError::Database(err),
        })
    }

    pub async fn update(&self, topic: TopicDto) -> Result<(), TopicError> {
        self.db.update_topic(&topic).await.map_err(|err| match err {
            DatabaseError::NotFound => TopicError::NotFound,
            _ => TopicError::Database(err),
        })
    }

    pub async fn fetch_topic_names(
        &self,
        storage_key: &[u8],
    ) -> Result<HashSet<String>, TopicError> {
        let cipher =
            Aes256Cipher::new(storage_key).map_err(TopicError::InvalidStorageEncryptionKey)?;

        let encrypted_topic_names = self.db.fetch_encrypted_topic_names().await?;

        let mut topic_names = HashSet::with_capacity(encrypted_topic_names.len());
        for encrypted_name in encrypted_topic_names {
            let topic_name = decrypt_value(&cipher, encrypted_name)?;
            topic_names.insert(topic_name);
        }

        Ok(topic_names)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<TopicDto, TopicError> {
        let hashed_name = hash_string_base64(name);
        self.find_by_hashed_name(&hashed_name).await
    }

    async fn find_by_hashed_name(&self, hashed_name: &str) -> Result<TopicDto, TopicError> {
        self.db
            .read_topic(hashed_name)
            .await
            .map_err(|err| match err {
                DatabaseError::Duplicate => TopicError::TopicCorrupted,
                _ => TopicError::Database(err),
            })?
            .ok_or(TopicError::NotFound)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TopicDto {
    pub hashed_name: String,
    pub encrypted_name: String,
    pub secret_hashed_names: Vec<String>,
    pub checksum: String,
}

impl TopicDto {
    pub fn new(name: String, keyset: &StorageAndTopicKeys) -> Result<Self, TopicError> {
        let hashed_name = hash_string_base64(&name);

        let encrypted_name = encrypt_string_base64(&name, keyset.storage_key)
            .map_err(TopicError::InvalidStorageEncryptionKey)?;

        let mut topic_dto = Self {
            hashed_name,
            encrypted_name,
            secret_hashed_names: Vec::new(),
            checksum: String::new(),
        };
        topic_dto
            .update_checksum(keyset)
            .map_err(TopicError::InvalidStorageEncryptionKey)?;

        Ok(topic_dto)
    }

    pub fn is_contains_secret(&self, secret_hashed_name: &String) -> bool {
        self.secret_hashed_names.contains(secret_hashed_name)
    }

    pub fn check_integrity(&self, keyset: &StorageAndTopicKeys) -> Result<(), TopicError> {
        let current_checksum = self.calculate_checksum(keyset)?;

        if self.checksum != current_checksum {
            return Err(TopicError::InvalidKey);
        }

        Ok(())
    }

    pub fn contains_secret_name(&self, secret_name: &str) -> bool {
        let hashed_secret_name = hash_string_base64(secret_name);
        self.contains_hashed_secret_name(&hashed_secret_name)
    }

    pub fn contains_hashed_secret_name(&self, hashed_name: &String) -> bool {
        self.secret_hashed_names.contains(hashed_name)
    }

    pub fn add_hashed_secret_name(
        &mut self,
        name: String,
        keyset: &StorageAndTopicKeys,
    ) -> Result<(), TopicError> {
        self.secret_hashed_names.push(name);
        self.update_checksum(keyset)
            .map_err(TopicError::InvalidStorageEncryptionKey)?;

        Ok(())
    }

    pub fn remove_hashed_secret_name(
        &mut self,
        name: String,
        keyset: &StorageAndTopicKeys,
    ) -> Result<(), TopicError> {
        self.secret_hashed_names.retain(|x| x != &name);
        self.update_checksum(keyset)
            .map_err(TopicError::InvalidStorageEncryptionKey)?;

        Ok(())
    }

    fn update_checksum(&mut self, keyset: &StorageAndTopicKeys) -> Result<(), AesError> {
        self.checksum = self.calculate_checksum(keyset)?;
        Ok(())
    }

    fn calculate_checksum(&self, keyset: &StorageAndTopicKeys) -> Result<String, AesError> {
        let mut hasher = Sha512::new();

        // Using storage and topic keys as salt
        hasher.update(keyset.storage_key);
        hasher.update(keyset.topic_key);

        hasher.update(&self.hashed_name);
        hasher.update(&self.encrypted_name);

        let mut sorted_secrets = self.secret_hashed_names.clone();
        sorted_secrets.sort();
        for secret in sorted_secrets {
            hasher.update(secret);
        }

        let checksum_bytes = hasher.finalize().to_vec();
        let encoded_base64_checksum = base64::encode(&checksum_bytes);

        Ok(encoded_base64_checksum)
    }
}
