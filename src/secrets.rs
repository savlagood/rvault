use crate::{
    cache::RedisCache,
    database::{DatabaseError, DbConn},
    models::StorageTopicAndSecretKeys,
    utils::aes::{Aes256Cipher, AesError},
    utils::{
        base64,
        common::{encrypt_string_base64, hash_string_base64},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Invalid storage encryption key. AesError: {0}")]
    InvalidStorageKey(String),

    #[error("Invalid topic encryption key. AesError: {0}")]
    InvalidTopicKey(String),

    #[error("Invalid secret encryption key. AesError: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid topic or secret encryption key")]
    InvalidKeys,

    #[error("Invalid version number")]
    InvalidVersion,

    #[error("Secret with such name already exists")]
    AlreadyExists,

    #[error("Secret with such name does not exist")]
    NotFound,

    #[error("Secret's data has been corrupted")]
    SecretCorrupted,

    #[error("Database error")]
    Database(#[from] DatabaseError),
}

fn decrypt_value(cipher: &Aes256Cipher, encrypted_value: String) -> Result<String, SecretError> {
    let encrypted_value_bytes =
        base64::decode(encrypted_value).map_err(|_| SecretError::SecretCorrupted)?;
    let decrypted_value_bytes = cipher
        .decrypt(&encrypted_value_bytes)
        .map_err(|_| SecretError::SecretCorrupted)?;

    let value =
        std::str::from_utf8(&decrypted_value_bytes).map_err(|_| SecretError::SecretCorrupted)?;

    Ok(String::from(value))
}
pub struct SecretDao {
    db: Arc<DbConn>,
    cache: Arc<RedisCache>,
}

impl SecretDao {
    pub fn new(db: Arc<DbConn>, cache: Arc<RedisCache>) -> Self {
        Self { db, cache }
    }

    pub async fn create(&self, secret: SecretDto) -> Result<(), SecretError> {
        self.db
            .create_secret(secret.clone())
            .await
            .map_err(|err| match err {
                DatabaseError::AlreadyExists => SecretError::AlreadyExists,
                _ => SecretError::Database(err),
            })?;

        let cache_key = Self::get_cache_key(&secret.hashed_topic_name, &secret.hashed_name);
        self.set_in_cache(&cache_key, &secret).await
    }

    pub async fn update(&self, secret: &SecretDto) -> Result<(), SecretError> {
        self.db
            .update_secret(secret)
            .await
            .map_err(|err| match err {
                DatabaseError::NotFound => SecretError::NotFound,
                _ => SecretError::Database(err),
            })?;

        let cache_key = Self::get_cache_key(&secret.hashed_topic_name, &secret.hashed_name);
        self.set_in_cache(&cache_key, secret).await
    }

    pub async fn delete(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<(), SecretError> {
        self.db
            .delete_secret(hashed_topic_name, hashed_name)
            .await
            .map_err(|err| match err {
                DatabaseError::NotFound => SecretError::NotFound,
                _ => SecretError::Database(err),
            })?;

        let cache_key = Self::get_cache_key(hashed_topic_name, hashed_name);
        self.delete_from_cache(&cache_key).await
    }

    pub async fn fetch_secret_names(
        &self,
        hashed_topic_name: &str,
        storage_key: &[u8],
    ) -> Result<HashSet<String>, SecretError> {
        let cipher = Aes256Cipher::new(storage_key)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        let encrypted_secret_names = self
            .db
            .fetch_topic_encrypted_secret_names(hashed_topic_name)
            .await?;

        let mut secret_names = HashSet::with_capacity(encrypted_secret_names.len());
        for encrypted_name in encrypted_secret_names {
            let secret_name = decrypt_value(&cipher, encrypted_name)?;
            secret_names.insert(secret_name);
        }

        Ok(secret_names)
    }

    pub async fn find_by_name(
        &self,
        hashed_topic_name: &str,
        name: &str,
    ) -> Result<SecretDto, SecretError> {
        let hashed_name = hash_string_base64(name);
        self.find_by_hashed_name(hashed_topic_name, &hashed_name)
            .await
    }

    pub async fn find_by_hashed_name(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<SecretDto, SecretError> {
        let cache_key = Self::get_cache_key(hashed_topic_name, hashed_name);

        if let Ok(Some(cached_secret)) = self.cache.get::<SecretDto>(&cache_key).await {
            return Ok(cached_secret);
        }

        let secret = self
            .db
            .read_secret(hashed_topic_name, hashed_name)
            .await
            .map_err(|err| match err {
                DatabaseError::Duplicate => SecretError::SecretCorrupted,
                _ => SecretError::Database(err),
            })?
            .ok_or(SecretError::NotFound)?;

        self.set_in_cache(&cache_key, &secret).await?;

        Ok(secret)
    }

    async fn set_in_cache(&self, cache_key: &str, secret: &SecretDto) -> Result<(), SecretError> {
        if let Err(err) = self.cache.set(cache_key, &secret).await {
            tracing::warn!("Failed to cache secret {}: {}", secret.hashed_name, err);
        }

        Ok(())
    }

    async fn delete_from_cache(&self, cache_key: &str) -> Result<(), SecretError> {
        if let Err(err) = self.cache.delete(cache_key).await {
            tracing::warn!("Failed to delete secret from cache {}: {}", cache_key, err);
        }

        Ok(())
    }

    fn get_cache_key(hashed_topic_name: &str, hashed_secret_name: &str) -> String {
        format!("secret:{}:{}", hashed_topic_name, hashed_secret_name)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretDto {
    pub hashed_name: String,
    pub encrypted_name: String,
    pub hashed_topic_name: String,
    pub versions: Vec<String>,
    pub cursor: usize,
    pub checksum: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
}

impl SecretDto {
    pub fn new(
        name: String,
        value: String,
        hashed_topic_name: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<Self, SecretError> {
        let hashed_name = hash_string_base64(&name);
        let encrypted_name = encrypt_string_base64(&name, keyset.storage_key)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        let encrypted_value = Self::encrypt_secret_value(value, keyset)?;

        let mut secret_dto = Self {
            hashed_name,
            encrypted_name,
            hashed_topic_name,
            versions: vec![encrypted_value],
            cursor: 0,
            checksum: "".to_string(),
            exp: None,
        };
        secret_dto
            .update_checksum(keyset)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        Ok(secret_dto)
    }

    pub fn get_current_secret_value(
        &self,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<String, SecretError> {
        let current_value = self
            .versions
            .get(self.cursor)
            .ok_or(SecretError::SecretCorrupted)?;
        Self::decrypt_secret_value(current_value.to_string(), keyset)
    }

    pub fn update_secret_value(
        &mut self,
        value: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<(), SecretError> {
        let encrypted_value = Self::encrypt_secret_value(value, keyset)?;
        self.versions.push(encrypted_value);
        self.cursor = self.versions.len() - 1;

        self.update_checksum(keyset)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        Ok(())
    }

    pub fn update_current_version(
        &mut self,
        version: usize,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<(), SecretError> {
        if version >= self.versions.len() {
            return Err(SecretError::InvalidVersion);
        }

        self.cursor = version;

        self.update_checksum(keyset)
            .map_err(|err| SecretError::InvalidStorageKey(err.to_string()))?;

        Ok(())
    }

    fn encrypt_secret_value(
        value: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<String, SecretError> {
        let value_bytes = value.as_bytes();

        let topic_cipher = Aes256Cipher::new(keyset.topic_key)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;
        let value = topic_cipher
            .encrypt(value_bytes)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;

        let secret_cipher = Aes256Cipher::new(keyset.secret_key)
            .map_err(|err| SecretError::InvalidSecretKey(err.to_string()))?;
        let encrypted_value = secret_cipher
            .encrypt(&value)
            .map_err(|err| SecretError::InvalidSecretKey(err.to_string()))?;

        Ok(base64::encode(&encrypted_value))
    }

    pub fn decrypt_secret_value(
        value: String,
        keyset: &StorageTopicAndSecretKeys,
    ) -> Result<String, SecretError> {
        let value_bytes = base64::decode(value).map_err(|_| SecretError::SecretCorrupted)?;

        let secret_cipher = Aes256Cipher::new(keyset.secret_key)
            .map_err(|err| SecretError::InvalidSecretKey(err.to_string()))?;
        let value = secret_cipher
            .decrypt(&value_bytes)
            .map_err(|err| SecretError::InvalidSecretKey(err.to_string()))?;

        let topic_cipher = Aes256Cipher::new(keyset.topic_key)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;
        let decrypted_value = topic_cipher
            .decrypt(&value)
            .map_err(|err| SecretError::InvalidTopicKey(err.to_string()))?;

        String::from_utf8(decrypted_value).map_err(|_| SecretError::SecretCorrupted)
    }

    pub fn check_integrity(&self, keyset: &StorageTopicAndSecretKeys) -> Result<(), SecretError> {
        let current_checksum = self
            .calculate_checksum(keyset)
            .map_err(|_| SecretError::InvalidKeys)?;

        if self.checksum != current_checksum {
            return Err(SecretError::InvalidKeys);
        }

        Ok(())
    }

    fn update_checksum(&mut self, keyset: &StorageTopicAndSecretKeys) -> Result<(), AesError> {
        self.checksum = self.calculate_checksum(keyset)?;
        Ok(())
    }

    fn calculate_checksum(&self, keyset: &StorageTopicAndSecretKeys) -> Result<String, AesError> {
        let mut hasher = Sha512::new();

        // Using storage and topic keys as salt
        hasher.update(keyset.storage_key);
        hasher.update(keyset.topic_key);
        hasher.update(keyset.secret_key);

        hasher.update(&self.hashed_name);
        hasher.update(&self.encrypted_name);

        for version in self.versions.iter() {
            hasher.update(version);
        }

        hasher.update(self.cursor.to_le_bytes());

        if let Some(exp) = self.exp {
            hasher.update(exp.to_le_bytes());
        }

        let checksum_bytes = hasher.finalize().to_vec();
        let encoded_base64_checksum = base64::encode(&checksum_bytes);

        Ok(encoded_base64_checksum)
    }
}
