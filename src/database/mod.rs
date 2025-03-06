use crate::{secrets::SecretDto, storage::StorageDto, topics::TopicDto};
use async_trait::async_trait;
use std::collections::HashSet;
use thiserror::Error;

pub mod builder;
pub mod mongo;

const DB_TYPE_MONGO: &str = "mongodb";

pub type DbConn = Box<dyn DatabaseConnection + Send + Sync>;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Unknown database type: {0}")]
    UnknownType(String),

    #[error("Error when setuping database factory: {0}")]
    FactorySetup(String),

    #[error("Error when creating connection with database: {0}")]
    Connection(String),

    #[error("Error when performing an operation with db: {0}")]
    Operation(String),

    #[error("Serialization/deserialization error: {0}")]
    Representation(String),

    #[error("Such object already exists")]
    AlreadyExists,

    #[error("Object is duplicated")]
    Duplicate,

    #[error("Desired object was not found")]
    NotFound,
}

pub enum DatabaseType {
    Mongo,
}

impl DatabaseType {
    pub fn from_str(db_type: &str) -> Result<Self, DatabaseError> {
        let db_type = match db_type {
            DB_TYPE_MONGO => DatabaseType::Mongo,
            _ => return Err(DatabaseError::UnknownType(String::from(db_type))),
        };

        Ok(db_type)
    }
}

#[async_trait]
pub trait DatabaseConnection {
    // needed for testing
    #[cfg(test)]
    async fn drop_database(&self) -> Result<(), DatabaseError>;

    // storage operations
    async fn read_storage(&self) -> Result<Option<StorageDto>, DatabaseError>;
    async fn save_storage(&self, storage: &StorageDto) -> Result<(), DatabaseError>;

    // topics operations
    async fn fetch_encrypted_topic_names(&self) -> Result<HashSet<String>, DatabaseError>;
    async fn create_topic(&self, topic: TopicDto) -> Result<(), DatabaseError>;
    async fn read_topic(&self, hashed_name: &str) -> Result<Option<TopicDto>, DatabaseError>;
    async fn update_topic(&self, topic: &TopicDto) -> Result<(), DatabaseError>;
    async fn delete_topic(&self, hashed_name: &str) -> Result<(), DatabaseError>;

    // secrets operations
    async fn fetch_topic_encrypted_secret_names(
        &self,
        hashed_topic_name: &str,
    ) -> Result<HashSet<String>, DatabaseError>;
    async fn create_secret(&self, secret: SecretDto) -> Result<(), DatabaseError>;
    async fn read_secret(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<Option<SecretDto>, DatabaseError>;
    async fn update_secret(&self, secret: &SecretDto) -> Result<(), DatabaseError>;
    async fn delete_secret(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait DatabaseFactory {
    type Connection: DatabaseConnection + Send + Sync;

    async fn create_connection(&self) -> Result<Self::Connection, DatabaseError>;
    #[cfg(test)]
    async fn create_test_connection(&self) -> Result<Self::Connection, DatabaseError>;
}
