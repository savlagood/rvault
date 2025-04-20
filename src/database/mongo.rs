use crate::{
    database::{DatabaseConnection, DatabaseError, DatabaseFactory},
    secrets::SecretDto,
    storage::StorageDto,
    topics::TopicDto,
    utils::common::get_env_var_required,
};
use anyhow::Result;
use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson, Client, Collection, Database};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use tracing::info;

// collections
const STORAGE_COLLECTION_NAME: &str = "storage";
const TOPICS_COLLECTION_NAME: &str = "topics";
const SECRETS_COLLECTION_NAME: &str = "secrets";

// env
const ENV_MONGO_URI: &str = "RVAULT_MONGO_URI";
const ENV_DB_NAME: &str = "RVAULT_MONGO_DB_NAME";

#[cfg(test)]
use once_cell::sync::Lazy;
#[cfg(test)]
use tokio::sync::Mutex;
#[cfg(test)]
static TEST_DB_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

impl From<anyhow::Error> for DatabaseError {
    fn from(error: anyhow::Error) -> Self {
        DatabaseError::FactorySetup(error.to_string())
    }
}

impl From<mongodb::error::Error> for DatabaseError {
    fn from(error: mongodb::error::Error) -> Self {
        DatabaseError::Operation(error.to_string())
    }
}

impl From<mongodb::bson::ser::Error> for DatabaseError {
    fn from(error: mongodb::bson::ser::Error) -> Self {
        DatabaseError::Representation(error.to_string())
    }
}

pub struct MongoFactory {
    uri: String,
    db_name: String,
}

impl MongoFactory {
    pub fn new() -> Result<Self, DatabaseError> {
        let uri = get_env_var_required(ENV_MONGO_URI)?;
        let db_name = get_env_var_required(ENV_DB_NAME)?;

        let factory = Self { uri, db_name };
        Ok(factory)
    }
}

#[async_trait]
impl DatabaseFactory for MongoFactory {
    type Connection = MongoConnection;

    async fn create_connection(&self) -> Result<Self::Connection, DatabaseError> {
        let connection = MongoConnection::new(self.uri.clone(), &self.db_name).await?;
        Ok(connection)
    }

    #[cfg(test)]
    async fn create_test_connection(&self) -> Result<Self::Connection, DatabaseError> {
        let _lock = TEST_DB_MUTEX.lock().await;

        let test_db_name = format!("test_rvault_{}", uuid::Uuid::new_v4().to_string());
        std::env::set_var(ENV_DB_NAME, test_db_name);

        let factory = Self::new()?;
        factory.create_connection().await
    }
}

pub struct MongoConnection {
    db: Database,
}

impl MongoConnection {
    pub async fn new(uri: String, db_name: &str) -> Result<Self, DatabaseError> {
        let client = Client::with_uri_str(uri)
            .await
            .map_err(|e| DatabaseError::Connection(e.to_string()))?;
        let db = client.database(db_name);

        Ok(Self { db })
    }

    fn get_storage_collection(&self) -> Collection<StorageDto> {
        self.get_collection(STORAGE_COLLECTION_NAME)
    }

    fn get_topics_collection(&self) -> Collection<TopicDto> {
        self.get_collection(TOPICS_COLLECTION_NAME)
    }

    fn get_secrets_collection(&self) -> Collection<SecretDto> {
        self.get_collection(SECRETS_COLLECTION_NAME)
    }

    fn get_collection<T>(&self, collection_name: &str) -> Collection<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync + Unpin,
    {
        self.db.collection::<T>(collection_name)
    }
}

#[async_trait]
impl DatabaseConnection for MongoConnection {
    // needed for testing
    #[cfg(test)]
    async fn drop_database(&self) -> Result<(), DatabaseError> {
        self.db.drop().await?;
        Ok(())
    }

    // storage operations
    async fn read_storage(&self) -> Result<Option<StorageDto>, DatabaseError> {
        let collection = self.get_storage_collection();

        let filter = bson::doc! {};
        let first_document = collection.find_one(filter).await?;

        info!("Storage was successfully read from database");

        Ok(first_document)
    }

    async fn save_storage(&self, storage: &StorageDto) -> Result<(), DatabaseError> {
        let collection = self.get_storage_collection();

        let filter = bson::doc! {};
        let update = bson::to_document(storage).map(|doc| bson::doc! { "$set": doc })?;

        collection.update_one(filter, update).upsert(true).await?;

        info!("Storage was successfully saved to database");

        Ok(())
    }

    // topics operations
    async fn fetch_encrypted_topic_names(&self) -> Result<HashSet<String>, DatabaseError> {
        let collections = self.get_topics_collection();

        let filter = bson::doc! {};
        let mut cursor = collections.find(filter).await?;

        let mut encrypted_topic_names = HashSet::new();
        while let Some(topic_doc) = cursor.try_next().await? {
            encrypted_topic_names.insert(topic_doc.encrypted_name);
        }

        Ok(encrypted_topic_names)
    }

    async fn create_topic(&self, topic: TopicDto) -> Result<(), DatabaseError> {
        let collection = self.get_topics_collection();

        let filter = bson::doc! { "hashed_name": topic.hashed_name.as_str() };
        if collection.find_one(filter).await?.is_some() {
            return Err(DatabaseError::AlreadyExists);
        }

        collection.insert_one(topic).await?;

        Ok(())
    }

    async fn read_topic(&self, hashed_name: &str) -> Result<Option<TopicDto>, DatabaseError> {
        let collection = self.get_topics_collection();

        let filter = bson::doc! { "hashed_name": hashed_name };
        let mut cursor = collection.find(filter).await?;

        let first_doc = match cursor.try_next().await? {
            Some(doc) => doc,
            None => return Ok(None),
        };

        if cursor.try_next().await?.is_some() {
            return Err(DatabaseError::Duplicate);
        }

        Ok(Some(first_doc))
    }

    async fn update_topic(&self, topic: &TopicDto) -> Result<(), DatabaseError> {
        let collection = self.get_topics_collection();

        let filter = bson::doc! { "hashed_name": topic.hashed_name.as_str() };
        let update = bson::to_document(topic).map(|doc| bson::doc! { "$set": doc })?;

        let result = collection.update_one(filter, update).await?;

        if result.matched_count == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    async fn delete_topic(&self, hashed_name: &str) -> Result<(), DatabaseError> {
        let collection = self.get_topics_collection();

        let filter = bson::doc! { "hashed_name": hashed_name };

        let result = collection.delete_one(filter).await?;
        if result.deleted_count == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    // secrets operations
    async fn fetch_topic_encrypted_secret_names(
        &self,
        hashed_topic_name: &str,
    ) -> Result<HashSet<String>, DatabaseError> {
        let collection = self.get_secrets_collection();

        let filter = bson::doc! { "hashed_topic_name": hashed_topic_name };
        let mut cursor = collection.find(filter).await?;

        let mut encrypted_secret_names = HashSet::new();
        while let Some(secret_doc) = cursor.try_next().await? {
            encrypted_secret_names.insert(secret_doc.encrypted_name);
        }

        Ok(encrypted_secret_names)
    }

    async fn create_secret(&self, secret: SecretDto) -> Result<(), DatabaseError> {
        let collection = self.get_secrets_collection();

        let filter = bson::doc! {
            "hashed_name": secret.hashed_name.as_str(),
            "hashed_topic_name": secret.hashed_topic_name.as_str(),
        };
        if collection.find_one(filter).await?.is_some() {
            return Err(DatabaseError::AlreadyExists);
        }

        collection.insert_one(secret).await?;

        Ok(())
    }

    async fn read_secret(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<Option<SecretDto>, DatabaseError> {
        let collection = self.get_secrets_collection();

        let filter = bson::doc! {
            "hashed_name": hashed_name,
            "hashed_topic_name": hashed_topic_name,
        };
        let mut cursor = collection.find(filter).await?;

        let first_doc = match cursor.try_next().await? {
            Some(doc) => doc,
            None => return Ok(None),
        };

        if cursor.try_next().await?.is_some() {
            return Err(DatabaseError::Duplicate);
        }

        Ok(Some(first_doc))
    }

    async fn update_secret(&self, secret: &SecretDto) -> Result<(), DatabaseError> {
        let collection = self.get_secrets_collection();

        let filter = bson::doc! {
            "hashed_name": secret.hashed_name.as_str(),
            "hashed_topic_name": secret.hashed_topic_name.as_str(),
        };
        let update = bson::to_document(secret).map(|doc| bson::doc! { "$set": doc })?;

        let result = collection.update_one(filter, update).await?;
        if result.matched_count == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    async fn delete_secret(
        &self,
        hashed_topic_name: &str,
        hashed_name: &str,
    ) -> Result<(), DatabaseError> {
        let collection = self.get_secrets_collection();

        let filter = bson::doc! {
            "hashed_name": hashed_name,
            "hashed_topic_name": hashed_topic_name,
        };

        let result = collection.delete_one(filter).await?;
        if result.deleted_count == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }
}
