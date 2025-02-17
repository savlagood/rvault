use crate::{secrets::SecretDto, storage::StorageDto, topics::TopicDto};
use anyhow::{Context, Result};
use futures::TryStreamExt;
use mongodb::{bson, Client, Collection, Database};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Debug, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::info;

#[cfg(not(test))]
const DB_NAME: &str = "rvault";
#[cfg(test)]
const DB_NAME: &str = "test_rvault";

const STORAGE_COLLECTION_NAME: &str = "storage";
const TOPICS_COLLECTION_NAME: &str = "topics";
const SECRETS_COLLECTION_NAME: &str = "secrets";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Error during making operation with MongoDB")]
    OperationFailed(#[from] mongodb::error::Error),

    #[error("Failed to serialize/deserialize object into/from bson::doc")]
    RepresentationError(#[from] bson::ser::Error),

    #[error("Document with such name already exists")]
    AlreadyExists,

    #[error("Duplicate")]
    Duplicate,

    #[error("Not found")]
    NotFound,
}

pub struct MongoDb {
    db: Arc<Mutex<Database>>,
}

impl MongoDb {
    pub async fn setup_with_connection_str(connection_str: &str) -> Result<Self> {
        let client = Client::with_uri_str(connection_str)
            .await
            .context("Failed to connect to MongoDB and create client")?;
        let db = client.database(DB_NAME);

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub async fn read_storage(&self) -> Result<Option<StorageDto>, DatabaseError> {
        let collection = self.get_storage_collection().await;

        let filter = bson::doc! {};
        let first_document = collection.find_one(filter).await?;

        info!("The storage was successfully read from the database");

        Ok(first_document)
    }

    pub async fn save_storage(&self, storage: &StorageDto) -> Result<(), DatabaseError> {
        let collection = self.get_storage_collection().await;

        let filter = bson::doc! {};
        let update = bson::to_document(storage).map(|doc| bson::doc! { "$set": doc })?;

        collection.update_one(filter, update).upsert(true).await?;

        info!("The storage was successfully saved to the database");

        Ok(())
    }

    pub async fn fetch_topic_names(&self) -> Result<Vec<String>, DatabaseError> {
        let collection = self.get_topics_collection().await;

        let filter = bson::doc! {};
        let mut cursor = collection.find(filter).await?;

        let mut topics = Vec::new();
        while let Some(topic_document) = cursor.try_next().await? {
            topics.push(topic_document.encrypted_name);
        }

        Ok(topics)
    }

    pub async fn create_topic(&self, topic: TopicDto) -> Result<(), DatabaseError> {
        let collection = self.get_topics_collection().await;

        let filter = bson::doc! { "hashed_name": topic.hashed_name.as_str() };
        if collection.find_one(filter).await?.is_some() {
            return Err(DatabaseError::AlreadyExists);
        }

        collection.insert_one(topic).await?;

        Ok(())
    }

    pub async fn read_topic(&self, hashed_name: &str) -> Result<Option<TopicDto>, DatabaseError> {
        let collection = self.get_topics_collection().await;

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

    pub async fn update_topic(&self, topic: TopicDto) -> Result<(), DatabaseError> {
        let collection = self.get_topics_collection().await;

        let filter = bson::doc! { "hashed_name": topic.hashed_name.as_str() };
        let update = bson::to_document(&topic).map(|doc| bson::doc! { "$set": doc })?;

        let result = collection.update_one(filter, update).await?;

        if result.matched_count == 0 {
            return Err(DatabaseError::NotFound);
        }

        Ok(())
    }

    pub async fn create_secret(&self, secret: SecretDto) -> Result<(), DatabaseError> {
        let collection = self.get_secrets_collection().await;

        let filter = bson::doc! { "hashed_name": secret.hashed_name.as_str() };
        if collection.find_one(filter).await?.is_some() {
            return Err(DatabaseError::AlreadyExists);
        }

        collection.insert_one(secret).await?;

        Ok(())
    }

    async fn get_storage_collection(&self) -> Collection<StorageDto> {
        self.get_collection(STORAGE_COLLECTION_NAME).await
    }

    async fn get_topics_collection(&self) -> Collection<TopicDto> {
        self.get_collection(TOPICS_COLLECTION_NAME).await
    }

    async fn get_secrets_collection(&self) -> Collection<SecretDto> {
        self.get_collection(SECRETS_COLLECTION_NAME).await
    }

    async fn get_collection<T>(&self, collection_name: &str) -> Collection<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync + Unpin,
    {
        let db = self.db.lock().await;
        db.collection::<T>(collection_name)
    }
}
