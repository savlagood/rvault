use crate::storage::StorageDto;
use anyhow::{Context, Result};
use mongodb::{bson, Client, Collection, Database};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::info;

#[cfg(not(test))]
const DB_NAME: &str = "rvault";
#[cfg(test)]
const DB_NAME: &str = "test_rvault";

const STORAGE_COLLECTION_NAME: &str = "storage";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Error during making operation with MongoDB")]
    OperationFailed(#[from] mongodb::error::Error),

    #[error("Failed to serialize/deserialize object into/from bson::doc")]
    RepresentationError(#[from] bson::ser::Error),
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

    async fn get_storage_collection(&self) -> Collection<StorageDto> {
        let db = self.db.lock().await;
        db.collection::<StorageDto>(STORAGE_COLLECTION_NAME)
    }
}
