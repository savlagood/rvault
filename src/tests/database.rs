use crate::database::MongoDb;
use crate::tests::server::CONFIG;

pub async fn clear_db_before_test() {
    let db = setup_db_connection().await;
    db.drop_all_collections()
        .await
        .expect("Failed to drop all collections"); // db.drop_storage_collection().await.expect("Failed to drop storage collection");
}

async fn setup_db_connection() -> MongoDb {
    MongoDb::setup_with_connection_str(&CONFIG.db_connection_string)
        .await
        .expect("Failed to setup test database")
}
