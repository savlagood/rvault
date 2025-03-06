use crate::{
    config::Config,
    database::{mongo::MongoFactory, DatabaseError, DatabaseFactory, DatabaseType, DbConn},
};

#[cfg(not(test))]
pub async fn build_db_connection(config: &Config) -> Result<DbConn, DatabaseError> {
    let db_type = config.db_type.trim().to_lowercase();
    let factory = get_db_factory(&db_type)?;

    factory
        .create_connection()
        .await
        .map(|conn| Box::new(conn) as DbConn)
}

#[cfg(test)]
pub async fn build_test_db_connection(config: &Config) -> Result<DbConn, DatabaseError> {
    let db_type = config.db_type.trim().to_lowercase();
    let factory = get_db_factory(&db_type)?;

    factory
        .create_test_connection()
        .await
        .map(|conn| Box::new(conn) as DbConn)
}

fn get_db_factory(db_type: &str) -> Result<impl DatabaseFactory, DatabaseError> {
    match DatabaseType::from_str(db_type)? {
        DatabaseType::Mongo => {
            MongoFactory::new().map_err(|err| DatabaseError::Connection(err.to_string()))
        }
    }
}
