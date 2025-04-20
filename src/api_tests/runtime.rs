use crate::api_tests::client::ClientWithServer;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const TEST_ENV_FILENAME: &str = ".env.test";

pub async fn use_app<F, Fut>(test_fn: F)
where
    F: FnOnce(ClientWithServer) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    load_env_vars_from_file(TEST_ENV_FILENAME);

    let client = ClientWithServer::new().await;
    let db_conn = client.app_state.get_db_conn();
    let cache = client.app_state.get_cache();

    let test_result = AssertUnwindSafe(test_fn(client)).catch_unwind().await;

    cache
        .clear_test_cache()
        .await
        .expect("Failed to clear cache after test");

    db_conn
        .drop_database()
        .await
        .expect("Failed to clear database after test");

    if let Err(err) = test_result {
        std::panic::resume_unwind(err)
    }
}

fn load_env_vars_from_file(filename: &str) {
    dotenv::from_filename(filename).expect("Failed to load variables from .env.test file");
}
