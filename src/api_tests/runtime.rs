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

    let test_result = AssertUnwindSafe(test_fn(client)).catch_unwind().await;

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

// pub async fn use_app<F, Fut>(test_fn: F)
// where
//     F: FnOnce(ClientWithServer) -> Fut,
//     Fut: std::future::Future<Output = ()>,
// {
//     load_env_vars_from_file(TEST_ENV_FILENAME);

//     let client = ClientWithServer::new().await;
//     let db_conn = client.app_state.get_db_conn();

//     let result = AssertUnwindSafe(test_fn(client))
//         .catch_unwind()
//         .await;

//     // Always clean up the test database.
//     db_conn
//         .drop_database()
//         .await
//         .expect("Failed to clear database after test");

//     // Resume the panic if one occurred.
//     if let Err(err) = result {
//         std::panic::resume_unwind(err);
//     }
// }
