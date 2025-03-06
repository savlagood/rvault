use crate::api_tests::{
    client::ClientWithServer,
    endpoints::{INIT_STORAGE, SEAL_STORAGE, UNSEAL_STORAGE},
    models::shared_keys::{SharedKeys, SharedKeysSettings},
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn from_uninitialized_to_sealed(client: &ClientWithServer) {
    let _shared_keys = init(client).await;
}

pub async fn from_uninitialized_to_unsealed(client: &ClientWithServer) {
    let shared_keys = init(client).await;
    unseal(client, shared_keys).await;
}

pub async fn init(client: &ClientWithServer) -> SharedKeys {
    let shared_keys_settings = SharedKeysSettings::default();
    let request_body = shared_keys_settings.into_value();

    let response = client
        .make_admin_request(INIT_STORAGE.clone(), &request_body)
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let shared_keys = response
        .json::<SharedKeys>()
        .await
        .expect("Failed to deserialize shared keys from value");
    shared_keys
}

pub async fn unseal(client: &ClientWithServer, shared_keys: SharedKeys) {
    let request_body = shared_keys.into_value();
    let response = client
        .make_admin_request(UNSEAL_STORAGE.clone(), &request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

pub async fn seal(client: &ClientWithServer) {
    let request_body = serde_json::json!({});
    let response = client
        .make_admin_request(SEAL_STORAGE.clone(), &request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}
