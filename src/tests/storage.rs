use crate::tests::{
    consts::{THRESHOLD, TOTAL_KEYS},
    models::shared_keys::SharedKeys,
    routes,
    server::ClientWithServer,
};
use reqwest::StatusCode;

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn init_and_get_shared_keys(client: &ClientWithServer) -> SharedKeys {
    let shared_keys_settings_request = serde_json::json!({
        "threshold": THRESHOLD,
        "total_keys": TOTAL_KEYS,
    });

    let response = client
        .make_admin_request(&routes::INIT_STORAGE_ENDPOINT, shared_keys_settings_request)
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let shared_keys = response
        .json::<SharedKeys>()
        .await
        .expect("Failed to serialize into Value");
    shared_keys
}

pub async fn unseal(client: &ClientWithServer, shared_keys: &SharedKeys) {
    let request_body = serde_json::json!(shared_keys);
    let response = client
        .make_admin_request(&routes::UNSEAL_STORAGE_ENDPOINT, request_body)
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}

pub async fn from_uninitialized_to_sealed(client: &ClientWithServer) {
    let _shared_keys = init_and_get_shared_keys(client).await;
}

pub async fn from_uninitialized_to_unsealed(client: &ClientWithServer) {
    let shared_keys = init_and_get_shared_keys(client).await;
    unseal(client, &shared_keys).await;
}
