use crate::tests::{database, jwt_utils::extract_token_pair_from_response, routes};
use crate::{
    config::Config,
    http::{jwt_tokens::TokenPair, server::create_router},
    state::AppState,
};
use once_cell::sync::Lazy;
use reqwest::{Client, Response};
use serde_json::Value;
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};

use super::routes::build_url;

pub static CONFIG: Lazy<Config> = Lazy::new(|| Config::setup().expect("Failed to setup config"));
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().expect("Failed to create runtime"));

pub struct ClientWithServer {
    client: Client,
    _server: JoinHandle<()>,
    port: u16,
}

impl ClientWithServer {
    pub async fn new() -> Self {
        let (port, server) = start_server().await;
        let client = Client::new();

        Self {
            client,
            _server: server,
            port,
        }
    }

    pub async fn make_request(&self, path: &str, body: Value) -> Response {
        let url = routes::build_url(path, self.port);
        self.client
            .post(url)
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn make_admin_request(&self, path: &str, body: Value) -> Response {
        let token_pair = self.fetch_admin_token_pair().await;
        let admin_access_token = token_pair.access_token;

        self.make_authorized_request(path, body, &admin_access_token)
            .await
    }

    pub async fn make_authorized_request(&self, path: &str, body: Value, token: &str) -> Response {
        let url = build_url(path, self.port);
        self.client
            .post(url)
            .json(&body)
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn fetch_admin_token_pair(&self) -> TokenPair {
        let request_body = serde_json::json!({
            "token": CONFIG.root_token.clone()
        });

        let response = self
            .make_request(routes::ISSUE_ADMIN_TOKEN_PATH, request_body)
            .await;

        extract_token_pair_from_response(response).await
    }
}

pub async fn start_server() -> (u16, JoinHandle<()>) {
    let app_state = AppState::setup().await.expect("Failed to setup app state");
    let app = create_router(app_state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Error listening on the assigned port");
    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();

    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Failed to start server");
    });

    (port, server)
}

pub fn use_app<F>(test_future: F)
where
    F: std::future::Future,
{
    RUNTIME.block_on(async move {
        database::clear_db_before_test().await;
        test_future.await;
    })
}
