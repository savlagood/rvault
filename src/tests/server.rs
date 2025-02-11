use crate::{http::server::create_router, state::AppState};

use crate::tests::{
    consts::ENV_ROOT_TOKEN,
    models::{jwt_tokens::TokenPair, policies::Policies},
    routes::{self, PathWithMethod, RequestMethod},
    utils,
};
use once_cell::sync::Lazy;
use reqwest::{Client, Response};
use serde_json::Value;
use tokio::{net::TcpListener, runtime::Runtime, task::JoinHandle};

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

    pub async fn make_request(&self, endpoint: &PathWithMethod, body: Value) -> Response {
        let url = routes::build_url(&endpoint.path, self.port);

        let request = match endpoint.method {
            RequestMethod::GET => self.client.get(url),
            RequestMethod::POST => self.client.post(url),
        };

        request
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn make_admin_request(&self, endpoint: &PathWithMethod, body: Value) -> Response {
        let token_pair = self.fetch_admin_token_pair().await;
        let admin_access_token = token_pair.access_token;

        self.make_authorized_request(endpoint, body, &admin_access_token)
            .await
    }

    pub async fn make_user_request(
        &self,
        endpoint: &PathWithMethod,
        policies: Policies,
        body: Value,
    ) -> Response {
        let token_pair = self.fetch_user_token_pair(policies).await;
        let user_access_token = token_pair.access_token;

        self.make_authorized_request(endpoint, body, &user_access_token)
            .await
    }

    pub async fn make_authorized_request(
        &self,
        endpoint: &PathWithMethod,
        body: Value,
        token: &str,
    ) -> Response {
        let url = routes::build_url(&endpoint.path, self.port);

        let request = match endpoint.method {
            RequestMethod::GET => self.client.get(url),
            RequestMethod::POST => self.client.post(url),
        };

        request
            .json(&body)
            .bearer_auth(token)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn fetch_admin_token_pair(&self) -> TokenPair {
        let root_token = utils::get_env_var(ENV_ROOT_TOKEN);
        let request_body = serde_json::json!({
            "token": root_token,
        });

        let response = self
            .make_request(&routes::ISSUE_ADMIN_TOKEN_ENDPOINT, request_body)
            .await;

        TokenPair::from_response(response).await
    }

    pub async fn fetch_user_token_pair(&self, policies: Policies) -> TokenPair {
        let request_body = serde_json::json!(policies);
        let response = self
            .make_admin_request(&routes::ISSUE_USER_TOKEN_ENDPOINT, request_body)
            .await;

        TokenPair::from_response(response).await
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
    dotenv::from_filename(".env.test").expect("Failed to load values from .env.test file");

    RUNTIME.block_on(async move {
        utils::database::clear_test_data_from_db().await;
        test_future.await;
    })
}
