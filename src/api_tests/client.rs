use crate::api_tests::{
    consts::ENV_ROOT_TOKEN,
    endpoints::{
        build_url, create_secret, create_topic, Endpoint, RequestMethod, ISSUE_ADMIN_TOKEN,
        ISSUE_USER_TOKEN,
    },
    models::{
        auth::{RootToken, TokenPair},
        common::{EncryptionMode, Headers},
        policies::Policies,
        secrets::{SecretCreateRequest, SecretEncryptionKey},
        topics::{TopicCreateRequest, TopicEncryptionKey},
    },
    utils::common::get_env_var,
};
use crate::{config::Config, http::server::create_router, state::AppState};
use reqwest::{Client, Response, StatusCode};
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};

#[cfg(test)]
use pretty_assertions::assert_eq;

pub async fn start_test_server() -> (AppState, (u16, JoinHandle<()>)) {
    let app_state = AppState::setup()
        .await
        .expect("Failed to setup test app state");

    let router = create_router(app_state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Error listening on the assigned port");

    let port = listener
        .local_addr()
        .expect("Failed to get local address")
        .port();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("Failed to start test server");
    });

    (app_state, (port, server))
}

struct RequestBuilder<'a> {
    client: Client,
    endpoint: Endpoint,
    port: u16,
    headers: Option<Headers>,
    body: Option<&'a Value>,
    bearer: Option<&'a str>,
}

impl<'a> RequestBuilder<'a> {
    fn new(client: Client, endpoint: Endpoint, port: u16) -> Self {
        Self {
            client,
            endpoint,
            port,
            headers: None,
            body: None,
            bearer: None,
        }
    }

    fn set_body(&mut self, body: &'a Value) {
        self.body = Some(body);
    }

    fn set_bearer(&mut self, bearer: &'a str) {
        self.bearer = Some(bearer);
    }

    fn set_headers(&mut self, headers: Headers) {
        self.headers = Some(headers);
    }

    async fn send(self) -> Response {
        let url = build_url(&self.endpoint.path, self.port);

        // method
        let request = match self.endpoint.method {
            RequestMethod::Get => self.client.get(url),
            RequestMethod::Post => self.client.post(url),
        };

        // headers
        let request = if let Some(headers) = self.headers {
            request.headers(headers.headers)
        } else {
            request
        };

        // body
        let request = if let Some(body) = self.body {
            request.json(&body)
        } else {
            request
        };

        // bearer
        let request = if let Some(bearer) = self.bearer {
            request.bearer_auth(bearer)
        } else {
            request
        };

        request.send().await.expect("Failed to send request")
    }
}

pub struct ClientWithServer {
    client: Client,
    _server: JoinHandle<()>,
    port: u16,
    pub config: Config,
    pub app_state: AppState,
}

impl ClientWithServer {
    pub async fn new() -> Self {
        let (app_state, (port, server)) = start_test_server().await;
        let client = Client::new();

        Self {
            client,
            _server: server,
            port,
            config: app_state.get_config().clone(),
            app_state,
        }
    }

    pub async fn make_request(&self, endpoint: Endpoint, body: &Value) -> Response {
        let mut request_builder =
            RequestBuilder::new(self.client.clone(), endpoint.clone(), self.port);
        request_builder.set_body(body);

        request_builder.send().await
    }

    pub async fn make_admin_request(&self, endpoint: Endpoint, body: &Value) -> Response {
        let token_pair = self.fetch_admin_token_pair().await;
        let admin_access_token = token_pair.access_token;

        self.make_authorized_request(endpoint, body, &admin_access_token)
            .await
    }

    pub async fn make_admin_request_with_headers(
        &self,
        endpoint: Endpoint,
        body: &Value,
        headers: Headers,
    ) -> Response {
        let token_pair = self.fetch_admin_token_pair().await;
        let admin_access_token = token_pair.access_token;

        self.make_authorized_request_with_headers(endpoint, body, &admin_access_token, headers)
            .await
    }

    pub async fn make_user_request(
        &self,
        endpoint: Endpoint,
        policies: Policies,
        body: &Value,
    ) -> Response {
        let token_pair = self.fetch_user_token_pair(policies).await;
        let user_access_token = token_pair.access_token;

        self.make_authorized_request(endpoint, body, &user_access_token)
            .await
    }

    pub async fn make_authorized_request(
        &self,
        endpoint: Endpoint,
        body: &Value,
        token: &str,
    ) -> Response {
        let mut request_builder =
            RequestBuilder::new(self.client.clone(), endpoint.clone(), self.port);
        request_builder.set_body(body);
        request_builder.set_bearer(token);

        request_builder.send().await
    }

    pub async fn make_authorized_request_with_headers(
        &self,
        endpoint: Endpoint,
        body: &Value,
        token: &str,
        headers: Headers,
    ) -> Response {
        let mut request_builder =
            RequestBuilder::new(self.client.clone(), endpoint.clone(), self.port);
        request_builder.set_headers(headers);
        request_builder.set_body(body);
        request_builder.set_bearer(token);

        request_builder.send().await
    }

    pub async fn fetch_admin_token_pair(&self) -> TokenPair {
        let root_token = get_env_var(ENV_ROOT_TOKEN);
        let request_body = RootToken::new(root_token).into_value();

        let response = self
            .make_request(ISSUE_ADMIN_TOKEN.clone(), &request_body)
            .await;

        TokenPair::from_response(response).await
    }

    pub async fn fetch_user_token_pair(&self, policies: Policies) -> TokenPair {
        let request_body = policies.into_value();
        let response = self
            .make_admin_request(ISSUE_USER_TOKEN.clone(), &request_body)
            .await;

        TokenPair::from_response(response).await
    }

    pub async fn create_topic(&self, topic_name: &str) -> String {
        let request_body = TopicCreateRequest::new(EncryptionMode::Generate).into_value();
        let response = self
            .make_admin_request(create_topic(topic_name), &request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        TopicEncryptionKey::from_response_to_string(response).await
    }

    pub async fn create_topic_with_key(&self, topic_name: &str, key: String) -> String {
        let mut request = TopicCreateRequest::new(EncryptionMode::Provided);
        request.set_key(key);

        let request_body = request.into_value();

        let response = self
            .make_admin_request(create_topic(topic_name), &request_body)
            .await;

        TopicEncryptionKey::from_response_to_string(response).await
    }

    pub async fn create_topic_encryption_none(&self, topic_name: &str) {
        let request_body = TopicCreateRequest::new(EncryptionMode::None).into_value();
        let response = self
            .make_admin_request(create_topic(topic_name), &request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    pub async fn create_secret(
        &self,
        topic_name: &str,
        secret_name: &str,
        value: String,
    ) -> String {
        let request_body = SecretCreateRequest::new(EncryptionMode::Generate, value).into_value();
        let response = self
            .make_admin_request(create_secret(topic_name, secret_name), &request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        SecretEncryptionKey::from_response_to_string(response).await
    }

    pub async fn create_secret_in_encrypted_topic(
        &self,
        topic_name: &str,
        secret_name: &str,
        value: String,
        topic_key: &str,
    ) -> String {
        let request_body = SecretCreateRequest::new(EncryptionMode::Generate, value).into_value();

        let mut headers = Headers::new();
        headers.add_topic_key_header(topic_key);

        let response = self
            .make_admin_request_with_headers(
                create_secret(topic_name, secret_name),
                &request_body,
                headers,
            )
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
        SecretEncryptionKey::from_response_to_string(response).await
    }

    pub async fn create_secret_encryption_none(
        &self,
        topic_name: &str,
        secret_name: &str,
        value: String,
    ) {
        let request_body = SecretCreateRequest::new(EncryptionMode::None, value).into_value();
        let response = self
            .make_admin_request(create_secret(topic_name, secret_name), &request_body)
            .await;

        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
