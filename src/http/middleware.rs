use crate::metrics::EndpointMetrics;
use axum::{extract::Request, middleware::Next, response::Response};
use lazy_static::lazy_static;
use regex::Regex;
use std::time::Instant;

const CURRENT_VERSION_PATH: &str =
    "/api/topics/{topic_name}/secrets/{secret_name}/versions/current";
const VERSIONS_PATH: &str = "/api/topics/{topic_name}/secrets/{secret_name}/versions";
const SECRET_PATH: &str = "/api/topics/{topic_name}/secrets/{secret_name}";
const SECRETS_PATH: &str = "/api/topics/{topic_name}/secrets";
const TOPIC_PATH: &str = "/api/topics/{topic_name}";

lazy_static! {
    static ref TOPIC_WITH_NAME: Regex = Regex::new(r"^/api/topics/[^/]+$").unwrap();
    static ref SECRETS_IN_TOPIC: Regex = Regex::new(r"^/api/topics/[^/]+/secrets$").unwrap();
    static ref SECRET_WITH_NAME: Regex = Regex::new(r"^/api/topics/[^/]+/secrets/[^/]+$").unwrap();
    static ref SECRET_VERSIONS: Regex =
        Regex::new(r"^/api/topics/[^/]+/secrets/[^/]+/versions$").unwrap();
    static ref SECRET_CURRENT_VERSION: Regex =
        Regex::new(r"^/api/topics/[^/]+/secrets/[^/]+/versions/current$").unwrap();
}

pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();

    let method = request.method().to_string();

    let origin_path = request.uri().path().to_string();
    let path = path_to_common_name(&origin_path);

    let metrics = EndpointMetrics::new(&method, path);

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status().as_u16();

    metrics.observe_duration(duration);
    metrics.increment_requests(status);

    response
}

fn path_to_common_name(path: &str) -> &str {
    if SECRET_CURRENT_VERSION.is_match(path) {
        CURRENT_VERSION_PATH
    } else if SECRET_VERSIONS.is_match(path) {
        VERSIONS_PATH
    } else if SECRET_WITH_NAME.is_match(path) {
        SECRET_PATH
    } else if SECRETS_IN_TOPIC.is_match(path) {
        SECRETS_PATH
    } else if TOPIC_WITH_NAME.is_match(path) {
        TOPIC_PATH
    } else {
        path
    }
}
