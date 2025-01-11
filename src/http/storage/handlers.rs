use axum::{routing::post, Router};

pub fn router() -> Router {
    Router::new().route("/init", post(init_storage))
}

async fn init_storage() -> String {
    "hello, world".to_string()
}
