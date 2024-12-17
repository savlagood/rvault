use axum::{routing::post, Router};

pub fn create_route() -> Router {
    Router::new().route("/test", post(|| async { "Hello, world!" }))
}

/*

*/
