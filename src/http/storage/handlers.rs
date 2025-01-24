use crate::state::SharedState;
use axum::{extract::State, routing::post, Router};

pub fn router(app_state: SharedState) -> Router {
    Router::new()
        .route("/init", post(init_storage))
        .with_state(app_state)
}

async fn init_storage(State(state): State<SharedState>) -> String {
    let config = state.get_config();
    format!("Hello, world!\n{}", config.server_port)
}
