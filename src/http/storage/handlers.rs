use crate::state::AppState;
use axum::{extract::State, routing::post, Router};

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/init", post(init_storage))
        .with_state(app_state)
}

async fn init_storage(State(state): State<AppState>) -> String {
    let config = state.get_config();
    format!("Hello, world!\n{}", config.server_port)
}
