use crate::{config::Config, http::server::create_router, state::AppState};
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use tokio::{net::TcpListener, runtime::Runtime, sync::OnceCell};

pub static CONFIG: OnceCell<Config> = OnceCell::const_new();

static API: OnceCell<()> = OnceCell::const_new();
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().unwrap());

pub async fn start_api_once() {
    API.get_or_init(|| async {
        let app_state = AppState::new().expect("Failed to setup app state");

        let config = app_state.get_config();
        CONFIG
            .set(config.clone())
            .expect("CONFIG already initialized");

        let port = config.server_port;
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(address)
            .await
            .expect("Error listening on the assigned port");

        let app = create_router(app_state);
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("Failed to start server");
        });
    })
    .await;
}

pub fn use_app<F>(test: F)
where
    F: std::future::Future,
{
    RUNTIME.block_on(async move {
        start_api_once().await;

        test.await;
    })
}
