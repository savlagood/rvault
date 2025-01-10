use once_cell::sync::Lazy;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::OnceCell;

use crate::config::CONFIG;
use crate::http::server::create_router;

static API: OnceCell<()> = OnceCell::const_new();
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().unwrap());

pub async fn start_api_once() {
    API.get_or_init(|| async {
        let app = create_router();
        let port = CONFIG.server_port;
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(address)
            .await
            .expect("Error listening on the assigned port");

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
