//! axum 0.8 on tokio, as in axum's examples: `axum::serve` with TCP_NODELAY on accepted sockets;
//! HTTP/1.1 and h2c on one port.
use axum::body::Bytes;
use axum::http::header::CONTENT_TYPE;
use axum::routing::{get, post};
use axum::serve::ListenerExt;
use axum::Router;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let app = Router::new()
        .route("/", get(|| async { ([(CONTENT_TYPE, "text/plain")], "Hello, World!") }))
        .route("/echo", post(|body: Bytes| async move { ([(CONTENT_TYPE, "application/json")], body) }));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("bind").tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    axum::serve(listener, app).await.expect("serve");
}
