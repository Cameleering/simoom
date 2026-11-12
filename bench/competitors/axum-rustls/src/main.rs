//! axum 0.8 on tokio with TLS from axum-server (rustls 0.23, aws-lc-rs): the same routes as the
//! axum competitor, plain HTTP/1.1 and h2c on 8080 and TLS 1.3 on 8443 (ALPN h2 and http/1.1).
use axum::body::Bytes;
use axum::http::header::CONTENT_TYPE;
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;

static B64K: [u8; 64 * 1024] = [b'x'; 64 * 1024];
static B1M: [u8; 1024 * 1024] = [b'x'; 1024 * 1024];

fn app() -> Router {
    Router::new()
        .route("/", get(|| async { ([(CONTENT_TYPE, "text/plain")], "Hello, World!") }))
        .route("/64k", get(|| async { ([(CONTENT_TYPE, "application/octet-stream")], Bytes::from_static(&B64K)) }))
        .route("/1m", get(|| async { ([(CONTENT_TYPE, "application/octet-stream")], Bytes::from_static(&B1M)) }))
        .route("/echo", post(|body: Bytes| async move { ([(CONTENT_TYPE, "application/json")], body) }))
}

#[tokio::main]
async fn main() {
    let cert = std::env::var("CERT").unwrap_or_else(|_| "/opt/bench/cert/cert.pem".into());
    let key = std::env::var("KEY").unwrap_or_else(|_| "/opt/bench/cert/key.pem".into());
    let tls = RustlsConfig::from_pem_file(cert, key).await.expect("certificate");
    let plain = axum_server::bind("0.0.0.0:8080".parse().unwrap()).serve(app().into_make_service());
    let secure = axum_server::bind_rustls("0.0.0.0:8443".parse().unwrap(), tls).serve(app().into_make_service());
    let (a, b) = tokio::join!(plain, secure);
    a.expect("plain");
    b.expect("tls");
}
