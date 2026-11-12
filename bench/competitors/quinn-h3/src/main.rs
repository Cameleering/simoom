//! HTTP/3 with h3 + h3-quinn + quinn (rustls 0.23, aws-lc-rs), following h3's server example:
//! a task per connection and a task per request. GET / answers "Hello, World!", /64k and /1m
//! fixed bodies, on UDP 8443. axum on TCP 8080 answers the harness's readiness probe.
use bytes::Bytes;
use std::sync::Arc;

static B64K: [u8; 64 * 1024] = [b'x'; 64 * 1024];
static B1M: [u8; 1024 * 1024] = [b'x'; 1024 * 1024];

#[tokio::main]
async fn main() {
    // quinn pulls in ring as well as rustls's default aws-lc-rs; pick aws-lc-rs explicitly
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = std::env::var("CERT").unwrap_or_else(|_| "/opt/bench/cert/cert.pem".into());
    let key = std::env::var("KEY").unwrap_or_else(|_| "/opt/bench/cert/key.pem".into());
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert).expect("cert")))
        .collect::<Result<Vec<_>, _>>()
        .expect("cert pem");
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key).expect("key")))
        .expect("key pem")
        .expect("a key");
    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).expect("tls");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic tls");
    let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), "0.0.0.0:8443".parse().unwrap())
        .expect("udp 8443");

    tokio::spawn(async {
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "Hello, World!" }));
        let l = tokio::net::TcpListener::bind("0.0.0.0:8080").await.expect("bind 8080");
        axum::serve(l, app).await.expect("serve");
    });

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let Ok(mut h3c) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else { return };
            while let Ok(Some(resolver)) = h3c.accept().await {
                tokio::spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                    let (ct, body): (&str, Bytes) = match req.uri().path() {
                        "/64k" => ("application/octet-stream", Bytes::from_static(&B64K)),
                        "/1m" => ("application/octet-stream", Bytes::from_static(&B1M)),
                        _ => ("text/plain", Bytes::from_static(b"Hello, World!")),
                    };
                    let resp = http::Response::builder().status(200).header("content-type", ct).body(()).unwrap();
                    if stream.send_response(resp).await.is_ok() && stream.send_data(body).await.is_ok() {
                        let _ = stream.finish().await;
                    }
                });
            }
        });
    }
}
