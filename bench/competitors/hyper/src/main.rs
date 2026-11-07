//! hyper 1.x on the multi-threaded tokio runtime, following hyper's server guide: one accept
//! loop, a task per connection, HTTP/1.1 and h2c on one port (hyper-util's auto builder).
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::POST {
        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        return Ok(Response::builder().header("content-type", "application/json").body(Full::new(body)).unwrap());
    }
    Ok(Response::builder().header("content-type", "text/plain").body(Full::new(Bytes::from_static(b"Hello, World!"))).unwrap())
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.expect("bind");
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let _ = Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service_fn(handle)).await;
        });
    }
}
