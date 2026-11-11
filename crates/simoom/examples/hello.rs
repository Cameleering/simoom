//! The smallest server: one fixed reply. Used by `scripts/size.sh` to measure the size each
//! feature set adds: optional features that only cost something when used (compression,
//! permessage-deflate, the server helpers, authentication) are exercised here when enabled, so their code is
//! linked and counted; without them this is the same server as before.
//!
//! ```text
//! cargo run --release -p simoom --example hello -- 127.0.0.1:8080
//! ```

#![forbid(unsafe_code)]

use simoom::{Outcome, Reply, Request, Server};

#[allow(unused_mut)]
fn hello(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let mut reply = reply;
    #[cfg(feature = "multipart")]
    if req.path() == b"/upload" {
        let n = req.multipart(&simoom::multipart::MultipartLimits::default()).map(|p| p.len()).unwrap_or(0);
        return reply.body(n.to_string());
    }
    // with Brotli or zstd, decode request bodies too, so their decoders are counted
    #[cfg(any(feature = "brotli", feature = "zstd"))]
    if req.path() == b"/decode" {
        let n = req.decoded_body(1 << 20).map(|b| b.len()).unwrap_or(0);
        return reply.body(n.to_string());
    }
    #[cfg(feature = "cookies")]
    {
        let seen = req.cookie("seen").is_some();
        reply = reply.cookie(&simoom::cookie::SetCookie::new("seen", if seen { "2" } else { "1" }).http_only(true));
    }
    #[cfg(feature = "conditional")]
    if req.path() == b"/doc" {
        return reply.content(req, b"Hello, World!", "text/plain", &simoom::conditional::Validators { etag: Some("\"1\""), last_modified: None });
    }
    let _ = &req;
    reply.header("content-type", "text/plain").body_static(b"Hello, World!")
}

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".into());
    let builder = Server::builder();
    // with the `compression` feature the size rows measure a server that compresses
    #[cfg(feature = "compression")]
    let builder = builder.compression(simoom::Compression::new());
    #[cfg(feature = "ws-deflate")]
    let builder = builder.websocket_deflate(simoom::WsDeflate::default());
    let builder = builder.listen(addr.as_str());
    // with `auth`, every request needs Digest, Basic or Bearer credentials
    #[cfg(feature = "auth")]
    let svc = {
        use simoom::auth::{Auth, Basic, Credential, Digest};
        let digest = Digest::new("hello", |u: &str, _| (u == "ann").then(|| Credential::Password("pw".into())));
        Auth::new().digest(digest).basic(Basic::new("hello", |u: &str| (u == "ann").then(|| "pw".into()))).bearer("hello", |t: &str| (t == "t").then(|| "svc".into())).wrap(hello)
    };
    #[cfg(not(feature = "auth"))]
    let svc = hello;
    #[cfg(feature = "cors")]
    let server = builder.service(simoom::cors::Cors::new().allow_any_origin().wrap(svc)).start().expect("start");
    #[cfg(not(feature = "cors"))]
    let server = builder.service(svc).start().expect("start");
    eprintln!("hello: listening on {}", server.local_addr());
    loop {
        std::thread::park();
    }
}
