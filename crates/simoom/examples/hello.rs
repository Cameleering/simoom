//! The smallest server: one fixed reply. Used by `scripts/size.sh` to measure the size each
//! feature set adds.
//!
//! ```text
//! cargo run --release -p simoom --example hello -- 127.0.0.1:8080
//! ```

#![forbid(unsafe_code)]

use simoom::{Outcome, Reply, Request, Server};

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8080".into());
    let server = Server::builder()
        .listen(addr.as_str())
        .service(|_: &mut Request<'_>, reply: Reply<'_>| -> Outcome { reply.header("content-type", "text/plain").body_static(b"Hello, World!") })
        .start()
        .expect("start");
    eprintln!("hello: listening on {}", server.local_addr());
    loop {
        std::thread::park();
    }
}
