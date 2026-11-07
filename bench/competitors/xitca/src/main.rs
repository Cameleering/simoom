//! xitca-web with its defaults (a worker per CPU), HTTP/1.1 and h2c on one port.
use xitca_web::{handler::handler_service, route::get, App};

fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    App::new()
        .at("/", get(handler_service(|| async { "Hello, World!" })))
        .serve()
        .backlog(65_535)
        .bind(("0.0.0.0", port))?
        .run()
        .wait()
}
