//! ntex 2 on tokio with its defaults (a worker per CPU).
use ntex::web;

#[ntex::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    web::HttpServer::new(|| {
        web::App::new()
            .route("/", web::get().to(|| async { web::HttpResponse::Ok().content_type("text/plain").body("Hello, World!") }))
            .route("/echo", web::post().to(|b: ntex::util::Bytes| async move { web::HttpResponse::Ok().content_type("application/json").body(b) }))
    })
    .backlog(65_535)
    .maxconn(1_000_000)
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
