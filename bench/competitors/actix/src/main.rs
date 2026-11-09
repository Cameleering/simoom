//! actix-web 4 with its production defaults: a worker per CPU, HTTP/1.1 and h2c (prior
//! knowledge) on one port, connection limits raised for the idle tests.
use actix_web::{web, App, HttpResponse, HttpServer};

static B64K: [u8; 64 * 1024] = [b'x'; 64 * 1024];
static B1M: [u8; 1024 * 1024] = [b'x'; 1024 * 1024];

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(|| async { HttpResponse::Ok().content_type("text/plain").body("Hello, World!") }))
            .route("/64k", web::get().to(|| async { HttpResponse::Ok().content_type("application/octet-stream").body(&B64K[..]) }))
            .route("/1m", web::get().to(|| async { HttpResponse::Ok().content_type("application/octet-stream").body(&B1M[..]) }))
            .route("/echo", web::post().to(|b: web::Bytes| async move { HttpResponse::Ok().content_type("application/json").body(b) }))
    })
    // idle keep-alive connections are held 120 s, like every other server here (actix's default
    // is 5 s, which closed the idle-test connections)
    .keep_alive(std::time::Duration::from_secs(120))
    .backlog(65_535)
    .max_connections(1_000_000)
    .max_connection_rate(65_536)
    .bind_auto_h2c(("0.0.0.0", port))?
    .run()
    .await
}
