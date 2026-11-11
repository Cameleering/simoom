//! A simoom server alone (HTTP/1.1, HTTP/2, TLS, HTTP/3, WebSocket): the baseline for
//! `size_both`, to measure what the client adds to a binary that already has the server.
fn main() {
    let s = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .service(|_: &mut simoom::Request<'_>, r: simoom::Reply<'_>| -> simoom::Outcome { r.body_static(b"hi") })
        .start()
        .expect("start");
    println!("{}", s.local_addr());
}
