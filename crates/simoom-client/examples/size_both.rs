//! The `client_size_server` server plus one client request (scripts/size-client.sh, marginal cost of
//! the client in a binary that already links the server).
fn main() {
    let s = simoom::Server::builder()
        .listen("127.0.0.1:0")
        .service(|_: &mut simoom::Request<'_>, r: simoom::Reply<'_>| -> simoom::Outcome { r.body_static(b"hi") })
        .start()
        .expect("start");
    let url = format!("http://{}/", s.local_addr());
    match simoom_client::Client::new().get(&url).send().and_then(|r| r.bytes()) {
        Ok(b) => println!("{} bytes", b.len()),
        Err(e) => eprintln!("{e}"),
    }
}
