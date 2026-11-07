//! may-minihttp (stackful coroutines), set up as in its TechEmpower entry: a worker per CPU.
use may_minihttp::{HttpServer, HttpService, Request, Response};
use std::io::{self, Read};

#[derive(Clone)]
struct Svc;

impl HttpService for Svc {
    fn call(&mut self, req: Request, rsp: &mut Response) -> io::Result<()> {
        if req.method() == "POST" {
            let mut body = Vec::new();
            req.body().read_to_end(&mut body)?;
            rsp.header("Content-Type: application/json");
            rsp.body_vec(body);
        } else {
            rsp.header("Content-Type: text/plain");
            rsp.body("Hello, World!");
        }
        Ok(())
    }
}

fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    may::config().set_workers(n).set_stack_size(0x1000 * 16);
    HttpServer(Svc).start(("0.0.0.0", port)).expect("start").join().expect("join");
}
