//! Heap allocations per request through the client (HTTP/1.1 keep-alive, h2c with `--h2`):
//! `client_allocs <url> [--h2]`. Uses simoom-sys's counting allocator.

#[global_allocator]
static A: simoom_sys::alloc::Counting = simoom_sys::alloc::Counting;

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:8080/".into());
    let h2 = std::env::args().any(|a| a == "--h2");
    let c = simoom_client::Client::builder().version(if h2 { simoom_client::HttpVersion::Http2 } else { simoom_client::HttpVersion::Auto }).build();
    for _ in 0..100 {
        c.get(&url).send().unwrap().bytes().unwrap();
    }
    let n = 10_000;
    let a0 = simoom_sys::alloc::allocation_calls();
    for _ in 0..n {
        c.get(&url).send().unwrap().bytes().unwrap();
    }
    let a1 = simoom_sys::alloc::allocation_calls();
    println!("allocations per request: {:.1}", (a1 - a0) as f64 / n as f64);
}
