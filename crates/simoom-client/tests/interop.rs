//! Interop with real servers on loopback, run when `SIMOOM_INTEROP=1`:
//! - Python's `http.server` (any OS with `python3` or `python` on PATH);
//! - nginx (Linux, `nginx` on PATH): HTTP/1.1, keep-alive, TLS with ALPN h2 and http/1.1,
//!   large files, uploads, chunked responses.
//!
//! `SIMOOM_INTEROP=1 cargo test -p simoom-client --test interop -- --nocapture`

mod common;

use simoom_client::{Client, Version};
#[cfg(unix)]
use simoom_client::{Body, HttpVersion};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn enabled() -> bool {
    std::env::var("SIMOOM_INTEROP").is_ok_and(|v| v == "1")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("simoom-client-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_port(port: u16) {
    let end = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < end, "server on {port} did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn write_files(dir: &Path) -> Vec<u8> {
    std::fs::write(dir.join("hello.txt"), b"hello from disk\n").unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    big
}

#[test]
fn python_http_server() {
    if !enabled() {
        eprintln!("skipped: set SIMOOM_INTEROP=1");
        return;
    }
    let dir = tmpdir("py");
    let big = write_files(&dir);
    let port = free_port();
    let py = ["python3", "python"].into_iter().find(|p| Command::new(p).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())).expect("python on PATH");
    let child = Command::new(py)
        .args(["-m", "http.server", &port.to_string(), "--bind", "127.0.0.1", "--directory"])
        .arg(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _p = Proc(child);
    wait_port(port);
    let c = Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let r = c.get(&format!("{base}/hello.txt")).send().unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.version(), Version::Http10, "http.server speaks HTTP/1.0");
    assert_eq!(r.text().unwrap(), "hello from disk\n");
    let mut body = Vec::new();
    c.get(&format!("{base}/big.bin")).send().unwrap().into_body().read_to_end(&mut body).unwrap();
    assert!(body == big, "3 MB file intact");
    let r = c.head(&format!("{base}/big.bin")).send().unwrap();
    assert_eq!(r.content_length(), Some(3_000_000));
    assert!(r.bytes().unwrap().is_empty());
    let e = c.get(&format!("{base}/missing")).ok_status(&[(200, 299)]).send().unwrap_err();
    assert_eq!(e.status().unwrap().status, 404);
    let listing = c.get(&format!("{base}/")).send().unwrap().text().unwrap();
    assert!(listing.contains("big.bin"));
    // redirect from a directory without a trailing slash
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub").join("index.html"), b"<p>sub</p>").unwrap();
    let r = Client::builder().follow_redirects(true).build().get(&format!("{base}/sub")).send().unwrap();
    assert_eq!(r.url().path, "/sub/");
    assert_eq!(r.text().unwrap(), "<p>sub</p>");
    eprintln!("python http.server: ok");
}

#[cfg(unix)]
#[test]
fn nginx() {
    if !enabled() {
        eprintln!("skipped: set SIMOOM_INTEROP=1");
        return;
    }
    if Command::new("nginx").arg("-v").stderr(Stdio::null()).status().is_err() {
        eprintln!("skipped: nginx not on PATH");
        return;
    }
    let dir = tmpdir("nginx");
    let www = dir.join("www");
    std::fs::create_dir_all(&www).unwrap();
    let big = write_files(&www);
    for d in ["logs", "tmp"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let cert = common::cert();
    std::fs::write(dir.join("cert.pem"), &cert.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &cert.key_pem).unwrap();
    let (p1, p2) = (free_port(), free_port());
    let conf = format!(
        r#"
worker_processes 1;
daemon off;
pid {d}/nginx.pid;
error_log {d}/logs/error.log warn;
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_body_temp_path {d}/tmp/body;
    proxy_temp_path {d}/tmp/proxy;
    fastcgi_temp_path {d}/tmp/fcgi;
    uwsgi_temp_path {d}/tmp/uwsgi;
    scgi_temp_path {d}/tmp/scgi;
    keepalive_requests 1000;
    server {{
        listen 127.0.0.1:{p1};
        listen 127.0.0.1:{p2} ssl http2;
        ssl_certificate {d}/cert.pem;
        ssl_certificate_key {d}/key.pem;
        root {d}/www;
        client_max_body_size 20m;
        location /upload {{ client_body_buffer_size 1m; return 200 "len=$content_length\n"; }}
        location /chunked {{ chunked_transfer_encoding on; gzip off; return 200 "chunk\n"; }}
        location /redir {{ return 301 /hello.txt; }}
        location /trailers {{ add_trailer X-Done yes; return 200 "body"; }}
    }}
}}
"#,
        d = dir.display()
    );
    std::fs::write(dir.join("nginx.conf"), conf).unwrap();
    let child = Command::new("nginx").arg("-p").arg(&dir).arg("-c").arg(dir.join("nginx.conf")).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let _p = Proc(child);
    wait_port(p1);
    wait_port(p2);
    let c = common::client().build();
    let base = format!("http://127.0.0.1:{p1}");
    // HTTP/1.1 keep-alive: one connection for many requests
    for _ in 0..50 {
        assert_eq!(c.get(&format!("{base}/hello.txt")).send().unwrap().text().unwrap(), "hello from disk\n");
    }
    assert_eq!(c.pool_stats().http1, 1);
    let mut body = Vec::new();
    c.get(&format!("{base}/big.bin")).send().unwrap().into_body().read_to_end(&mut body).unwrap();
    assert!(body == big);
    // uploads, sized and chunked; the connection stays usable
    let r = c.post(&format!("{base}/upload")).body(vec![1u8; 5_000_000]).send().unwrap();
    assert_eq!(r.text().unwrap(), "len=5000000\n");
    let r = c.post(&format!("{base}/upload")).body(Body::reader(std::io::repeat(2).take(1_000_000))).send().unwrap();
    assert_eq!(r.status(), 200);
    let _ = r.bytes();
    let r = c.post(&format!("{base}/upload")).expect_continue(true).body(vec![1u8; 100_000]).send().unwrap();
    assert_eq!(r.text().unwrap(), "len=100000\n");
    let r = Client::builder().follow_redirects(true).build().get(&format!("{base}/redir")).send().unwrap();
    assert_eq!(r.text().unwrap(), "hello from disk\n");
    assert_eq!(c.get(&format!("{base}/missing")).send().unwrap().status(), 404);
    // TLS: ALPN h2, then http/1.1
    let sbase = format!("https://localhost:{p2}");
    let r = c.get(&format!("{sbase}/hello.txt")).send().unwrap();
    assert_eq!(r.version(), Version::Http2);
    assert_eq!(r.text().unwrap(), "hello from disk\n");
    let mut body = Vec::new();
    c.get(&format!("{sbase}/big.bin")).send().unwrap().into_body().read_to_end(&mut body).unwrap();
    assert!(body == big, "3 MB over h2");
    let r = c.post(&format!("{sbase}/upload")).body(vec![1u8; 3_000_000]).send().unwrap();
    assert_eq!(r.text().unwrap(), "len=3000000\n");
    let ts: Vec<_> = (0..16)
        .map(|_| {
            let (c, u) = (c.clone(), format!("{sbase}/hello.txt"));
            std::thread::spawn(move || c.get(&u).send().unwrap().text().unwrap())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), "hello from disk\n");
    }
    assert_eq!(c.pool_stats().multiplexed, 1);
    let r = c.get(&format!("{sbase}/hello.txt")).version(HttpVersion::Http1).send().unwrap();
    assert_eq!(r.version(), Version::Http11);
    assert_eq!(r.text().unwrap(), "hello from disk\n");
    let mut r = c.get(&format!("{sbase}/trailers")).send().unwrap();
    assert_eq!(r.buffer().unwrap(), b"body");
    eprintln!("nginx trailers over h2: {:?}", r.trailers());
    // WebSocket is not configured in this nginx; HTTP/2 ping keepalive
    let k = common::client().keepalive_interval(Some(Duration::from_millis(100))).build();
    assert_eq!(k.get(&format!("{sbase}/hello.txt")).send().unwrap().status(), 200);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(k.get(&format!("{sbase}/hello.txt")).send().unwrap().status(), 200);
    assert_eq!(k.pool_stats().multiplexed, 1, "nginx answered the keepalive PINGs");
    eprintln!("nginx: ok");
}
