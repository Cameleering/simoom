//! Interop with real clients when they are installed: curl (HTTP/1.1, h2c, HTTP/3 over TLS) and
//! Python's `http.client`. Missing tools or features are skipped with a printed note.

mod common;

use simoom::{Outcome, Reply, Request, Server, ServerHandle};
use std::process::Command;

fn service(req: &mut Request<'_>, reply: Reply<'_>) -> Outcome {
    let s = format!("{:?} {} {} {}", req.version(), String::from_utf8_lossy(req.method()), req.path_str(), req.body().len());
    reply.header("content-type", "text/plain").body(s)
}

fn curl_features() -> Option<String> {
    let out = Command::new("curl").arg("--version").output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn curl(args: &[&str]) -> Option<String> {
    let out = Command::new("curl").args(["-sS", "--max-time", "10"]).args(args).output().ok()?;
    if !out.status.success() {
        eprintln!("curl {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn start() -> ServerHandle {
    Server::builder().listen("127.0.0.1:0").threads(2).service(service).start().unwrap()
}

#[test]
fn curl_http1() {
    let Some(v) = curl_features() else {
        eprintln!("note: curl not found; skipping the curl HTTP/1.1 interop test");
        return;
    };
    let _ = v;
    let h = start();
    let base = format!("http://{}", h.local_addr());
    // Two URLs on one connection (keep-alive), a POST, and a chunked upload.
    let out = curl(&["--http1.1", &format!("{base}/a"), &format!("{base}/b")]).expect("curl");
    assert_eq!(out, "Http11 GET /a 0Http11 GET /b 0");
    let out = curl(&["--http1.1", "--data-binary", "0123456789", &format!("{base}/post")]).expect("curl");
    assert_eq!(out, "Http11 POST /post 10");
    let out = curl(&["--http1.1", "-H", "Transfer-Encoding: chunked", "--data-binary", "abcdef", &format!("{base}/chunked")]).expect("curl");
    assert_eq!(out, "Http11 POST /chunked 6");
    assert_eq!(h.stats().accepted, 3);
}

#[test]
fn curl_h2c() {
    let Some(v) = curl_features() else {
        eprintln!("note: curl not found; skipping the curl h2c interop test");
        return;
    };
    if !cfg!(feature = "http2") || !v.contains("HTTP2") {
        eprintln!("note: this curl (or build) has no HTTP/2; skipping the curl h2c interop test");
        return;
    }
    let h = start();
    let base = format!("http://{}", h.local_addr());
    assert_eq!(curl(&["--http2-prior-knowledge", &format!("{base}/pk"), &format!("{base}/pk2")]).expect("curl"), "H2 GET /pk 0H2 GET /pk2 0");
    assert_eq!(curl(&["--http2", &format!("{base}/upgrade")]).expect("curl"), "H2 GET /upgrade 0");
    assert_eq!(curl(&["--http2-prior-knowledge", "--data-binary", "xyz", &format!("{base}/post")]).expect("curl"), "H2 POST /post 3");
}

#[cfg(feature = "http3")]
#[test]
fn curl_http3() {
    use simoom::tls::{certgen, CertifiedKey, ServerConfig};
    let Some(v) = curl_features() else {
        eprintln!("note: curl not found; skipping the curl HTTP/3 interop test");
        return;
    };
    if !v.contains("HTTP3") {
        eprintln!("note: this curl has no HTTP/3; skipping the curl HTTP/3 interop test");
        return;
    }
    let ss = certgen::issue(&certgen::CertParams::server(&["localhost"]), simoom_tls::keys::PrivateKey::generate_ec(simoom_tls::keys::EcCurve::P256), None);
    let dir = std::env::temp_dir().join(format!("simoom-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, &ss.cert_pem).unwrap();
    let ck = || CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap();
    let h = Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(ServerConfig::new(ck()))
        .listen_quic("127.0.0.1:0")
        .quic_tls(ServerConfig::new(ck()))
        .threads(2)
        .service(service)
        .start()
        .unwrap();
    let port = h.quic_addrs()[0].port();
    let url = format!("https://localhost:{port}/h3");
    let resolve = format!("localhost:{port}:127.0.0.1");
    let ca = ca.to_string_lossy().into_owned();
    match curl(&["--http3-only", "--cacert", &ca, "--resolve", &resolve, &url]) {
        Some(out) => assert_eq!(out, "H3 GET /h3 0"),
        None => panic!("curl --http3-only failed"),
    }
    let tport = h.local_addr().port();
    let resolve = format!("localhost:{tport}:127.0.0.1");
    let out = curl(&["--cacert", &ca, "--resolve", &resolve, &format!("https://localhost:{tport}/tls")]).expect("curl over TLS");
    assert!(out.ends_with("GET /tls 0"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "tls")]
#[test]
fn curl_tls_alpn() {
    use simoom::tls::{certgen, CertifiedKey, ServerConfig};
    let Some(v) = curl_features() else {
        eprintln!("note: curl not found; skipping the curl TLS interop test");
        return;
    };
    if !v.contains("OpenSSL") {
        eprintln!("note: this curl does not take a PEM CA file (not OpenSSL); skipping the curl TLS interop test");
        return;
    }
    let ss = certgen::issue(&certgen::CertParams::server(&["localhost"]), simoom_tls::keys::PrivateKey::generate_ec(simoom_tls::keys::EcCurve::P256), None);
    let dir = std::env::temp_dir().join(format!("simoom-interop-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, &ss.cert_pem).unwrap();
    let h = Server::builder()
        .listen_tls("127.0.0.1:0")
        .tls(ServerConfig::new(CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap()))
        .threads(2)
        .service(service)
        .start()
        .unwrap();
    let port = h.local_addr().port();
    let resolve = format!("localhost:{port}:127.0.0.1");
    let ca = ca.to_string_lossy().into_owned();
    let url = format!("https://localhost:{port}/tls");
    let out = curl(&["--http1.1", "--cacert", &ca, "--resolve", &resolve, &url, &url]).expect("curl https http/1.1");
    assert_eq!(out, "Http11 GET /tls 0Http11 GET /tls 0");
    if v.contains("HTTP2") {
        let out = curl(&["--http2", "--cacert", &ca, "--resolve", &resolve, "--data-binary", "abc", &url]).expect("curl https h2");
        assert_eq!(out, "H2 POST /tls 3");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_http_client() {
    let h = start();
    let addr = h.local_addr();
    let script = format!(
        r#"
import http.client
c = http.client.HTTPConnection("{ip}", {port}, timeout=10)
out = []
for p in ["/one", "/two"]:
    c.request("GET", p)
    r = c.getresponse()
    out.append(r.read().decode())
c.request("POST", "/form", body=b"a=1&b=2", headers={{"Content-Type": "application/x-www-form-urlencoded"}})
out.append(c.getresponse().read().decode())
c.request("POST", "/chunks", body=iter([b"ab", b"cde"]), encode_chunked=True)
out.append(c.getresponse().read().decode())
print("|".join(out))
"#,
        ip = addr.ip(),
        port = addr.port()
    );
    for py in ["python3", "python"] {
        let Ok(out) = Command::new(py).args(["-I", "-c", &script]).output() else { continue };
        if !out.status.success() {
            continue;
        }
        let s = String::from_utf8_lossy(&out.stdout);
        assert_eq!(s.trim(), "Http11 GET /one 0|Http11 GET /two 0|Http11 POST /form 7|Http11 POST /chunks 5");
        assert_eq!(h.stats().accepted, 1, "one keep-alive connection");
        return;
    }
    eprintln!("note: python not found; skipping the http.client interop test");
}
