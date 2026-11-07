//! Interop over loopback with real TLS stacks: `openssl s_client` and `s_server`, and curl
//! (OpenSSL build and, on Windows, the system curl with Schannel). Each test prints a note and
//! passes when the tool is missing. Set `SIMOOM_OPENSSL` / `SIMOOM_CURL` to choose binaries.

#![cfg(feature = "client")]

mod common;

use common::*;
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::x509::RootStore;
use simoom_tls::{ClientAuth, ClientConfig, ClientConnection, Connection, NamedGroup, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn tool(env: &str, name: &str, extra: &[&str]) -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Ok(p) = std::env::var(env) {
        cands.push(p.into());
    }
    cands.push(name.into());
    cands.extend(extra.iter().map(PathBuf::from));
    cands.into_iter().find(|c| Command::new(c).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok() || Command::new(c).arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok())
}

fn openssl() -> Option<PathBuf> {
    let found = tool("SIMOOM_OPENSSL", "openssl", &[r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\msys64\ucrt64\bin\openssl.exe"]);
    if found.is_none() {
        println!("NOTE: openssl not found; interop test skipped");
    }
    found
}

fn tempdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!("simoom-tls-interop-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Paths written for a test: server cert/key and a client CA + client cert/key.
struct Pki {
    dir: PathBuf,
    server: simoom_tls::certgen::SelfSigned,
    ca: simoom_tls::certgen::SelfSigned,
    client: simoom_tls::certgen::SelfSigned,
}

impl Pki {
    fn new() -> Pki {
        let dir = tempdir();
        let server = certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), PrivateKey::generate_ec(EcCurve::P256), None);
        let ca = certgen::issue(&CertParams::ca("Interop CA"), PrivateKey::generate_ec(EcCurve::P256), None);
        let client = certgen::issue(&CertParams::client("interop-client"), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
        for (name, data) in [
            ("server.pem", &server.cert_pem),
            ("server.key", &server.key_pem),
            ("ca.pem", &ca.cert_pem),
            ("client.pem", &client.cert_pem),
            ("client.key", &client.key_pem),
        ] {
            std::fs::write(dir.join(name), data).unwrap();
        }
        Pki { dir, server, ca, client }
    }
    fn p(&self, name: &str) -> String {
        self.dir.join(name).to_string_lossy().replace('\\', "/")
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Drives a TLS connection over a blocking socket until the peer closes. `on_data` sees each
/// batch of plaintext and may write a reply; it returns true to close.
fn drive(sock: &mut TcpStream, conn: &mut Connection, mut on_data: impl FnMut(&mut Connection, &[u8]) -> bool) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut buf = vec![0u8; 32 * 1024];
    let mut closing = false;
    loop {
        while conn.wants_write() {
            let n = sock.write(conn.tls_output()).map_err(|e| e.to_string())?;
            conn.consume_tls_output(n);
        }
        if closing || conn.peer_has_closed() {
            if !closing {
                conn.send_close_notify();
                while conn.wants_write() {
                    let n = sock.write(conn.tls_output()).map_err(|e| e.to_string())?;
                    conn.consume_tls_output(n);
                }
            }
            return Ok(());
        }
        let n = match sock.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset || e.kind() == std::io::ErrorKind::ConnectionAborted => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        let mut off = 0;
        while off < n {
            off += conn.read_tls(&buf[off..n]);
            if let Err(e) = conn.process_new_packets() {
                while conn.wants_write() {
                    let w = sock.write(conn.tls_output()).unwrap_or(0);
                    if w == 0 {
                        break;
                    }
                    conn.consume_tls_output(w);
                }
                return Err(e.to_string());
            }
            let data = conn.plaintext().to_vec();
            if !data.is_empty() {
                conn.consume_plaintext(data.len());
                if on_data(conn, &data) {
                    conn.send_close_notify();
                    closing = true;
                }
            }
        }
    }
}

/// Starts a simoom server thread accepting `count` connections; each echoes data back, and
/// replies with an HTTP response when it sees a request line. Returns the port and a handle
/// yielding (resumed, alpn, error) per connection.
fn spawn_server(cfg: Arc<ServerConfig>, count: usize) -> (u16, std::thread::JoinHandle<Vec<(bool, Option<Vec<u8>>, Option<String>, Vec<u8>)>>) {
    spawn_server_opts(cfg, count, false)
}

/// `key_update`: send KeyUpdate(update_requested) before echoing.
fn spawn_server_opts(cfg: Arc<ServerConfig>, count: usize, key_update: bool) -> (u16, std::thread::JoinHandle<Vec<(bool, Option<Vec<u8>>, Option<String>, Vec<u8>)>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let mut out = Vec::new();
        for _ in 0..count {
            let (mut sock, _) = l.accept().unwrap();
            let mut conn = ServerConnection::new(cfg.clone());
            let mut got = Vec::new();
            let r = drive(&mut sock, &mut conn, |c, d| {
                got.extend_from_slice(d);
                if got.starts_with(b"GET ") {
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        c.write_plaintext(b"HTTP/1.1 200 OK\r\ncontent-length: 13\r\nconnection: close\r\n\r\nhello, simoom").unwrap();
                        return true;
                    }
                    false
                } else {
                    // echo one line, then close (s_client -quiet waits for the server to close)
                    if key_update {
                        c.send_key_update(true).unwrap();
                    }
                    c.write_plaintext(d).unwrap();
                    got.ends_with(b"
")
                }
            });
            out.push((conn.is_resumed(), conn.alpn_protocol().map(|a| a.to_vec()), r.err(), got));
        }
        out
    });
    (port, h)
}

fn run(cmd: &mut Command, stdin: &[u8]) -> (bool, String, String) {
    run_paced(cmd, &[stdin])
}

/// Like `run`, writing each chunk of stdin separately with a pause in between (s_client reads
/// one command per read).
fn run_paced(cmd: &mut Command, chunks: &[&[u8]]) -> (bool, String, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("spawn");
    let mut stdin = child.stdin.take().unwrap();
    for (i, c) in chunks.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(700));
        }
        let _ = stdin.write_all(c);
        let _ = stdin.flush();
    }
    if chunks.len() > 1 {
        std::thread::sleep(Duration::from_millis(700));
    }
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(_st) = child.try_wait().unwrap() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let o = child.wait_with_output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn s_client(openssl: &Path, port: u16, args: &[&str]) -> Command {
    let mut c = Command::new(openssl);
    c.args(["s_client", "-connect", &format!("127.0.0.1:{port}"), "-tls1_3", "-servername", "localhost", "-verify_return_error"]);
    c.args(args);
    c
}

#[test]
fn openssl_s_client_against_simoom_server() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    let cases = [
        ("TLS_AES_128_GCM_SHA256", "X25519"),
        ("TLS_AES_256_GCM_SHA384", "P-256"),
        ("TLS_CHACHA20_POLY1305_SHA256", "X25519"),
        ("TLS_AES_128_GCM_SHA256", "P-256"),
    ];
    for (suite, group) in cases {
        let cfg = Arc::new(ServerConfig::new(certified(&pki.server)).with_alpn(&[b"h2", b"http/1.1"]));
        let (port, h) = spawn_server(cfg, 1);
        let ca = pki.p("server.pem");
        let (_, out, err) = run(
            &mut s_client(&ossl, port, &["-ciphersuites", suite, "-groups", group, "-CAfile", &ca, "-alpn", "http/1.1", "-quiet"]),
            b"hello from openssl\n",
        );
        // -quiet keeps reading after stdin closes; the echo server closes after the peer does
        let res = h.join().unwrap();
        assert!(out.contains("hello from openssl"), "{suite} {group}: stdout={out} stderr={err}");
        assert_eq!(res[0].1.as_deref(), Some(&b"http/1.1"[..]));
        println!("s_client {suite} {group}: ok");
    }
}

#[test]
fn openssl_s_client_hrr_mtls_resumption_keyupdate() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    let ca = pki.p("server.pem");
    // HelloRetryRequest: s_client sends an X25519 share, the server only takes P-256
    let mut cfg = ServerConfig::new(certified(&pki.server));
    cfg.groups = vec![NamedGroup::Secp256r1];
    let (port, h) = spawn_server(Arc::new(cfg), 1);
    let (_, out, err) = run(&mut s_client(&ossl, port, &["-groups", "X25519:P-256", "-CAfile", &ca, "-quiet"]), b"after hrr\n");
    h.join().unwrap();
    assert!(out.contains("after hrr"), "hrr: {out} {err}");

    // mutual TLS
    let mut roots = RootStore::empty();
    roots.add_der(&pki.ca.cert_der).unwrap();
    let mut cfg = ServerConfig::new(certified(&pki.server));
    cfg.client_auth = ClientAuth::Required(roots);
    let cfg = Arc::new(cfg);
    let (port, h) = spawn_server(cfg.clone(), 1);
    let (_, out, err) = run(&mut s_client(&ossl, port, &["-CAfile", &ca, "-cert", &pki.p("client.pem"), "-key", &pki.p("client.key"), "-quiet"]), b"mtls\n");
    let res = h.join().unwrap();
    assert!(out.contains("mtls"), "mtls: {out} {err}");
    assert!(res[0].2.is_none());
    // ... and without a client certificate the server refuses
    let (port, h) = spawn_server(cfg, 1);
    let _ = run(&mut s_client(&ossl, port, &["-CAfile", &ca, "-quiet"]), b"no cert\n");
    let res = h.join().unwrap();
    assert!(res[0].2.as_deref().unwrap_or("").contains("certificate_required"), "{:?}", res[0].2);

    // resumption with a saved session
    let cfg = Arc::new(ServerConfig::new(certified(&pki.server)));
    let sess = pki.p("sess.pem");
    let (port, h) = spawn_server(cfg.clone(), 1);
    let (_, out, err) = run(&mut s_client(&ossl, port, &["-CAfile", &ca, "-sess_out", &sess, "-quiet"]), b"first\n");
    h.join().unwrap();
    assert!(out.contains("first"), "{out} {err}");
    let (port, h) = spawn_server(cfg.clone(), 1);
    let (_, out, _) = run(&mut s_client(&ossl, port, &["-CAfile", &ca, "-sess_in", &sess, "-quiet"]), b"second\n");
    let res = h.join().unwrap();
    assert!(out.contains("second"));
    assert!(res[0].0, "the second connection must resume");

    // our KeyUpdate (update_requested): s_client must decrypt the echo under the new key
    let (port, h) = spawn_server_opts(cfg.clone(), 1, true);
    let (_, out, err) = run(&mut s_client(&ossl, port, &["-CAfile", &ca, "-quiet"]), b"after our key update\n");
    let res = h.join().unwrap();
    assert!(out.contains("after our key update"), "{out} {err}");
    assert!(res[0].2.is_none(), "{:?}", res[0].2);

    // OpenSSL's KeyUpdate ("K" command, interactive mode). Windows builds of s_client do not
    // read commands from a piped stdin, so an empty result there is only noted.
    let (port, h) = spawn_server(cfg, 1);
    let (_, _out, err) = run_paced(&mut s_client(&ossl, port, &["-CAfile", &ca]), &[b"K\n", b"after key update\n"]);
    let res = h.join().unwrap();
    assert!(res[0].2.is_none(), "{:?} {err}", res[0].2);
    if res[0].3.is_empty() && cfg!(windows) {
        println!("NOTE: s_client read no commands from the pipe (Windows); peer-initiated KeyUpdate checked on Linux only");
    } else {
        assert!(String::from_utf8_lossy(&res[0].3).contains("after key update"), "{:?}", String::from_utf8_lossy(&res[0].3));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn connect_retry(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("cannot connect to s_server: {e}"),
        }
    }
}

/// Connects a simoom client to s_server -www, sends a GET and returns the response.
fn get(cfg: Arc<ClientConfig>, port: u16, key_update: bool) -> (String, bool) {
    let mut sock = connect_retry(port);
    let mut conn = ClientConnection::new(cfg, "localhost").unwrap();
    conn.write_plaintext(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    let mut updated = false;
    drive(&mut sock, &mut conn, |c, d| {
        if key_update && !updated {
            c.send_key_update(true).unwrap();
            updated = true;
        }
        resp.extend_from_slice(d);
        false
    })
    .unwrap();
    (String::from_utf8_lossy(&resp).into_owned(), conn.is_resumed())
}

fn s_server(ossl: &Path, pki: &Pki, port: u16, naccept: u32, extra: &[&str]) -> std::process::Child {
    let mut c = Command::new(ossl);
    c.args(["s_server", "-accept", &port.to_string(), "-tls1_3", "-cert", &pki.p("server.pem"), "-key", &pki.p("server.key"), "-www"]);
    c.args(["-naccept", &naccept.to_string()]);
    c.args(extra);
    c.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn s_server")
}

#[test]
fn simoom_client_against_openssl_s_server() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    let roots = roots_of(&pki.server);
    for (suites, group) in [
        (vec![simoom_tls::CipherSuite::Aes128GcmSha256], NamedGroup::X25519),
        (vec![simoom_tls::CipherSuite::Aes256GcmSha384], NamedGroup::Secp256r1),
        (vec![simoom_tls::CipherSuite::Chacha20Poly1305Sha256], NamedGroup::X25519),
    ] {
        let port = free_port();
        let mut child = s_server(&ossl, &pki, port, 1, &[]);
        let mut cfg = ClientConfig::new(roots.clone());
        cfg.suites = suites.clone();
        cfg.groups = vec![group];
        let (resp, _) = get(Arc::new(cfg), port, false);
        let _ = child.kill();
        let _ = child.wait();
        assert!(resp.starts_with("HTTP/1.0 200 ok"), "{suites:?} {group:?}: {resp}");
        assert!(resp.contains(suites[0].name()), "s_server reports the suite: {resp}");
    }
    // HelloRetryRequest from OpenSSL, resumption and KeyUpdate in one s_server run
    let port = free_port();
    let mut child = s_server(&ossl, &pki, port, 3, &["-groups", "P-256"]);
    let mut cfg = ClientConfig::new(roots.clone());
    cfg.groups = vec![NamedGroup::X25519, NamedGroup::Secp256r1];
    let cfg = Arc::new(cfg);
    let (resp, resumed) = get(cfg.clone(), port, false);
    assert!(resp.starts_with("HTTP/1.0 200 ok") && !resumed, "{resp}");
    let (resp, resumed) = get(cfg.clone(), port, true);
    assert!(resp.starts_with("HTTP/1.0 200 ok"), "{resp}");
    assert!(resumed, "second connection resumes with OpenSSL's ticket");
    let (resp, _) = get(cfg, port, false);
    assert!(resp.starts_with("HTTP/1.0 200 ok"));
    let _ = child.kill();
    let _ = child.wait();
    // mutual TLS: s_server demands a client certificate
    let port = free_port();
    let mut child = s_server(&ossl, &pki, port, 1, &["-Verify", "1", "-CAfile", &pki.p("ca.pem")]);
    let mut cfg = ClientConfig::new(roots);
    cfg.client_cert = Some(simoom_tls::CertifiedKey::new(vec![pki.client.cert_der.clone()], pki.client.key.clone()).unwrap());
    let (resp, _) = get(Arc::new(cfg), port, false);
    let _ = child.kill();
    let _ = child.wait();
    assert!(resp.starts_with("HTTP/1.0 200 ok"), "mtls: {resp}");
}

#[test]
fn curl_against_simoom_server() {
    let mut curls: Vec<PathBuf> = Vec::new();
    if let Some(c) = tool("SIMOOM_CURL", "curl", &[]) {
        curls.push(c);
    }
    let system = PathBuf::from(r"C:\Windows\System32\curl.exe");
    if cfg!(windows) && system.exists() && !curls.contains(&system) {
        curls.push(system);
    }
    if curls.is_empty() {
        println!("NOTE: curl not found; interop test skipped");
        return;
    }
    let pki = Pki::new();
    let cfg = Arc::new(ServerConfig::new(certified(&pki.server)).with_alpn(&[b"http/1.1"]));
    for curl in curls {
        let (port, h) = spawn_server(cfg.clone(), 1);
        let (ok, out, err) = run(
            Command::new(&curl).args([
                "-sS",
                "--http1.1",
                "--tlsv1.3",
                "--cacert",
                &pki.p("server.pem"),
                "--resolve",
                &format!("localhost:{port}:127.0.0.1"),
                &format!("https://localhost:{port}/"),
            ]),
            b"",
        );
        let res = h.join().unwrap();
        if !ok && err.contains("schannel") && (err.contains("not supported") || err.contains("SEC_E")) {
            println!("NOTE: {} cannot do this TLS 1.3 test here: {err}", curl.display());
            continue;
        }
        assert!(ok && out == "hello, simoom", "{}: out={out} err={err} server={:?}", curl.display(), res[0].2);
        println!("{}: ok", curl.display());
    }
}
