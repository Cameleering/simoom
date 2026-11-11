//! TLS 1.2 interop over loopback (feature `tls12`) with real TLS stacks: `openssl s_client` and
//! `s_server` with `-tls1_2`, curl (`--tls-max 1.2`) and Python's `ssl` module, in both
//! directions. Each test prints a note and passes when the tool is missing. Set
//! `SIMOOM_OPENSSL` / `SIMOOM_CURL` / `SIMOOM_PYTHON` to choose binaries.

mod common;

use common::*;
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use simoom_tls::tls::tls12::Tls12Suite;
use simoom_tls::tls::ProtocolVersion;
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
    server_rsa: simoom_tls::certgen::SelfSigned,
    ca: simoom_tls::certgen::SelfSigned,
    client: simoom_tls::certgen::SelfSigned,
}

impl Pki {
    fn new() -> Pki {
        let dir = tempdir();
        let server = certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), PrivateKey::generate_ec(EcCurve::P256), None);
        let ca = certgen::issue(&CertParams::ca("Interop CA"), PrivateKey::generate_ec(EcCurve::P256), None);
        let client = certgen::issue(&CertParams::client("interop-client"), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
        let server_rsa = certgen::issue(&CertParams::server(&["localhost", "127.0.0.1"]), rsa_key(), None);
        for (name, data) in [
            ("server_rsa.pem", &server_rsa.cert_pem),
            ("server_rsa.key", &server_rsa.key_pem),
            ("server.pem", &server.cert_pem),
            ("server.key", &server.key_pem),
            ("ca.pem", &ca.cert_pem),
            ("client.pem", &client.cert_pem),
            ("client.key", &client.key_pem),
        ] {
            std::fs::write(dir.join(name), data).unwrap();
        }
        Pki { dir, server, server_rsa, ca, client }
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



fn s_client12(openssl: &Path, port: u16, args: &[&str]) -> Command {
    let mut c = Command::new(openssl);
    c.args(["s_client", "-connect", &format!("127.0.0.1:{port}"), "-tls1_2", "-servername", "localhost", "-verify_return_error"]);
    c.args(args);
    c
}

fn s_server12(ossl: &Path, pki: &Pki, cert: &str, port: u16, naccept: u32, extra: &[&str]) -> std::process::Child {
    let mut c = Command::new(ossl);
    c.args(["s_server", "-accept", &port.to_string(), "-tls1_2", "-cert", &pki.p(&format!("{cert}.pem")), "-key", &pki.p(&format!("{cert}.key")), "-www"]);
    c.args(["-naccept", &naccept.to_string()]);
    c.args(extra);
    c.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn s_server")
}

fn get12(cfg: Arc<ClientConfig>, port: u16) -> (String, bool, Option<ProtocolVersion>) {
    let mut sock = connect_retry(port);
    let mut conn = ClientConnection::new(cfg, "localhost").unwrap();
    conn.write_plaintext(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    let r = drive(&mut sock, &mut conn, |_, d| {
        resp.extend_from_slice(d);
        false
    });
    let resp = String::from_utf8_lossy(&resp).into_owned();
    if let Err(e) = r {
        return (format!("ERROR {e} {resp}"), false, None);
    }
    (resp, conn.is_resumed(), conn.protocol_version())
}

fn client12(roots: RootStore) -> ClientConfig {
    let mut c = ClientConfig::new(roots);
    c.max_version = ProtocolVersion::Tls12;
    c
}

#[test]
fn openssl_s_client_tls12_against_simoom_server() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    for (cert, cipher, group) in [
        ("server", "ECDHE-ECDSA-AES128-GCM-SHA256", "X25519:P-256"),
        ("server", "ECDHE-ECDSA-AES256-GCM-SHA384", "P-256"),
        ("server", "ECDHE-ECDSA-CHACHA20-POLY1305", "P-384:P-256"),
        ("server_rsa", "ECDHE-RSA-AES128-GCM-SHA256", "P-256"),
        ("server_rsa", "ECDHE-RSA-AES256-GCM-SHA384", "X25519"),
        ("server_rsa", "ECDHE-RSA-CHACHA20-POLY1305", "X25519"),
    ] {
        let ss = if cert == "server" { &pki.server } else { &pki.server_rsa };
        let mut cfg = ServerConfig::new(certified(ss)).with_alpn(&[b"h2", b"http/1.1"]);
        cfg.groups = vec![NamedGroup::Secp384r1, NamedGroup::X25519, NamedGroup::Secp256r1];
        let (port, h) = spawn_server(Arc::new(cfg), 1);
        let ca = pki.p(&format!("{cert}.pem"));
        let (_, out, err) = run(&mut s_client12(&ossl, port, &["-cipher", cipher, "-groups", group, "-CAfile", &ca, "-alpn", "http/1.1", "-quiet"]), b"hello tls12\n");
        let res = h.join().unwrap();
        assert!(out.contains("hello tls12"), "{cipher} {group}: stdout={out} stderr={err} server={:?}", res[0].2);
        assert_eq!(res[0].1.as_deref(), Some(&b"http/1.1"[..]));
        println!("s_client -tls1_2 {cipher} {group}: ok");
    }
    // a TLS 1.3 s_client still gets TLS 1.3 from the same server
    let cfg = Arc::new(ServerConfig::new(certified(&pki.server)));
    let (port, h) = spawn_server(cfg.clone(), 1);
    let mut cmd = Command::new(&ossl);
    cmd.args(["s_client", "-connect", &format!("127.0.0.1:{port}"), "-servername", "localhost", "-CAfile", &pki.p("server.pem")]);
    let (_, out, _) = run(&mut cmd, b"Q\n");
    let _ = h.join();
    assert!(out.contains("TLSv1.3"), "default s_client negotiates TLS 1.3: {out}");
}

#[test]
fn openssl_s_client_tls12_resumption_and_mtls() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    let ca = pki.p("server.pem");
    // tickets, then session IDs (-no_ticket)
    for (label, extra) in [("ticket", None), ("session id", Some("-no_ticket"))] {
        let cfg = Arc::new(ServerConfig::new(certified(&pki.server)));
        let sess = pki.p(&format!("sess-{}.pem", label.replace(' ', "")));
        let mut a1 = vec!["-CAfile", ca.as_str(), "-sess_out", sess.as_str(), "-quiet"];
        let mut a2 = vec!["-CAfile", ca.as_str(), "-sess_in", sess.as_str(), "-quiet"];
        if let Some(x) = extra {
            a1.push(x);
            a2.push(x);
        }
        let (port, h) = spawn_server(cfg.clone(), 1);
        let (_, out, err) = run(&mut s_client12(&ossl, port, &a1), b"first\n");
        h.join().unwrap();
        assert!(out.contains("first"), "{label}: {out} {err}");
        let (port, h) = spawn_server(cfg.clone(), 1);
        let (_, out, _) = run(&mut s_client12(&ossl, port, &a2), b"second\n");
        let res = h.join().unwrap();
        assert!(out.contains("second"));
        assert!(res[0].0, "{label}: the second connection must resume");
        println!("s_client -tls1_2 resumption by {label}: ok");
    }
    // mutual TLS
    let mut roots = RootStore::empty();
    roots.add_der(&pki.ca.cert_der).unwrap();
    let mut cfg = ServerConfig::new(certified(&pki.server));
    cfg.client_auth = ClientAuth::Required(roots);
    let cfg = Arc::new(cfg);
    let (port, h) = spawn_server(cfg.clone(), 1);
    let (_, out, err) = run(&mut s_client12(&ossl, port, &["-CAfile", &ca, "-cert", &pki.p("client.pem"), "-key", &pki.p("client.key"), "-quiet"]), b"mtls12\n");
    let res = h.join().unwrap();
    assert!(out.contains("mtls12"), "mtls: {out} {err} {:?}", res[0].2);
    let (port, h) = spawn_server(cfg, 1);
    let _ = run(&mut s_client12(&ossl, port, &["-CAfile", &ca, "-quiet"]), b"no cert\n");
    let res = h.join().unwrap();
    assert!(res[0].2.as_deref().unwrap_or("").contains("client certificate required"), "{:?}", res[0].2);
    // a client without the extended master secret is refused outright (OpenSSL 3.0 has no
    // -no_ems; only newer builds can run this part)
    let help = Command::new(&ossl).args(["s_client", "-help"]).output().map(|o| String::from_utf8_lossy(&o.stderr).into_owned() + &String::from_utf8_lossy(&o.stdout)).unwrap_or_default();
    if !help.contains("-no_ems") {
        println!("NOTE: this s_client has no -no_ems; EMS refusal checked in tests/tls12.rs only");
        return;
    }
    let cfg = Arc::new(ServerConfig::new(certified(&pki.server)));
    let (port, h) = spawn_server(cfg, 1);
    let _ = run(&mut s_client12(&ossl, port, &["-CAfile", &ca, "-quiet", "-no_ems"]), b"x\n");
    let res = h.join().unwrap();
    assert!(res[0].2.as_deref().unwrap_or("").contains("extended master secret"), "{:?}", res[0].2);
}

#[test]
fn simoom_client_tls12_against_openssl_s_server() {
    let Some(ossl) = openssl() else { return };
    let pki = Pki::new();
    for (cert, suite) in [
        ("server", Tls12Suite::EcdheEcdsaAes128GcmSha256),
        ("server", Tls12Suite::EcdheEcdsaAes256GcmSha384),
        ("server", Tls12Suite::EcdheEcdsaChacha20Poly1305),
        ("server_rsa", Tls12Suite::EcdheRsaAes128GcmSha256),
        ("server_rsa", Tls12Suite::EcdheRsaAes256GcmSha384),
        ("server_rsa", Tls12Suite::EcdheRsaChacha20Poly1305),
    ] {
        let ss = if cert == "server" { &pki.server } else { &pki.server_rsa };
        let port = free_port();
        let mut child = s_server12(&ossl, &pki, cert, port, 1, &[]);
        let mut cfg = client12(roots_of(ss));
        cfg.suites12 = vec![suite];
        let (resp, _, v) = get12(Arc::new(cfg), port);
        let _ = child.kill();
        let _ = child.wait();
        assert!(resp.starts_with("HTTP/1.0 200 ok"), "{suite:?}: {resp}");
        assert!(resp.contains(suite.openssl_name()), "s_server reports the suite: {resp}");
        assert_eq!(v, Some(ProtocolVersion::Tls12));
        println!("s_server -tls1_2 {}: ok", suite.name());
    }
    // a client offering TLS 1.3 and 1.2 against a TLS 1.2-only OpenSSL: no false downgrade alarm
    let port = free_port();
    let mut child = s_server12(&ossl, &pki, "server", port, 1, &[]);
    let (resp, _, v) = get12(Arc::new(ClientConfig::new(roots_of(&pki.server))), port);
    let _ = child.kill();
    let _ = child.wait();
    assert!(resp.starts_with("HTTP/1.0 200 ok"), "{resp}");
    assert_eq!(v, Some(ProtocolVersion::Tls12));
    // resumption: tickets, then session IDs
    for extra in [&[][..], &["-no_ticket"][..]] {
        let port = free_port();
        let mut child = s_server12(&ossl, &pki, "server", port, 2, extra);
        let cfg = Arc::new(client12(roots_of(&pki.server)));
        let (r1, resumed1, _) = get12(cfg.clone(), port);
        let (r2, resumed2, _) = get12(cfg, port);
        let _ = child.kill();
        let _ = child.wait();
        assert!(r1.starts_with("HTTP/1.0 200 ok") && r2.starts_with("HTTP/1.0 200 ok"), "{extra:?}: {r1} / {r2}");
        assert!(!resumed1 && resumed2, "{extra:?}: second connection resumes");
        println!("s_server -tls1_2 resumption {extra:?}: ok");
    }
    // mutual TLS
    let port = free_port();
    let mut child = s_server12(&ossl, &pki, "server", port, 1, &["-Verify", "1", "-CAfile", &pki.p("ca.pem")]);
    let mut cfg = client12(roots_of(&pki.server));
    cfg.client_cert = Some(simoom_tls::CertifiedKey::new(vec![pki.client.cert_der.clone()], pki.client.key.clone()).unwrap());
    let (resp, _, _) = get12(Arc::new(cfg), port);
    let _ = child.kill();
    let _ = child.wait();
    assert!(resp.starts_with("HTTP/1.0 200 ok"), "mtls: {resp}");
}

#[test]
fn curl_tls12_against_simoom_server() {
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
    for (cert, ss) in [("server", &pki.server), ("server_rsa", &pki.server_rsa)] {
        let cfg = Arc::new(ServerConfig::new(certified(ss)).with_alpn(&[b"http/1.1"]));
        for curl in &curls {
            let (port, h) = spawn_server(cfg.clone(), 1);
            let (ok, out, err) = run(
                Command::new(curl).args([
                    "-sS",
                    "--http1.1",
                    "--tlsv1.2",
                    "--tls-max",
                    "1.2",
                    "--cacert",
                    &pki.p(&format!("{cert}.pem")),
                    "--resolve",
                    &format!("localhost:{port}:127.0.0.1"),
                    &format!("https://localhost:{port}/"),
                ]),
                b"",
            );
            let res = h.join().unwrap();
            assert!(ok && out == "hello, simoom", "{} {cert}: out={out} err={err} server={:?}", curl.display(), res[0].2);
            println!("{} --tls-max 1.2 ({cert}): ok", curl.display());
        }
    }
}

fn python() -> Option<PathBuf> {
    let found = ["SIMOOM_PYTHON"].iter().filter_map(|e| std::env::var(e).ok().map(PathBuf::from)).chain(["python3".into(), "python".into()]).find(|p| {
        Command::new(p).args(["-c", "import ssl"]).stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
    });
    if found.is_none() {
        println!("NOTE: python with ssl not found; interop test skipped");
    }
    found
}

#[test]
fn python_ssl_tls12_both_directions() {
    let Some(py) = python() else { return };
    let pki = Pki::new();
    // Python client (TLS 1.2 only) against the simoom server
    let cfg = Arc::new(ServerConfig::new(certified(&pki.server_rsa)).with_alpn(&[b"http/1.1"]));
    let (port, h) = spawn_server(cfg, 1);
    let script = format!(
        "import ssl,socket\nc=ssl.create_default_context(cafile=r'{ca}')\nc.maximum_version=ssl.TLSVersion.TLSv1_2\ns=c.wrap_socket(socket.create_connection(('127.0.0.1',{port})),server_hostname='localhost')\ns.sendall(b'GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n')\nd=b''\nwhile True:\n  b=s.recv(4096)\n  if not b: break\n  d+=b\nprint(s.version(), s.cipher()[0], d.decode().split('\\r\\n\\r\\n')[-1])\n",
        ca = pki.p("server_rsa.pem")
    );
    let (ok, out, err) = run(Command::new(&py).args(["-I", "-c", &script]), b"");
    let res = h.join().unwrap();
    assert!(ok && out.contains("TLSv1.2") && out.contains("hello, simoom"), "python client: {out} {err} {:?}", res[0].2);
    println!("python client: {}", out.trim());
    // simoom client against a Python TLS 1.2 server
    let port = free_port();
    let script = format!(
        "import ssl,socket\nc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nc.maximum_version=ssl.TLSVersion.TLSv1_2\nc.load_cert_chain(r'{cert}',r'{key}')\nl=socket.create_server(('127.0.0.1',{port}))\nconn,_=l.accept()\ns=c.wrap_socket(conn,server_side=True)\nd=s.recv(4096)\ns.sendall(b'HTTP/1.0 200 ok\\r\\n\\r\\n'+s.version().encode()+b' '+s.cipher()[0].encode())\ns.close()\n",
        cert = pki.p("server.pem"),
        key = pki.p("server.key")
    );
    let mut child = Command::new(&py).args(["-I", "-c", &script]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (resp, _, v) = get12(Arc::new(ClientConfig::new(roots_of(&pki.server))), port);
    let _ = child.wait();
    assert!(resp.contains("TLSv1.2") && resp.contains("ECDHE-ECDSA"), "python server: {resp}");
    assert_eq!(v, Some(ProtocolVersion::Tls12));
    println!("python server: {}", resp.lines().last().unwrap_or(""));
}
