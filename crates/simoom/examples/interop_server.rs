//! A server endpoint for the QUIC Interop Runner
//! (<https://github.com/quic-interop/quic-interop-runner>).
//!
//! ```text
//! TESTCASE=transfer cargo run --release -p simoom --features http3 --example interop_server -- \
//!     [--addr [::]:443] [--www /www] [--certs /certs]
//! ```
//!
//! It follows the runner's endpoint contract: the test case comes from `TESTCASE`, files are
//! served from `--www`, the key and chain are `priv.key` and `cert.pem` in `--certs`, and an
//! unsupported test case exits with status 127.
//!
//! - `http3` goes through the `simoom` facade (`Server::listen_quic`), the production HTTP/3
//!   path.
//! - Every other test case speaks `hq-interop` (HTTP/0.9 over QUIC: `GET /path\r\n` on a
//!   bidirectional stream, the file as the reply) on a `simoom_quic::Endpoint` driven by a std
//!   UDP socket.

#![forbid(unsafe_code)]

use simoom_quic::tls::TlsProvider;
use simoom_quic::{ConnHandle, Config, DatagramEvent, Endpoint, Event, StreamError, VERSION_1, VERSION_2};
use simoom_tls::{CipherSuite, ServerConfig};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Settings derived from `TESTCASE`.
struct Case {
    retry: bool,
    chacha20: bool,
    v2: bool,
    http3: bool,
}

fn case(name: &str) -> Option<Case> {
    let base = Case { retry: false, chacha20: false, v2: false, http3: false };
    Some(match name {
        // `multiconnect` is handshakeloss and handshakecorruption; `transfer` is also used for
        // multiplexing, blackhole, amplificationlimit, keyupdate, the loss and corruption
        // cases, rebinding and ipv6; `ecn` and `zerortt` run as plain transfers (simoom has no
        // ECN marking and never accepts 0-RTT, so those checks are expected to fail).
        "handshake" | "transfer" | "multiconnect" | "resumption" | "ecn" | "zerortt" | "keyupdate" => base,
        "retry" => Case { retry: true, ..base },
        "chacha20" => Case { chacha20: true, ..base },
        "v2" => Case { v2: true, ..base },
        "http3" => Case { http3: true, ..base },
        _ => return None,
    })
}

/// `/www` joined with a request path, refusing anything that leaves the directory.
fn resolve(www: &Path, path: &[u8]) -> Option<PathBuf> {
    let p = std::str::from_utf8(path).ok()?;
    let p = p.split(['?', '#']).next()?;
    let rel = Path::new(p.trim_start_matches('/'));
    if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(www.join(rel))
}

fn tls_config(certs: &Path, case: &Case, alpn: &[&[u8]]) -> ServerConfig {
    let chain = std::fs::read(certs.join("cert.pem")).expect("read cert.pem");
    let key = std::fs::read(certs.join("priv.key")).expect("read priv.key");
    let mut c = ServerConfig::from_pem(&chain, &key).expect("load certificate and key").with_alpn(alpn);
    if case.chacha20 {
        c.suites = vec![CipherSuite::Chacha20Poly1305Sha256];
    }
    c
}

fn transport(cfg: &mut Config, case: &Case) {
    cfg.retry = case.retry;
    if case.v2 {
        // Prefer v2: a client that starts in v1 and lists v2 is moved to v2 (RFC 9368).
        cfg.versions = vec![VERSION_2, VERSION_1];
    }
    // The default stream limit (100, raised with MAX_STREAMS as streams finish): a client
    // that opens one file per allowed stream at once (quiche) runs out of descriptors at 1000.
    let t = &mut cfg.transport;
    t.max_data = 16 << 20;
    t.stream_window_bidi_remote = 4 << 20;
    t.max_idle_timeout = Duration::from_secs(60);
}

fn main() {
    let mut addr = "[::]:443".to_string();
    let mut www = PathBuf::from("/www");
    let mut certs = PathBuf::from("/certs");
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i + 1 < v.len() {
        let val = v[i + 1].clone();
        match v[i].as_str() {
            "--addr" => addr = val,
            "--www" => www = val.into(),
            "--certs" => certs = val.into(),
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    let name = std::env::var("TESTCASE").unwrap_or_default();
    let Some(case) = case(&name) else {
        eprintln!("unsupported test case {name:?}");
        std::process::exit(127);
    };
    eprintln!("simoom interop server: test case {name}, listening on {addr}");
    if case.http3 {
        serve_h3(&addr, www, &certs, &case);
    } else {
        serve_hq(&addr, &www, &certs, &case);
    }
}

fn serve_h3(addr: &str, www: PathBuf, certs: &Path, case: &Case) {
    use simoom::{Outcome, Reply, Request, Server};
    let retry = case.retry;
    let server = Server::builder()
        .listen_quic(addr)
        .quic_tls(tls_config(certs, case, &[b"h3"]))
        .quic_config(move |c| {
            c.retry = retry;
            c.transport.max_data = 16 << 20;
        })
        .threads(1)
        .limits(simoom::Limits { max_body: 0, ..simoom::Limits::default() })
        .service(move |req: &mut Request<'_>, reply: Reply<'_>| -> Outcome {
            match resolve(&www, req.path()).and_then(|p| std::fs::read(p).ok()) {
                Some(body) => reply.body(body),
                None => reply.status(404).body("not found"),
            }
        })
        .start()
        .expect("start");
    eprintln!("HTTP/3 on {:?}", server.quic_addrs());
    loop {
        std::thread::park();
    }
}

/// One hq-interop request: the request bytes until FIN, then the file being sent.
#[derive(Default)]
struct HqStream {
    request: Vec<u8>,
    reply: Option<Vec<u8>>,
    sent: usize,
    done: bool,
}

fn serve_hq(addr: &str, www: &Path, certs: &Path, case: &Case) {
    let tls = tls_config(certs, case, &[b"hq-interop"]);
    let mut cfg = Config::new(Arc::new(TlsProvider::server(Arc::new(tls))));
    transport(&mut cfg, case);
    let mut ep = Endpoint::new(Arc::new(cfg), true);
    let sock = UdpSocket::bind(addr).expect("bind");
    let mut streams: HashMap<ConnHandle, HashMap<u64, HqStream>> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::with_capacity(65536);
    let mut resp = Vec::new();
    let mut touched = Vec::new();
    loop {
        let now = Instant::now();
        let wait = ep.poll_timeout().map_or(Duration::from_millis(200), |d| d.saturating_duration_since(now)).max(Duration::from_micros(200));
        sock.set_read_timeout(Some(wait)).expect("timeout");
        touched.clear();
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let from = canonical(from);
                match ep.recv(Instant::now(), from, &mut buf[..n], &mut resp) {
                    DatagramEvent::Connection(h) | DatagramEvent::NewConnection(h) => touched.push(h),
                    DatagramEvent::Response(t) => send(&sock, &resp[..t.size], t.destination, None),
                    DatagramEvent::Dropped => {}
                }
                // Drain whatever else is queued before sending, so ACKs cover batches.
                sock.set_nonblocking(true).expect("nonblocking");
                while let Ok((n, from)) = sock.recv_from(&mut buf) {
                    let from = canonical(from);
                    match ep.recv(Instant::now(), from, &mut buf[..n], &mut resp) {
                        DatagramEvent::Connection(h) | DatagramEvent::NewConnection(h) => touched.push(h),
                        DatagramEvent::Response(t) => send(&sock, &resp[..t.size], t.destination, None),
                        DatagramEvent::Dropped => {}
                    }
                }
                sock.set_nonblocking(false).expect("blocking");
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => eprintln!("recv: {e}"),
        }
        ep.handle_timeout(Instant::now(), &mut touched);
        touched.sort();
        touched.dedup();
        for &h in &touched {
            drive(&mut ep, h, www, streams.entry(h).or_default());
            if ep.conn(h).is_none() {
                streams.remove(&h);
            }
        }
        // Connections with replies still waiting for flow control are driven again after
        // every batch (credit arrives with ACK and MAX_*_DATA frames).
        let pending: Vec<ConnHandle> = streams.iter().filter(|(_, s)| s.values().any(|x| x.reply.is_some() && !x.done)).map(|(h, _)| *h).collect();
        for h in pending {
            if !touched.contains(&h) {
                drive(&mut ep, h, www, streams.entry(h).or_default());
            }
        }
        while let Some((_, t)) = ep.poll_transmit(Instant::now(), &mut out, 16) {
            send(&sock, &out[..t.size], t.destination, t.segment_size);
        }
    }
}

/// IPv4-mapped IPv6 addresses (from the dual-stack socket) as plain IPv4.
fn canonical(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => a,
        },
        v4 => v4,
    }
}

fn send(sock: &UdpSocket, data: &[u8], to: SocketAddr, segment: Option<usize>) {
    let to = match (to, sock.local_addr()) {
        (SocketAddr::V4(v4), Ok(SocketAddr::V6(_))) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        (a, _) => a,
    };
    for d in data.chunks(segment.unwrap_or(data.len()).max(1)) {
        if let Err(e) = sock.send_to(d, to) {
            eprintln!("send to {to}: {e}");
        }
    }
}

fn drive(ep: &mut Endpoint, h: ConnHandle, www: &Path, streams: &mut HashMap<u64, HqStream>) {
    let mut readable = Vec::new();
    while let Some(ev) = ep.poll_event(h) {
        match ev {
            Event::StreamOpened(id) | Event::StreamReadable(id) => readable.push(id),
            Event::StreamReset { id, .. } | Event::StreamStopped { id, .. } => {
                streams.remove(&id);
            }
            Event::Closed(e) => eprintln!("connection {h:?} closed: {e:?}"),
            _ => {}
        }
    }
    let Some(conn) = ep.conn_mut(h) else { return };
    let mut tmp = [0u8; 4096];
    for id in readable {
        let st = streams.entry(id).or_default();
        loop {
            match conn.stream_recv(id, &mut tmp) {
                Ok((n, fin)) => {
                    st.request.extend_from_slice(&tmp[..n]);
                    if st.request.len() > 8192 {
                        let _ = conn.stream_reset(id, 0);
                        st.done = true;
                        break;
                    }
                    if fin || st.request.ends_with(b"\n") {
                        if st.reply.is_none() {
                            st.reply = Some(reply(www, &st.request));
                        }
                        if fin {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    for (&id, st) in streams.iter_mut() {
        let Some(body) = &st.reply else { continue };
        while !st.done {
            let chunk = &body[st.sent..];
            match conn.stream_send(id, chunk, true) {
                Ok(n) => {
                    st.sent += n;
                    if st.sent == body.len() {
                        st.done = true;
                    } else if n == 0 {
                        break;
                    }
                }
                Err(StreamError::Blocked) => break,
                Err(e) => {
                    eprintln!("stream {id}: {e:?}");
                    st.done = true;
                }
            }
        }
    }
    streams.retain(|_, s| !(s.done && s.reply.is_some()));
}

/// The reply to an HTTP/0.9 request line: the file, or an empty body if there is none.
fn reply(www: &Path, request: &[u8]) -> Vec<u8> {
    let line = request.split(|&b| b == b'\n').next().unwrap_or(request);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some(path) = line.strip_prefix(b"GET ") else { return Vec::new() };
    let path = path.split(|&b| b == b' ').next().unwrap_or(path);
    resolve(www, path).and_then(|p| std::fs::read(p).ok()).unwrap_or_default()
}
