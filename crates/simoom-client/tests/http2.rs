//! TLS and HTTP/2: ALPN, h2c, multiplexing, flow control, trailers, duplex calls, resets,
//! GOAWAY, keepalive, certificate checks.

#![cfg(all(feature = "client-h2", feature = "tls"))]

mod common;

use common::{client, plain, raw, secure, surl, url};
use simoom_client::tls::TlsOptions;
use simoom_client::{Body, Client, ErrorKind, Headers, HttpVersion, Version};
use simoom_h2::{Config, Connection, ErrorCode, Event};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn https_with_alpn_h2_and_http1() {
    let h = secure();
    let c = client().build();
    let r = c.get(&surl(&h, "/echo")).send().unwrap();
    assert_eq!(r.version(), Version::Http2);
    let t = r.text().unwrap();
    assert!(t.starts_with("H2 GET /echo"), "{t}");
    assert!(t.contains(&format!("host=localhost:{}", h.local_addrs()[1].port())), "authority: {t}");
    let r = c.get(&surl(&h, "/echo")).version(HttpVersion::Http1).send().unwrap();
    assert_eq!(r.version(), Version::Http11);
    assert!(r.text().unwrap().starts_with("Http11 GET /echo"));
    let s = c.pool_stats();
    assert_eq!((s.multiplexed, s.idle), (1, 1), "{s:?}");
}

#[test]
fn certificate_verification_is_always_on() {
    let h = secure();
    // untrusted
    let c = Client::builder().roots(simoom_client::tls::RootStore::empty()).build();
    let e = c.get(&surl(&h, "/echo")).send().unwrap_err();
    assert_eq!(e.kind, ErrorKind::Tls, "{e}");
    // wrong name
    let c = client().build();
    let u = format!("https://127.0.0.2:{}/echo", h.local_addrs()[1].port());
    let e = c.get(&u).send().unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Tls | ErrorKind::Connect), "{e}");
    // server name override: connect by address, verify `localhost`
    let c = client().tls(TlsOptions { roots: common::roots(), server_name: Some("localhost".into()), ..TlsOptions::default() }).build();
    let u = format!("https://127.0.0.1:{}/echo", h.local_addrs()[1].port());
    assert_eq!(c.get(&u).send().unwrap().status(), 200);
}

#[test]
fn h2c_prior_knowledge_and_multiplexing() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).build();
    let r = c.get(&url(&h, "/echo")).send().unwrap();
    assert_eq!(r.version(), Version::Http2);
    assert!(r.text().unwrap().starts_with("H2 GET"));
    // 16 slow requests at once share one connection
    let t = Instant::now();
    let ts: Vec<_> = (0..16)
        .map(|_| {
            let (c, u) = (c.clone(), url(&h, "/slow?ms=200"));
            std::thread::spawn(move || c.get(&u).send().unwrap().text().unwrap())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), "slow done");
    }
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
    assert_eq!(c.pool_stats().multiplexed, 1);
    assert_eq!(c.pool_stats().http1, 0);
}

#[test]
fn large_bodies_both_ways_with_flow_control() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).build();
    let n = 6_000_000;
    let r = c.get(&url(&h, &format!("/big?n={n}"))).send().unwrap();
    let mut body = r.into_body();
    let mut buf = vec![0u8; 3000];
    let mut total = 0;
    loop {
        let k = body.read(&mut buf).unwrap();
        if k == 0 {
            break;
        }
        assert_eq!(buf[0], (total % 251) as u8);
        total += k;
    }
    assert_eq!(total, n);
    let up = vec![5u8; 5_000_000];
    let sum = up.iter().fold(0u64, |a, &x| a.wrapping_mul(31).wrapping_add(x as u64));
    let r = c.post(&url(&h, "/upload")).body(up).send().unwrap();
    assert_eq!(r.text().unwrap(), format!("5000000 {sum}"));
    let r = c.post(&url(&h, "/upload")).body(Body::reader(std::io::repeat(5).take(3_000_000))).send().unwrap();
    let sum = (0..3_000_000).fold(0u64, |a, _| a.wrapping_mul(31).wrapping_add(5));
    assert_eq!(r.text().unwrap(), format!("3000000 {sum}"));
    // two big downloads interleaved on one connection, read alternately
    let mut a = c.get(&url(&h, "/big?n=2000000")).send().unwrap().into_body();
    let mut b = c.get(&url(&h, "/big?n=2000000")).send().unwrap().into_body();
    let (mut na, mut nb) = (0, 0);
    loop {
        let ka = a.read(&mut buf).unwrap();
        let kb = b.read(&mut buf).unwrap();
        na += ka;
        nb += kb;
        if ka == 0 && kb == 0 {
            break;
        }
    }
    assert_eq!((na, nb), (2_000_000, 2_000_000));
}

#[test]
fn response_trailers_over_h2() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).build();
    let mut r = c.get(&url(&h, "/trailers")).send().unwrap();
    assert_eq!(r.buffer().unwrap(), b"payload");
    assert_eq!(r.trailers().unwrap().get("x-checksum"), Some("abc123"));
}

#[test]
fn dropping_a_body_cancels_the_stream() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).build();
    for _ in 0..30 {
        let r = c.get(&url(&h, "/big?n=3000000")).send().unwrap();
        drop(r);
    }
    // the connection is still usable and no stream leaked (the server allows 100)
    let ts: Vec<_> = (0..120)
        .map(|_| {
            let (c, u) = (c.clone(), url(&h, "/echo"));
            std::thread::spawn(move || c.get(&u).send().unwrap().status())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), 200);
    }
}

#[test]
fn duplex_call_streams_both_ways() {
    // An h2 echo server built on simoom-h2: echoes each DATA frame, then trailers.
    let srv = h2_server(|conn, ev| match ev {
        Ev::Headers(id) => {
            conn.send_response(id, 200, &[(b"content-type", b"application/grpc")], false).unwrap();
        }
        Ev::Data(id, d, end) => {
            if !d.is_empty() {
                conn.send_data(id, &d, false).unwrap();
            }
            if end {
                conn.send_trailers(id, &[(b"grpc-status", b"0")]).unwrap();
            }
        }
    });
    let c = Client::builder().version(HttpVersion::Http2).build();
    let mut call = c.call("POST", &format!("http://{srv}/svc/Echo"), &Headers::new()).unwrap();
    let sender = call.sender();
    let (s, _) = call.response().map(|(s, h)| (s, h.clone())).unwrap();
    assert_eq!(s, 200);
    let mut buf = [0u8; 64];
    for i in 0..5 {
        let msg = format!("msg{i}");
        sender.send(msg.as_bytes()).unwrap();
        let mut got = Vec::new();
        while got.len() < msg.len() {
            let k = call.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..k]);
        }
        assert_eq!(got, msg.as_bytes(), "echo arrives before the request ends");
    }
    sender.finish().unwrap();
    assert_eq!(call.read(&mut buf).unwrap(), 0);
    assert_eq!(call.trailers().unwrap().get("grpc-status"), Some("0"));
}

#[test]
fn complete_response_then_rst_stream_no_error_is_kept() {
    // RFC 9113 §8.1 (simoom BUGS U11, client side): a server may answer before reading the
    // whole request and then reset the stream with NO_ERROR.
    let srv = h2_server(|conn, ev| {
        if let Ev::Headers(id) = ev {
            conn.send_response(id, 200, &[], false).unwrap();
            conn.send_data(id, b"early answer", true).unwrap();
            conn.reset(id, ErrorCode::NO_ERROR);
        }
    });
    let c = Client::builder().version(HttpVersion::Http2).build();
    let r = c.post(&format!("http://{srv}/")).body(Body::reader(std::io::repeat(1).take(200_000))).send();
    // either the upload finished first or the reset stopped it; the answer is kept
    let r = r.unwrap();
    assert_eq!(r.text().unwrap(), "early answer");
}

#[test]
fn refused_streams_are_retried_and_goaway_opens_a_new_connection() {
    let refused = Arc::new(AtomicUsize::new(0));
    let rf = refused.clone();
    let srv = h2_server(move |conn, ev| {
        if let Ev::Headers(id) = ev {
            if rf.fetch_add(1, Ordering::SeqCst) == 0 {
                conn.reset(id, ErrorCode::REFUSED_STREAM);
            } else {
                conn.send_response(id, 200, &[], false).unwrap();
                conn.send_data(id, b"ok", true).unwrap();
            }
        }
    });
    let c = Client::builder().version(HttpVersion::Http2).build();
    assert_eq!(c.get(&format!("http://{srv}/")).send().unwrap().text().unwrap(), "ok");
    assert_eq!(refused.load(Ordering::SeqCst), 2);

    // GOAWAY after each response: the next request needs a new connection
    let conns = Arc::new(AtomicUsize::new(0));
    let srv = h2_server_with(conns.clone(), |conn, ev| {
        if let Ev::Headers(id) = ev {
            conn.send_response(id, 200, &[], false).unwrap();
            conn.send_data(id, b"bye", true).unwrap();
            conn.shutdown(0);
        }
    });
    for _ in 0..3 {
        assert_eq!(c.get(&format!("http://{srv}/")).send().unwrap().text().unwrap(), "bye");
        std::thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(conns.load(Ordering::SeqCst), 3);
}

#[test]
fn keepalive_pings_idle_connections() {
    let pings = Arc::new(AtomicUsize::new(0));
    let conns = Arc::new(AtomicUsize::new(0));
    let p2 = pings.clone();
    let srv = h2_server_full(conns, Some(p2), |conn, ev| {
        if let Ev::Headers(id) = ev {
            conn.send_response(id, 200, &[], false).unwrap();
            conn.send_data(id, b"ok", true).unwrap();
        }
    });
    let c = Client::builder().version(HttpVersion::Http2).keepalive_interval(Some(Duration::from_millis(100))).keepalive_timeout(Duration::from_secs(2)).build();
    assert_eq!(c.get(&format!("http://{srv}/")).send().unwrap().text().unwrap(), "ok");
    std::thread::sleep(Duration::from_millis(700));
    assert!(pings.load(Ordering::SeqCst) >= 2, "pings: {}", pings.load(Ordering::SeqCst));
    assert_eq!(c.get(&format!("http://{srv}/")).send().unwrap().text().unwrap(), "ok");
    assert_eq!(c.pool_stats().multiplexed, 1);
}

#[test]
fn keepalive_closes_a_dead_connection() {
    // A server that accepts h2 and then stops answering anything.
    let silent = raw(|mut s, _| {
        let mut conn = Connection::server(Config::default());
        let mut buf = vec![0u8; 65536];
        let mut answered = false;
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            let Ok(n) = s.read(&mut buf) else { return };
            if n == 0 {
                return;
            }
            if answered {
                continue; // swallow PINGs
            }
            let mut req = None;
            conn.recv(&buf[..n], 0, &mut |ev| {
                if let Event::Headers { stream, .. } = ev {
                    req = Some(stream);
                }
            });
            if let Some(id) = req {
                conn.send_response(id, 200, &[], false).unwrap();
                conn.send_data(id, b"ok", true).unwrap();
                answered = true;
            }
            let out = conn.output().to_vec();
            conn.advance_output(out.len());
            s.write_all(&out).unwrap();
        }
    });
    let c = Client::builder().version(HttpVersion::Http2).keepalive_interval(Some(Duration::from_millis(50))).keepalive_timeout(Duration::from_millis(200)).build();
    assert_eq!(c.get(&format!("http://{}/", silent.addr)).send().unwrap().text().unwrap(), "ok");
    let end = Instant::now() + Duration::from_secs(5);
    while c.pool_stats().multiplexed > 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(c.pool_stats().multiplexed, 0, "the unanswered PING closed the connection");
}

#[test]
fn http2_required_but_server_speaks_http1() {
    let h = secure();
    let srv = raw(|mut s, _| {
        let _ = common::read_head(&mut s);
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
    });
    let _ = h;
    // h2c to an HTTP/1.1-only server fails cleanly
    let e = Client::builder().version(HttpVersion::Http2).read_timeout(Some(Duration::from_secs(2))).build().get(&format!("http://{}/", srv.addr)).send().unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Protocol | ErrorKind::Closed), "{e}");
}

// ---------------------------------------------------------------------- an h2 test server

enum Ev {
    Headers(u32),
    Data(u32, Vec<u8>, bool),
}

fn h2_server(f: impl Fn(&mut Connection, Ev) + Send + Sync + 'static) -> std::net::SocketAddr {
    h2_server_with(Arc::new(AtomicUsize::new(0)), f)
}

fn h2_server_with(conns: Arc<AtomicUsize>, f: impl Fn(&mut Connection, Ev) + Send + Sync + 'static) -> std::net::SocketAddr {
    h2_server_full(conns, None, f)
}

fn h2_server_full(conns: Arc<AtomicUsize>, pings: Option<Arc<AtomicUsize>>, f: impl Fn(&mut Connection, Ev) + Send + Sync + 'static) -> std::net::SocketAddr {
    let f = Arc::new(f);
    let r = raw(move |s: TcpStream, _| {
        conns.fetch_add(1, Ordering::SeqCst);
        let f = f.clone();
        let mut s = s;
        let mut conn = Connection::server(Config::default());
        let mut buf = vec![0u8; 65536];
        let mut pending: Vec<u8> = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        loop {
            let n = match s.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            pending.extend_from_slice(&buf[..n]);
            if let Some(p) = &pings {
                // count PING frames (type 6, not ACK) in what arrived
                let mut i = 0;
                let d = &buf[..n];
                while i + 9 <= d.len() {
                    let len = ((d[i] as usize) << 16) | ((d[i + 1] as usize) << 8) | d[i + 2] as usize;
                    if d[i + 3] == 6 && d[i + 4] & 1 == 0 {
                        p.fetch_add(1, Ordering::SeqCst);
                    }
                    i += 9 + len;
                }
            }
            let mut evs = Vec::new();
            let used = conn.recv(&pending, 0, &mut |ev| match ev {
                Event::Headers { stream, end_stream, .. } => {
                    evs.push(Ev::Headers(stream));
                    if end_stream {
                        evs.push(Ev::Data(stream, Vec::new(), true));
                    }
                }
                Event::Data { stream, data, end_stream } => evs.push(Ev::Data(stream, data.to_vec(), end_stream)),
                _ => {}
            });
            pending.drain(..used);
            for ev in evs {
                if let Ev::Data(id, d, _) = &ev {
                    conn.release(*id, d.len());
                }
                f(&mut conn, ev);
            }
            let out = conn.output().to_vec();
            conn.advance_output(out.len());
            if s.write_all(&out).is_err() {
                return;
            }
            if conn.wants_close() {
                std::thread::sleep(Duration::from_millis(20));
                return;
            }
        }
    });
    r.addr
}

#[test]
fn client_certificates() {
    use simoom_tls::certgen::{issue, CertParams};
    use simoom_tls::keys::{EcCurve, PrivateKey};
    use simoom_tls::{ClientAuth, CertifiedKey};
    let ca = issue(&CertParams::ca("test client CA"), PrivateKey::generate_ec(EcCurve::P256), None);
    let client_cert = issue(&CertParams::client("client-1"), PrivateKey::generate_ec(EcCurve::P256), Some(&ca));
    let mut client_roots = simoom_client::tls::RootStore::empty();
    client_roots.add_der(&ca.cert_der).unwrap();
    let mut sc = common::server_config();
    sc.client_auth = ClientAuth::Required(client_roots);
    let h = simoom::Server::builder().listen_tls("127.0.0.1:0").tls(sc).threads(1).service(common::service).start().unwrap();
    let u = format!("https://localhost:{}/echo", h.local_addr().port());
    let opts = TlsOptions { roots: common::roots(), client_cert: Some(CertifiedKey::new(vec![client_cert.cert_der.clone(), ca.cert_der.clone()], client_cert.key.clone()).unwrap()), ..TlsOptions::default() };
    let c = Client::builder().tls(opts).build();
    for v in [HttpVersion::Http1, HttpVersion::Http2] {
        let r = c.get(&u).version(v).send().unwrap();
        assert_eq!(r.status(), 200);
    }
    // without a certificate the handshake (or the first read) fails
    let e = client().build().get(&u).version(HttpVersion::Http1).send().unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Tls | ErrorKind::Closed), "{e}");
}

/// The default trust store is not empty: bundle files on Unix, the certificate store on
/// Windows (`simoom_sys::certstore`).
#[test]
fn system_roots_are_loaded() {
    let n = simoom_client::tls::RootStore::system().len();
    assert!(n > 5, "{n} system roots");
}

#[cfg(feature = "h2c-upgrade")]
#[test]
fn h2c_through_upgrade() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).h2c_upgrade(true).build();
    for _ in 0..3 {
        let r = c.get(&url(&h, "/echo")).send().unwrap();
        assert_eq!(r.version(), Version::Http2);
        assert!(r.text().unwrap().starts_with("H2 GET /echo"));
    }
    assert_eq!(c.pool_stats().multiplexed, 1);
    // a server without h2c answers the probe over HTTP/1.1: the client stays there
    let srv = raw(|mut s, _| {
        while let Some(head) = common::read_head(&mut s) {
            let body = if head.starts_with("OPTIONS *") { "" } else { "plain" };
            s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
        }
    });
    let r = c.get(&format!("http://{}/", srv.addr)).send().unwrap();
    assert_eq!(r.version(), Version::Http11);
    assert_eq!(r.text().unwrap(), "plain");
}

#[test]
fn more_connections_past_a_stream_threshold() {
    let h = plain();
    let c = client().version(HttpVersion::Http2).streams_per_connection(Some(2)).max_multiplexed_per_origin(4).build();
    // warm one connection first so the threshold decides, not the race to connect
    c.get(&url(&h, "/echo")).send().unwrap().bytes().unwrap();
    let ts: Vec<_> = (0..8)
        .map(|i| {
            let (c, u) = (c.clone(), url(&h, "/slow?ms=300"));
            std::thread::sleep(Duration::from_millis(10 * i));
            std::thread::spawn(move || c.get(&u).send().unwrap().text().unwrap())
        })
        .collect();
    for t in ts {
        assert_eq!(t.join().unwrap(), "slow done");
    }
    let n = c.pool_stats().multiplexed;
    assert!((2..=8).contains(&n), "{n} connections");
}
