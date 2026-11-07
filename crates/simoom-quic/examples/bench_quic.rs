//! Transport CPU cost through the in-memory network (both endpoints on one thread, zero
//! link delay, so wall time is the CPU of client + server + the simulator).
//!
//! `cargo run --release -p simoom-quic --example bench_quic [requests] [bulk_mb]`

use simoom_quic::crypto::null::NullProvider;
use simoom_quic::sim::{Link, Pair};
use simoom_quic::tls::TlsProvider;
use simoom_quic::{ConnHandle, Config, CryptoProvider};
use simoom_tls::certgen::{self, CertParams};
use simoom_tls::keys::{EcCurve, PrivateKey};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn link() -> Link {
    Link { delay: Duration::ZERO, mtu: 1500, ..Link::default() }
}

fn providers(real: bool) -> (Arc<dyn CryptoProvider>, Arc<dyn CryptoProvider>) {
    if !real {
        return (Arc::new(NullProvider::new(1)), Arc::new(NullProvider::new(2)));
    }
    let ss = certgen::issue(&CertParams::server(&["localhost"]), PrivateKey::generate_ec(EcCurve::P256), None);
    let ck = simoom_tls::CertifiedKey::new(vec![ss.cert_der.clone()], ss.key.clone()).unwrap();
    let s = TlsProvider::server(Arc::new(simoom_tls::ServerConfig::new(ck).with_alpn(&[b"h3"])));
    let mut roots = simoom_tls::x509::RootStore::empty();
    roots.add_der(&ss.cert_der).unwrap();
    let c = TlsProvider::client(Arc::new(simoom_tls::ClientConfig::new(roots).with_alpn(&[b"h3"])));
    (Arc::new(c), Arc::new(s))
}

fn pair(real: bool) -> (Pair, ConnHandle, ConnHandle) {
    let (cp, sp) = providers(real);
    let mut c = Config::new(cp);
    let mut s = Config::new(sp);
    for x in [&mut c, &mut s] {
        x.transport.max_data = 16 << 20;
        x.transport.stream_window_bidi_local = 8 << 20;
        x.transport.stream_window_bidi_remote = 8 << 20;
        x.transport.send_buffer = 8 << 20;
    }
    let mut p = Pair::new(Arc::new(c), Arc::new(s), link(), 7);
    p.batch = 16;
    let ch = p.connect();
    assert!(p.run_until(Duration::from_secs(10), |p| p.client.conn(ch).is_some_and(|c| c.is_established())
        && p.server_conn().and_then(|s| p.server.conn(s)).is_some_and(|c| c.is_established())));
    let sh = p.server_conn().unwrap();
    p.run_for(Duration::from_millis(50));
    (p, ch, sh)
}

/// `n` request/response exchanges of `size` bytes each way, `conc` in flight.
fn small(real: bool, n: usize, size: usize, conc: usize) -> f64 {
    let (mut p, c, s) = pair(real);
    let req = vec![7u8; size];
    let mut buf = vec![0u8; 65536];
    let mut open: Vec<(u64, usize)> = Vec::new(); // (stream, bytes received back)
    let mut started = 0;
    let mut done = 0;
    let mut server_got: std::collections::HashMap<u64, usize> = Default::default();
    let t = Instant::now();
    while done < n {
        while open.len() < conc && started < n {
            let Ok(id) = p.client.conn_mut(c).unwrap().open_bi() else { break };
            p.client.conn_mut(c).unwrap().stream_send(id, &req, true).unwrap();
            open.push((id, 0));
            started += 1;
        }
        p.step();
        // Server: read requests, answer when complete.
        while let Some(e) = p.server.poll_event(s) {
            if let simoom_quic::Event::StreamReadable(id) = e {
                let conn = p.server.conn_mut(s).unwrap();
                while let Ok((k, fin)) = conn.stream_recv(id, &mut buf) {
                    *server_got.entry(id).or_default() += k;
                    if fin {
                        server_got.remove(&id);
                        conn.stream_send(id, &req, true).unwrap();
                        break;
                    }
                    if k == 0 {
                        break;
                    }
                }
            }
        }
        while let Some(e) = p.client.poll_event(c) {
            if let simoom_quic::Event::StreamReadable(id) = e {
                let conn = p.client.conn_mut(c).unwrap();
                while let Ok((k, fin)) = conn.stream_recv(id, &mut buf) {
                    if let Some(o) = open.iter_mut().find(|o| o.0 == id) {
                        o.1 += k;
                    }
                    if fin {
                        open.retain(|o| o.0 != id);
                        done += 1;
                        break;
                    }
                    if k == 0 {
                        break;
                    }
                }
            }
        }
    }
    let us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    let pk = p.client.conn(c).unwrap().stats().sent_packets + p.server.conn(s).unwrap().stats().sent_packets;
    eprintln!("    ({n} exchanges, {:.2} packets per exchange)", pk as f64 / n as f64);
    us
}

/// One stream of `mb` MiB client to server; returns MB/s.
fn bulk(real: bool, mb: usize) -> (f64, u64) {
    let (mut p, c, s) = pair(real);
    let chunk = vec![1u8; 256 << 10];
    let total = mb << 20;
    let id = p.client.conn_mut(c).unwrap().open_uni().unwrap();
    let mut sent = 0;
    let mut got = 0;
    let mut buf = vec![0u8; 256 << 10];
    let t = Instant::now();
    while got < total {
        if sent < total {
            let conn = p.client.conn_mut(c).unwrap();
            let want = (total - sent).min(chunk.len());
            if let Ok(k) = conn.stream_send(id, &chunk[..want], sent + want == total) {
                sent += k;
            }
        }
        p.step();
        if let Some(conn) = p.server.conn_mut(s) {
            while let Ok((k, fin)) = conn.stream_recv(id, &mut buf) {
                got += k;
                if fin || k == 0 {
                    break;
                }
            }
        }
        while p.server.poll_event(s).is_some() {}
        while p.client.poll_event(c).is_some() {}
    }
    let secs = t.elapsed().as_secs_f64();
    (total as f64 / secs / 1e6, p.client.conn(c).unwrap().stats().lost_packets)
}

fn main() {
    let args: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let n = args.first().copied().unwrap_or(50_000);
    let mb = args.get(1).copied().unwrap_or(200);
    for real in [false, true] {
        let name = if real { "TLS 1.3 (AES-128-GCM)" } else { "null crypto" };
        let seq = small(real, n / 5, 100, 1);
        let par = small(real, n, 100, 32);
        let (tp, lost) = bulk(real, mb);
        println!("{name}:");
        println!("  request/response, 100 B each way, 1 in flight:  {seq:6.2} us per exchange (client + server + sim)");
        println!("  request/response, 100 B each way, 32 in flight: {par:6.2} us per exchange");
        println!("  bulk, one stream, {mb} MiB:                       {tp:7.1} MB/s (lost {lost})");
    }
}
