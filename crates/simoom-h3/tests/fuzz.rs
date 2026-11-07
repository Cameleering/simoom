//! Seeded mutation fuzzing of the HTTP/3 server: request streams, control streams and
//! QPACK streams carrying mutated bytes. `SIMOOM_FUZZ_ITERS` and `SIMOOM_FUZZ_SEED` tune it.

mod common;
use common::*;
use simoom_h3::{Config as H3Config, Settings};
use simoom_quic::coding::put_varint;
use simoom_quic::sim::{Link, Rng};
use std::time::Duration;

fn iters(default: u64) -> u64 {
    std::env::var("SIMOOM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn seed() -> u64 {
    std::env::var("SIMOOM_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0xf00d)
}

fn mutate(rng: &mut Rng, d: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(3) {
        let len = d.len().max(1) as u64;
        match rng.below(6) {
            0 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                d[i] = [0x00, 0x01, 0x04, 0x07, 0x3f, 0x40, 0x80, 0xc0, 0xff][rng.below(9) as usize];
            }
            2 => d.truncate(rng.below(len + 1) as usize),
            3 => {
                let i = rng.below(len + 1) as usize;
                for _ in 0..1 + rng.below(6) {
                    d.insert(i.min(d.len()), rng.next() as u8);
                }
            }
            4 if !d.is_empty() => {
                let i = rng.below(len) as usize;
                let n = (1 + rng.below(8) as usize).min(d.len() - i);
                d.drain(i..i + n);
            }
            _ => {
                let i = rng.below(len) as usize;
                let n = (1 + rng.below(16) as usize).min(d.len().saturating_sub(i));
                let s = d[i..i + n].to_vec();
                d.extend_from_slice(&s);
            }
        }
    }
}

fn request_bytes(id: u64, dynamic: Option<&mut simoom_qpack::Encoder>) -> (Vec<u8>, Vec<u8>) {
    let mut fresh = simoom_qpack::Encoder::new();
    let enc = dynamic.unwrap_or(&mut fresh);
    let mut req = get("/fuzz");
    req.push((b"content-length".to_vec(), b"5".to_vec()));
    let mut block = Vec::new();
    enc.encode(id, &refs(&req), &mut block);
    let mut b = Vec::new();
    put_varint(&mut b, 0x01);
    put_varint(&mut b, block.len() as u64);
    b.extend_from_slice(&block);
    b.extend_from_slice(&[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let mut block = Vec::new();
    enc.encode(id, &[(b"x-trailer", b"1")], &mut block);
    put_varint(&mut b, 0x01);
    put_varint(&mut b, block.len() as u64);
    b.extend_from_slice(&block);
    let mut es = Vec::new();
    enc.take_encoder_stream(&mut es);
    (b, es)
}

#[test]
fn fuzz_server_streams() {
    let mut rng = Rng::new(seed());
    let total = iters(3000);
    let mut done = 0;
    let mut conns = 0;
    while done < total {
        conns += 1;
        let mut h = H3Pair::new(Link::default(), conns, None, H3Config::default());
        // Control stream: valid SETTINGS, sometimes mutated.
        let mut ctl = vec![0x00];
        Settings { qpack_max_table_capacity: Some(4096), qpack_blocked_streams: Some(8), ..Default::default() }.encode(&mut ctl);
        if rng.below(8) == 0 {
            mutate(&mut rng, &mut ctl);
        }
        let conn = h.cconn();
        let c = conn.open_uni().unwrap();
        let _ = conn.stream_send(c, &ctl, false);
        // An encoder stream for dynamic-table requests.
        let e = conn.open_uni().unwrap();
        let _ = conn.stream_send(e, &[0x02], false);
        let mut enc = simoom_qpack::Encoder::with_dynamic_table(4096);
        enc.set_peer_settings(4096, 8);
        for _ in 0..50 {
            done += 1;
            let conn = h.cconn();
            let Ok(id) = conn.open_bi() else { break };
            let use_dyn = rng.below(2) == 0;
            let (mut b, es) = request_bytes(id, if use_dyn { Some(&mut enc) } else { None });
            mutate(&mut rng, &mut b);
            let fin = rng.below(4) != 0;
            let _ = conn.stream_send(id, &b, fin);
            if !es.is_empty() {
                let mut es = es;
                if rng.below(10) == 0 {
                    mutate(&mut rng, &mut es);
                }
                // Encoder-stream bytes sometimes arrive late (blocked streams).
                let _ = conn.stream_send(e, &es, false);
            }
            if rng.below(10) == 0 {
                let _ = conn.stream_reset(id, 0x10c);
            }
            h.run_for(Duration::from_millis(5));
            // Drain whatever the server reports; it must never panic.
            h.sev.clear();
            if h.p.client.conn(h.c).is_none_or(|c| c.is_closed()) {
                break;
            }
        }
        h.run_for(Duration::from_millis(200));
        if let Some(s) = h.server.as_ref() {
            assert!(s.active_streams() <= 200);
        }
    }
}

#[test]
fn fuzz_settings_and_validation() {
    let mut rng = Rng::new(seed() ^ 1);
    let mut base = Vec::new();
    Settings { qpack_max_table_capacity: Some(1), max_field_section_size: Some(2), qpack_blocked_streams: Some(3) }.encode(&mut base);
    for _ in 0..iters(50_000) {
        let mut d = base[2..].to_vec();
        mutate(&mut rng, &mut d);
        let _ = Settings::decode(&d);
        let fields: Vec<simoom_h3::Field> = (0..rng.below(6))
            .map(|_| {
                let mut n = [&b":method"[..], b":path", b":scheme", b":authority", b"content-length", b"te", b"x"][rng.below(7) as usize].to_vec();
                let mut v = b"GET".to_vec();
                mutate(&mut rng, &mut n);
                mutate(&mut rng, &mut v);
                simoom_h3::Field::new(n, v)
            })
            .collect();
        let _ = simoom_h3::validate_request(&fields);
        let _ = simoom_h3::validate_response(&fields);
    }
}
