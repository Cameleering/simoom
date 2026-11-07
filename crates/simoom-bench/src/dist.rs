//! Several load nodes running one test together.
//!
//! An **agent** (`simoom-bench agent --listen 10.0.0.5:7070`) waits for a coordinator. The
//! **coordinator** (any `load` or `sweep` with `--agents a:7070,b:7070,c:7070`) splits the
//! connections and the rate across the agents and talks a line protocol to each:
//!
//! ```text
//! -> RUN <spec as key=value words>       agent opens its connections
//! <- READY connected=<n>                 (or ERROR <message>)
//! -> GO <delay_ms>                       sent to every agent at once, after all are READY
//! <- REPORT ... / HIST ... / LAG ... / INTERVAL ... / END
//! ```
//!
//! Each agent times from its own monotonic clock, so only the GO messages' skew (a network
//! round trip, well under a millisecond in one VPC) separates the nodes' windows. The
//! coordinator merges the histograms bucket by bucket (they share HdrHistogram's layout), so
//! merged percentiles are exact, not averages of percentiles.

use crate::load::{self, Report, Spec};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Serves coordinators one at a time, forever.
pub fn agent(listen: &str) -> Result<(), String> {
    let l = TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    eprintln!("simoom-bench agent listening on {}", l.local_addr().map_err(|e| e.to_string())?);
    for s in l.incoming() {
        let Ok(s) = s else { continue };
        if let Err(e) = serve_one(s) {
            eprintln!("agent: {e}");
        }
    }
    Ok(())
}

fn serve_one(s: TcpStream) -> Result<(), String> {
    let _ = s.set_nodelay(true);
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Ok(());
        }
        let l = line.trim_end();
        if l == "PING" {
            writeln!(w, "PONG").map_err(|e| e.to_string())?;
            continue;
        }
        let Some(kv) = l.strip_prefix("RUN ") else {
            writeln!(w, "ERROR expected RUN").map_err(|e| e.to_string())?;
            continue;
        };
        let spec = match Spec::from_kv(kv) {
            Ok(s) => s,
            Err(e) => {
                writeln!(w, "ERROR {e}").map_err(|e| e.to_string())?;
                continue;
            }
        };
        eprintln!("agent: {} conns to {} at {} req/s", spec.conns, spec.addr, spec.rate);
        let p = match load::prepare(spec) {
            Ok(p) => p,
            Err(e) => {
                writeln!(w, "ERROR {e}").map_err(|e| e.to_string())?;
                continue;
            }
        };
        writeln!(w, "READY connected={}", p.connected()).map_err(|e| e.to_string())?;
        line.clear();
        r.read_line(&mut line).map_err(|e| e.to_string())?;
        let delay = line.trim().strip_prefix("GO ").and_then(|d| d.parse().ok()).unwrap_or(100u64);
        let rep = p.go(Duration::from_millis(delay));
        w.write_all(rep.to_wire().as_bytes()).map_err(|e| e.to_string())?;
    }
}

/// Splits `spec` over `n` agents: connections as evenly as possible, rate in proportion.
pub fn split(spec: &Spec, n: usize) -> Vec<Spec> {
    let mut out = Vec::new();
    for i in 0..n {
        let conns = spec.conns / n + usize::from(i < spec.conns % n);
        let mut s = spec.clone();
        s.conns = conns.max(1);
        s.rate = spec.rate * conns as f64 / spec.conns.max(1) as f64;
        s.seed = spec.seed.wrapping_add(i as u64 * 0x1000_0000);
        out.push(s);
    }
    out
}

/// Runs `spec` across `agents` and merges the reports. The per-node reports are returned too.
pub fn run(agents: &[String], spec: &Spec) -> Result<(Report, Vec<Report>), String> {
    let parts = split(spec, agents.len());
    let mut conns = Vec::new();
    for (a, part) in agents.iter().zip(&parts) {
        let s = TcpStream::connect(a).map_err(|e| format!("agent {a}: {e}"))?;
        let _ = s.set_nodelay(true);
        let w = s.try_clone().map_err(|e| e.to_string())?;
        let mut w = w;
        writeln!(w, "RUN {}", part.to_kv()).map_err(|e| format!("agent {a}: {e}"))?;
        conns.push((a.clone(), w, BufReader::new(s)));
    }
    let ready_timeout = Duration::from_secs(300);
    for (a, _, r) in conns.iter_mut() {
        r.get_ref().set_read_timeout(Some(ready_timeout)).ok();
        let mut line = String::new();
        r.read_line(&mut line).map_err(|e| format!("agent {a}: {e}"))?;
        if !line.starts_with("READY") {
            return Err(format!("agent {a}: {}", line.trim()));
        }
    }
    for (a, w, _) in conns.iter_mut() {
        writeln!(w, "GO 300").map_err(|e| format!("agent {a}: {e}"))?;
    }
    let run_timeout = spec.warmup + spec.duration + spec.drain + Duration::from_secs(120);
    let mut merged = Report::default();
    let mut nodes = Vec::new();
    for (a, _, r) in conns.iter_mut() {
        r.get_ref().set_read_timeout(Some(run_timeout)).ok();
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).map_err(|e| format!("agent {a}: {e}"))? == 0 {
                return Err(format!("agent {a} closed the connection"));
            }
            let end = line.trim_end() == "END";
            lines.push(line.trim_end().to_string());
            if end {
                break;
            }
        }
        let rep = Report::from_wire(lines.iter().map(|s| s.as_str()))?;
        merged.merge(&rep);
        nodes.push(rep);
    }
    merged.window_s = spec.duration.as_secs_f64();
    Ok((merged, nodes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_totals() {
        let s = Spec { conns: 1000, rate: 300_000.0, ..Spec::default() };
        let p = split(&s, 3);
        assert_eq!(p.iter().map(|x| x.conns).sum::<usize>(), 1000);
        let r: f64 = p.iter().map(|x| x.rate).sum();
        assert!((r - 300_000.0).abs() < 1e-6);
        assert_ne!(p[0].seed, p[1].seed);
    }

    #[test]
    fn spec_round_trips_through_kv() {
        let s = Spec {
            conns: 7,
            rate: 1234.5,
            body: b"{\"a\":1}".to_vec(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            method: "POST".into(),
            path: "/echo".into(),
            cpus: Some(vec![1, 3]),
            ..Spec::default()
        };
        let t = Spec::from_kv(&s.to_kv()).unwrap();
        assert_eq!((t.conns, t.rate, t.body, t.headers, t.method, t.path, t.cpus), (s.conns, s.rate, s.body, s.headers, s.method, s.path, s.cpus));
    }
}
