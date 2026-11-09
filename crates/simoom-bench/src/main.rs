//! `simoom-bench`: open-loop HTTP load generator, rate sweep, multi-node coordinator, cold-start
//! timer and HdrHistogram tools. Run `simoom-bench help` for usage.

#![forbid(unsafe_code)]

use simoom_bench::hdr::{Histogram, IntervalLog};
use simoom_bench::load::{self, Dist, Proto, Report, Spec};
use simoom_bench::{coldstart, dist, raw, sweep};
use std::time::Duration;

const USAGE: &str = "\
simoom-bench: open-loop HTTP load generator (wrk2 semantics), SLO sweep and multi-node runs

USAGE
  simoom-bench load  [target options] [load options] [--agents a:7070,b:7070] [--out PREFIX]
  simoom-bench sweep [target options] [load options] [sweep options] [--agents ...] [--out PREFIX]
  simoom-bench agent --listen ADDR:PORT
  simoom-bench raw [--addr 0.0.0.0:8080] [--threads N] [--backend B] [--cpus LIST]
                                                         the simoom-rt raw responder (GET: 13 bytes, POST: echo)
  simoom-bench coldstart --addr HOST:PORT [--path /] [--repeat 10] [--timeout 30] [--ready LINE] -- CMD ARGS...
  simoom-bench hist print FILE.hlog [--scale 1e6]       merged percentile distribution of a log
  simoom-bench hist merge OUT.hlog IN.hlog...           merge interval logs (by interval index)

TARGET
  --url http[s]://HOST:PORT/PATH or --addr HOST:PORT [--path /PATH]
  --proto h1|h2c|h2|h3           HTTP/1.1 (default), HTTP/2 prior knowledge (cleartext), HTTP/2
                                 over TLS (ALPN h2), HTTP/3 over QUIC
  --tls                          TLS 1.3 (implied by https:// and --proto h2)
  --cacert FILE                  PEM roots the server certificate must chain to (TLS, h3; the
                                 certificate is always verified)
  --sni NAME                     server name for SNI and the certificate check
  --tls-resume                   resume TLS sessions (default: a full handshake per connection)
  --new-conn                     S5: a new connection per request (Connection: close); --conns is
                                 then the number of concurrent workers per run
  --method GET|POST|...          --body-size N (a JSON document of N bytes) | --body-file F
  --header 'Name: value'         repeatable

LOAD
  --conns N          connections (default 64)          --threads N   loops (default: all CPUs)
  --cpus 0,1,2       pin loops to these CPUs (default on Linux: every allowed CPU)
  --rate R           total requests/s, open loop; 0 = closed loop (default 0)
  --dist fixed|poisson                                 inter-arrival schedule (default fixed)
  --depth N          in flight per connection: HTTP/1.1 pipelining or HTTP/2 streams (default 1)
  --batch            closed loop: send the next `depth` requests only when the whole batch is
                     answered (wrk's pipeline script, as TechEmpower runs it); default: a window
  --warmup S         seconds before the window (default 5)   --duration S   window (default 30)
  --drain S          wait for outstanding responses after the window (default 2)
  --idle             open the connections, one request each, then hold them for --duration
  --backend auto|epoll|io_uring   (default io_uring on Linux, falling back to epoll)
  --tick-us N        timer resolution (default 20)       --interval-ms N  log interval (1000)
  --ticker-us N      open loop on epoll/IOCP: wake the loops every N us so timers are not rounded
                     to milliseconds (default 20; 0 = off)
  --label 'k=v ...'  prefix for the RESULT line

ATTACK (S10, run alongside a load)
  simoom-bench attack --addr HOST:PORT [--slowloris N] [--slowread N] [--path /64k]
                      [--interval-s 10] [--duration S] [--label ...]
    slowloris: N connections that send a request head one header line per interval and
    never finish it; slow read: N connections that pipeline 16 requests for --path and read
    1 KB a second. Reopens what the server closes; prints an ATTACK line with the counts.

SWEEP (SLO throughput: highest rate with p99 <= limit, no errors, rate achieved)
  --slo-us 1000  --probe S  --step-warmup S  --step S  --point-warmup S  --point S  --steps N
  --points 0.5,0.8,0.95   fractions of the SLO throughput measured after the search (repeat a
                          fraction to measure it more than once)
  --hint RATE             expected SLO rate: try it first, then 30% above or below, then bisect
  --precision 0.02        stop when the pass/fail bracket is narrower than this fraction

OUTPUT
  One `RESULT key=value ...` line per run on stdout (latencies in microseconds; gen_cpu_pct is the
  generator's share of all CPUs, node_cpu_pct the machine's; load_node_over_60pct=1 flags a run
  where a load node passed 60%). --out PREFIX writes PREFIX.hgrm (percentile distribution in ms,
  HdrHistogram format), PREFIX.hlog (HdrHistogram interval log) and PREFIX.lag.hgrm (timer lag).
";

struct Args {
    flags: Vec<(String, String)>,
    switches: Vec<String>,
    pos: Vec<String>,
    tail: Vec<String>,
}

const SWITCHES: &[&str] = &["--idle", "--batch", "--help", "-h", "--tls", "--new-conn", "--tls-resume"];

fn parse_args(v: &[String]) -> Args {
    let mut a = Args { flags: Vec::new(), switches: Vec::new(), pos: Vec::new(), tail: Vec::new() };
    let mut i = 0;
    while i < v.len() {
        let x = &v[i];
        if x == "--" {
            a.tail = v[i + 1..].to_vec();
            break;
        }
        if x.starts_with("--") || x == "-h" {
            if let Some((k, val)) = x.split_once('=') {
                a.flags.push((k.to_string(), val.to_string()));
            } else if SWITCHES.contains(&x.as_str()) {
                a.switches.push(x.clone());
            } else {
                a.flags.push((x.clone(), v.get(i + 1).cloned().unwrap_or_default()));
                i += 1;
            }
        } else {
            a.pos.push(x.clone());
        }
        i += 1;
    }
    a
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.flags.iter().rev().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
    }
    fn all(&self, k: &str) -> Vec<&str> {
        self.flags.iter().filter(|(a, _)| a == k).map(|(_, v)| v.as_str()).collect()
    }
    fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }
    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> Result<T, String> {
        match self.get(k) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("bad value for {k}: {v}")),
        }
    }
    fn secs(&self, k: &str, default: f64) -> Result<Duration, String> {
        Ok(Duration::from_secs_f64(self.num(k, default)?))
    }
}

/// A JSON document of about `n` bytes (S3: the 1 KB POST body).
fn json_body(n: usize) -> Vec<u8> {
    let mut s = String::from("{\"id\":12345,\"name\":\"simoom-bench\",\"items\":[");
    let mut i = 0;
    while s.len() + 40 < n {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{{\"sku\":\"SKU-{i:05}\",\"qty\":{}}}", i % 7 + 1));
        i += 1;
    }
    s.push_str("],\"pad\":\"");
    while s.len() + 2 < n {
        s.push('x');
    }
    s.push_str("\"}");
    s.into_bytes()
}

fn spec_from(a: &Args) -> Result<Spec, String> {
    let mut s = Spec::default();
    let mut https = false;
    let (target, path) = if let Some(url) = a.get("--url") {
        let rest = match url.strip_prefix("https://") {
            Some(r) => {
                https = true;
                r
            }
            None => url.strip_prefix("http://").ok_or("--url must start with http:// or https://")?,
        };
        match rest.find('/') {
            Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
            None => (rest.to_string(), "/".to_string()),
        }
    } else {
        (a.get("--addr").ok_or("--url or --addr is required")?.to_string(), a.get("--path").unwrap_or("/").to_string())
    };
    s.addr = load::resolve(&target)?;
    s.host = target;
    s.path = path;
    s.proto = Proto::parse(a.get("--proto").unwrap_or("h1"))?;
    s.tls = https || a.has("--tls") || s.proto == Proto::H2;
    if s.proto == Proto::H2c && s.tls {
        s.proto = Proto::H2;
    }
    if let Some(f) = a.get("--cacert") {
        s.ca = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
    }
    s.sni = a.get("--sni").unwrap_or("").to_string();
    s.new_conn = a.has("--new-conn");
    s.slo_us = a.num("--slo-us", 1000)?;
    if a.has("--tls-resume") {
        s.headers.push(("X-Bench-Resume".into(), "1".into()));
    }
    s.method = a.get("--method").unwrap_or("GET").to_string();
    for h in a.all("--header") {
        let (k, v) = h.split_once(':').ok_or("--header must be 'Name: value'")?;
        s.headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    if let Some(n) = a.get("--body-size") {
        s.body = json_body(n.parse().map_err(|_| "bad --body-size")?);
        if !s.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
            s.headers.push(("Content-Type".into(), "application/json".into()));
        }
    }
    if let Some(f) = a.get("--body-file") {
        s.body = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
    }
    if !s.body.is_empty() && a.get("--method").is_none() {
        s.method = "POST".into();
    }
    s.conns = a.num("--conns", 64)?;
    s.threads = a.num("--threads", 0)?;
    if let Some(c) = a.get("--cpus") {
        s.cpus = Some(c.split(',').map(|x| x.trim().parse().map_err(|_| "bad --cpus")).collect::<Result<_, _>>()?);
    }
    s.rate = a.num("--rate", 0.0)?;
    s.dist = match a.get("--dist").unwrap_or("fixed") {
        "fixed" => Dist::Fixed,
        "poisson" => Dist::Poisson,
        d => return Err(format!("unknown --dist {d}")),
    };
    s.depth = a.num("--depth", a.num("--pipeline", a.num("--streams", 1)?)?)?;
    s.warmup = a.secs("--warmup", 5.0)?;
    s.duration = a.secs("--duration", 30.0)?;
    s.drain = a.secs("--drain", 2.0)?;
    s.idle = a.has("--idle");
    s.batch = a.has("--batch");
    s.backend = load::parse_backend(a.get("--backend").unwrap_or(if cfg!(target_os = "linux") { "io_uring" } else { "auto" }))?;
    s.tick = Duration::from_micros(a.num("--tick-us", 20)?);
    s.ticker = Duration::from_micros(a.num("--ticker-us", 20)?);
    s.interval = Duration::from_millis(a.num("--interval-ms", 1000)?);
    s.connect_threads = a.num("--connect-threads", 32)?;
    s.seed = a.num("--seed", 0x5eed)?;
    Ok(s)
}

fn label(a: &Args, s: &Spec) -> String {
    let mut l = a.get("--label").map(|x| format!("{x} ")).unwrap_or_default();
    l.push_str(&format!(
        "proto={}{} mode={} depth={}{} dist={} ",
        s.proto.name(),
        if s.tls && s.proto == Proto::H1 { " tls=1" } else { "" },
        if s.idle {
            "idle"
        } else if s.new_conn && s.rate > 0.0 {
            "newconn-open"
        } else if s.new_conn {
            "newconn-closed"
        } else if s.rate > 0.0 {
            "open"
        } else {
            "closed"
        },
        s.depth,
        if s.batch { " batch=1" } else { "" },
        match s.dist {
            Dist::Fixed => "fixed",
            Dist::Poisson => "poisson",
        }
    ));
    l
}

fn write_outputs(prefix: &str, r: &Report, tag: &str) -> Result<(), String> {
    let w = |p: String, t: &str| std::fs::write(&p, t).map_err(|e| format!("{p}: {e}"));
    w(format!("{prefix}{tag}.hgrm"), &r.hist.percentile_distribution(5, 1e6))?;
    w(format!("{prefix}{tag}.lag.hgrm"), &r.lag.percentile_distribution(5, 1e6))?;
    let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let mut log = IntervalLog::new(start - r.window_s, "simoom-bench latency (ns), intended-time based");
    let len = if r.intervals.len() > 1 { r.window_s / r.intervals.len() as f64 } else { r.window_s };
    for (i, h) in &r.intervals {
        log.add(None, *i as f64 * len, len, h);
    }
    w(format!("{prefix}{tag}.hlog"), log.text())
}

fn human(r: &Report) {
    let ms = |v: u64| v as f64 / 1e6;
    eprintln!(
        "  {:.0} req/s achieved (offered {:.0}), {} samples, errors {}, incomplete {}\n  latency ms: p50 {:.3}  p90 {:.3}  p99 {:.3}  p99.9 {:.3}  max {:.3}\n  generator: cpu {} of the machine, busiest loop {}, node busy {}, timer lag p99 {:.3} ms, backend {}",
        r.achieved(),
        r.spec_rate,
        r.completed,
        r.errors(),
        r.incomplete,
        ms(r.hist.percentile(50.0)),
        ms(r.hist.percentile(90.0)),
        ms(r.hist.percentile(99.0)),
        ms(r.hist.percentile(99.9)),
        ms(r.hist.max()),
        r.gen_pct_max.or(r.cpu.proc_pct).map(|x| format!("{x:.1}%")).unwrap_or("n/a".into()),
        r.thread_pct_max.or(r.cpu.max_thread_pct).map(|x| format!("{x:.1}%")).unwrap_or("n/a".into()),
        r.node_pct_max.or(r.cpu.node_pct).map(|x| format!("{x:.1}%")).unwrap_or("n/a".into()),
        ms(r.lag.percentile(99.0)),
        r.backend
    );
}

fn agents(a: &Args) -> Vec<String> {
    a.get("--agents").map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default()
}

fn run_once(agents: &[String], s: &Spec) -> Result<Report, String> {
    if agents.is_empty() {
        load::run(s.clone())
    } else {
        let (m, nodes) = dist::run(agents, s)?;
        for (i, n) in nodes.iter().enumerate() {
            eprintln!(
                "  node {i}: {:.0} req/s, node cpu {}, generator cpu {}",
                n.achieved(),
                n.cpu.node_pct.map(|x| format!("{x:.1}%")).unwrap_or("n/a".into()),
                n.cpu.proc_pct.map(|x| format!("{x:.1}%")).unwrap_or("n/a".into())
            );
        }
        Ok(m)
    }
}

fn cmd_load(a: &Args) -> Result<(), String> {
    let s = spec_from(a)?;
    let ag = agents(a);
    let r = run_once(&ag, &s)?;
    human(&r);
    println!("{}", r.result_line(&label(a, &s)));
    if let Some(p) = a.get("--out") {
        write_outputs(p, &r, "")?;
    }
    Ok(())
}

fn cmd_sweep(a: &Args) -> Result<(), String> {
    let s = spec_from(a)?;
    let ag = agents(a);
    let plan = sweep::Plan {
        p99_limit_us: a.num("--slo-us", 1000.0)?,
        probe: a.secs("--probe", 5.0)?,
        step_warmup: a.secs("--step-warmup", 3.0)?,
        step: a.secs("--step", 10.0)?,
        point_warmup: a.secs("--point-warmup", 5.0)?,
        point: a.secs("--point", 30.0)?,
        max_steps: a.num("--steps", 8)?,
        ..sweep::Plan::default()
    };
    let mut plan = plan;
    if let Some(h) = a.get("--hint") {
        plan.hint = Some(h.parse::<f64>().map_err(|_| format!("bad --hint {h}"))?);
    }
    plan.precision = a.num("--precision", plan.precision)?;
    if let Some(p) = a.get("--points") {
        plan.points = p.split(',').map(|x| x.trim().parse::<f64>().map_err(|_| format!("bad --points {p}"))).collect::<Result<_, _>>()?;
    }
    let base_label = label(a, &s);
    let out = a.get("--out").map(String::from);
    let mut runner = |sp: &Spec| run_once(&ag, sp);
    let mut emit = |tag: &str, r: &Report| {
        human(r);
        println!("{}", r.result_line(&format!("{base_label}{tag}")));
        if let (Some(p), true) = (&out, tag.starts_with("phase=point")) {
            let pct = tag.split("pct=").nth(1).unwrap_or("x").trim().replace(" idx=", "-");
            let _ = write_outputs(p, r, &format!(".p{pct}"));
        }
    };
    let o = sweep::sweep(&s, &plan, &mut runner, &mut emit)?;
    println!(
        "SLO {}slo_rps={:.0} p99_limit_us={:.0} probe_rps={:.0} capped={} conns={}",
        a.get("--label").map(|x| format!("{x} ")).unwrap_or_default(),
        o.slo_rps,
        plan.p99_limit_us,
        o.probe_rps,
        u8::from(o.capped),
        s.conns
    );
    Ok(())
}

fn cmd_coldstart(a: &Args) -> Result<(), String> {
    let addr = load::resolve(a.get("--addr").ok_or("--addr is required")?)?;
    let v = coldstart::measure(addr, a.get("--path").unwrap_or("/"), &a.tail, a.num("--repeat", 10)?, a.secs("--timeout", 30.0)?, a.get("--ready"))?;
    let mut s = v.clone();
    s.sort_by(|x, y| x.partial_cmp(y).unwrap());
    println!(
        "COLDSTART {}min_ms={:.2} median_ms={:.2} max_ms={:.2} runs={}",
        a.get("--label").map(|x| format!("{x} ")).unwrap_or_default(),
        s[0],
        s[s.len() / 2],
        s[s.len() - 1],
        s.len()
    );
    Ok(())
}

fn cmd_raw(a: &Args) -> Result<(), String> {
    let addr = load::resolve(a.get("--addr").unwrap_or("0.0.0.0:8080"))?;
    let cpus = match a.get("--cpus") {
        Some(c) => Some(c.split(',').map(|x| x.trim().parse().map_err(|_| "bad --cpus")).collect::<Result<Vec<usize>, _>>()?),
        None => None,
    };
    raw::serve(addr, a.num("--threads", 0)?, load::parse_backend(a.get("--backend").unwrap_or("auto"))?, cpus)
}

fn cmd_hist(a: &Args) -> Result<(), String> {
    match a.pos.get(1).map(String::as_str) {
        Some("print") => {
            let f = a.pos.get(2).ok_or("hist print FILE")?;
            let text = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
            let mut m = Histogram::default();
            for h in IntervalLog::parse(&text)? {
                m.merge(&h);
            }
            print!("{}", m.percentile_distribution(5, a.num("--scale", 1e6)?));
            Ok(())
        }
        Some("merge") => {
            let out = a.pos.get(2).ok_or("hist merge OUT IN...")?;
            let mut by: Vec<Histogram> = Vec::new();
            for f in &a.pos[3..] {
                let text = std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
                for (i, h) in IntervalLog::parse(&text)?.into_iter().enumerate() {
                    if by.len() <= i {
                        by.push(Histogram::default());
                    }
                    by[i].merge(&h);
                }
            }
            let mut log = IntervalLog::new(0.0, "merged by simoom-bench");
            for (i, h) in by.iter().enumerate() {
                log.add(None, i as f64, 1.0, h);
            }
            std::fs::write(out, log.text()).map_err(|e| format!("{out}: {e}"))
        }
        _ => Err("hist print|merge".into()),
    }
}

fn main() {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let a = parse_args(&v);
    let r = match a.pos.first().map(String::as_str) {
        Some("load") => cmd_load(&a),
        Some("sweep") => cmd_sweep(&a),
        Some("agent") => dist::agent(a.get("--listen").unwrap_or("0.0.0.0:7070")),
        Some("coldstart") => cmd_coldstart(&a),
        Some("raw") => cmd_raw(&a),
        Some("attack") => simoom_bench::attack::run(
            a.get("--addr").ok_or_else(|| "--addr is required".to_string()).and_then(load::resolve).unwrap_or_else(|e| {
                eprintln!("simoom-bench: {e}");
                std::process::exit(1)
            }),
            a.get("--addr").unwrap_or(""),
            a.num("--slowloris", 0usize).unwrap_or(0),
            a.num("--slowread", 0usize).unwrap_or(0),
            a.get("--path").unwrap_or("/64k"),
            Duration::from_secs_f64(a.num("--interval-s", 10.0).unwrap_or(10.0)),
            Duration::from_secs_f64(a.num("--duration", 60.0).unwrap_or(60.0)),
            a.get("--label").unwrap_or(""),
        ),
        Some("hist") => cmd_hist(&a),
        Some("version") => {
            println!("simoom-bench {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            print!("{USAGE}");
            Ok(())
        }
    };
    if let Err(e) = r {
        eprintln!("simoom-bench: {e}");
        std::process::exit(1);
    }
}
