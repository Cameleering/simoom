//! Cold start: the time from spawning a server process to its first successful response.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// One GET; true on a 2xx status.
fn probe(addr: SocketAddr, path: &str) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else { return false };
    let _ = s.set_nodelay(true);
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    let mut n = 0;
    while n < 12 {
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => return false,
            Ok(k) => n += k,
        }
    }
    &buf[..5] == b"HTTP/" && buf[9] == b'2'
}

/// Spawns `cmd` `repeat` times; returns each time to the first 2xx in milliseconds. With
/// `ready`, the probing starts once the child printed that line on standard output (on
/// Windows a connect to a port nobody listens on yet takes hundreds of milliseconds to fail,
/// which would hide the start-up time).
pub fn measure(addr: SocketAddr, path: &str, cmd: &[String], repeat: usize, timeout: Duration, ready: Option<&str>) -> Result<Vec<f64>, String> {
    let (prog, args) = cmd.split_first().ok_or("no command")?;
    let mut out = Vec::new();
    for _ in 0..repeat {
        // the port must be free first
        let wait = Instant::now();
        while TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            if wait.elapsed() > Duration::from_secs(10) {
                return Err(format!("{addr} is still answering before the start"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let t = Instant::now();
        let mut cmd = Command::new(prog);
        cmd.args(args).stdin(Stdio::null()).stdout(if ready.is_some() { Stdio::piped() } else { Stdio::null() }).stderr(Stdio::null());
        // its own process group, so forked workers (nginx, HAProxy, H2O) are stopped with it
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let mut child = cmd.spawn().map_err(|e| format!("{prog}: {e}"))?;
        if let (Some(line), Some(out)) = (ready, child.stdout.take()) {
            use std::io::BufRead;
            let mut r = std::io::BufReader::new(out);
            let mut l = String::new();
            loop {
                l.clear();
                if r.read_line(&mut l).map_err(|e| e.to_string())? == 0 {
                    return Err(format!("{prog} closed its output before printing {line:?}"));
                }
                if l.trim_end() == line {
                    break;
                }
            }
            // keep the pipe open (the child may print more) without blocking it
            std::thread::spawn(move || std::io::copy(&mut r, &mut std::io::sink()));
        }
        let mut ok = None;
        while t.elapsed() < timeout {
            if probe(addr, path) {
                ok = Some(t.elapsed().as_secs_f64() * 1000.0);
                break;
            }
            if let Ok(Some(st)) = child.try_wait() {
                return Err(format!("{prog} exited early: {st}"));
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        #[cfg(unix)]
        let _ = Command::new("kill").args(["-9", "--", &format!("-{}", child.id())]).stderr(Stdio::null()).status();
        let _ = child.kill();
        let _ = child.wait();
        out.push(ok.ok_or_else(|| format!("{prog}: no response within {timeout:?}"))?);
    }
    Ok(out)
}
