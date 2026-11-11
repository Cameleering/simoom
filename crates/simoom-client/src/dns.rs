//! Name resolution with a timeout, and Happy Eyeballs connection racing (RFC 8305).

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Resolves `host:port`, giving up after `timeout` (the system resolver has no timeout of its
/// own, so it runs on a helper thread; IP literals are parsed directly).
#[cfg(feature = "dns-timeout")]
pub(crate) fn resolve(host: &str, port: u16, timeout: Option<Duration>) -> Result<Vec<SocketAddr>> {
    let what = format!("{host}:{port}");
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let lookup = move |h: String| -> io::Result<Vec<SocketAddr>> { (h.as_str(), port).to_socket_addrs().map(|a| a.collect()) };
    let addrs = match timeout {
        None => lookup(host.to_string()),
        Some(t) => {
            let (tx, rx) = mpsc::channel();
            let h = host.to_string();
            std::thread::Builder::new()
                .name("simoom-client-dns".into())
                .spawn(move || {
                    let _ = tx.send(lookup(h));
                })
                .map_err(|e| Error::io(&e, &what))?;
            match rx.recv_timeout(t) {
                Ok(r) => r,
                Err(_) => return Err(Error::new(ErrorKind::Timeout(TimeoutKind::Connect), format!("name resolution timed out: {what}"))),
            }
        }
    };
    let mut addrs = addrs.map_err(|e| Error::new(ErrorKind::Connect, format!("cannot resolve {what}: {e}")))?;
    if host.eq_ignore_ascii_case("localhost") {
        addrs.sort_by_key(|a| !a.is_ipv4());
    }
    if addrs.is_empty() {
        return Err(Error::new(ErrorKind::Connect, format!("unknown host: {host}")));
    }
    Ok(addrs)
}

/// Interleaves address families, starting with the family of the first address (RFC 8305 §4).
#[cfg(feature = "happy-eyeballs")]
pub(crate) fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(|a| a.is_ipv6());
    let (mut a, mut b): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|x| x.is_ipv6() == first_v6);
    a.reverse();
    b.reverse();
    let mut out = Vec::with_capacity(a.len() + b.len());
    while !a.is_empty() || !b.is_empty() {
        if let Some(x) = a.pop() {
            out.push(x);
        }
        if let Some(x) = b.pop() {
            out.push(x);
        }
    }
    out
}

#[cfg(feature = "happy-eyeballs")]
fn attempt(a: SocketAddr, deadline: Option<Instant>) -> io::Result<TcpStream> {
    match deadline {
        Some(d) => match d.checked_duration_since(Instant::now()) {
            Some(t) if !t.is_zero() => TcpStream::connect_timeout(&a, t),
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "deadline")),
        },
        None => TcpStream::connect(a),
    }
}

/// Connects to the first address that answers: a new attempt starts every `delay` (or as soon
/// as one fails) while earlier ones are still running (RFC 8305 §5). With one address it is a
/// plain connect.
#[cfg(feature = "happy-eyeballs")]
pub(crate) fn connect(addrs: Vec<SocketAddr>, deadline: Option<Instant>, delay: Duration) -> io::Result<TcpStream> {
    let addrs = interleave(addrs);
    if addrs.len() == 1 {
        return attempt(addrs[0], deadline);
    }
    let (tx, rx) = mpsc::channel::<io::Result<TcpStream>>();
    let mut next = 0;
    let mut running = 0;
    let mut last: Option<io::Error> = None;
    loop {
        if next < addrs.len() {
            let (a, tx) = (addrs[next], tx.clone());
            next += 1;
            running += 1;
            let spawned = std::thread::Builder::new().name("simoom-client-connect".into()).spawn(move || {
                let _ = tx.send(attempt(a, deadline));
            });
            if let Err(e) = spawned {
                running -= 1;
                last = Some(e);
                continue;
            }
        }
        if running == 0 {
            return Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")));
        }
        // wait for an answer, or the delay before the next attempt
        let wait = if next < addrs.len() { delay } else { deadline.map_or(Duration::from_secs(3600), |d| d.saturating_duration_since(Instant::now())) };
        match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                running -= 1;
                last = Some(e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if next >= addrs.len() && deadline.is_some_and(|d| Instant::now() >= d) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "happy-eyeballs")]
    #[test]
    fn families_alternate() {
        let a: Vec<SocketAddr> = ["[::1]:1", "[::2]:1", "127.0.0.1:1", "127.0.0.2:1"].iter().map(|s| s.parse().unwrap()).collect();
        let o = interleave(a);
        assert_eq!(o.iter().map(|x| x.is_ipv6()).collect::<Vec<_>>(), vec![true, false, true, false]);
    }

    #[cfg(feature = "happy-eyeballs")]
    #[test]
    fn a_dead_first_address_does_not_block_the_next() {
        // a listener that never accepts would still complete the handshake; use a refused port
        // first and a live one second
        let live = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let t = Instant::now();
        let s = connect(vec![dead, live.local_addr().unwrap()], Some(Instant::now() + Duration::from_secs(5)), Duration::from_millis(250)).unwrap();
        assert_eq!(s.peer_addr().unwrap(), live.local_addr().unwrap());
        assert!(t.elapsed() < Duration::from_secs(3));
    }

    #[cfg(feature = "dns-timeout")]
    #[test]
    fn ip_literals_skip_the_resolver() {
        assert_eq!(resolve("127.0.0.1", 80, Some(Duration::from_millis(1))).unwrap()[0].port(), 80);
        assert_eq!(resolve("[::1]", 80, None).unwrap()[0].is_ipv6(), true);
    }
}
