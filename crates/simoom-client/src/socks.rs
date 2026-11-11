//! SOCKS5 proxies (RFC 1928) with username/password authentication (RFC 1929).
//!
//! `socks5://` resolves the target name locally and sends the address; `socks5h://` sends the
//! name and lets the proxy resolve it.

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::proxy::ProxyAddr;
use crate::transport::{is_timeout, remaining};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::time::Instant;

fn err(proxy: &ProxyAddr, msg: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Proxy, format!("SOCKS5 proxy {}:{}: {msg}", proxy.host, proxy.port))
}

fn read_exact(tcp: &TcpStream, buf: &mut [u8], deadline: Option<Instant>, proxy: &ProxyAddr) -> Result<()> {
    let what = format!("SOCKS5 proxy {}:{}", proxy.host, proxy.port);
    let mut off = 0;
    while off < buf.len() {
        let _ = tcp.set_read_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
        match (&*tcp).read(&mut buf[off..]) {
            Ok(0) => return Err(err(proxy, "closed the connection")),
            Ok(n) => off += n,
            Err(e) if is_timeout(&e) => return Err(Error::timeout(TimeoutKind::Connect, &what)),
            Err(e) => return Err(Error::io(&e, &what)),
        }
    }
    Ok(())
}

/// Asks the SOCKS5 proxy on `tcp` to connect to `host:port`. `remote_dns` sends the name
/// (`socks5h`); otherwise the name is resolved here and the address is sent.
pub(crate) fn connect(tcp: &TcpStream, host: &str, port: u16, proxy: &ProxyAddr, remote_dns: bool, deadline: Option<Instant>) -> Result<()> {
    let what = format!("SOCKS5 proxy {}:{}", proxy.host, proxy.port);
    let _ = tcp.set_write_timeout(remaining(deadline, TimeoutKind::Connect, &what)?);
    let creds = proxy.credentials.as_deref().map(|c| c.split_once(':').unwrap_or((c, "")));
    let greeting: &[u8] = if creds.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    (&*tcp).write_all(greeting).map_err(|e| Error::io(&e, &what))?;
    let mut r = [0u8; 2];
    read_exact(tcp, &mut r, deadline, proxy)?;
    if r[0] != 5 {
        return Err(err(proxy, "not a SOCKS5 server"));
    }
    match r[1] {
        0 => {}
        2 => {
            let (u, p) = creds.ok_or_else(|| err(proxy, "asks for credentials, none configured"))?;
            if u.len() > 255 || p.len() > 255 {
                return Err(err(proxy, "user name or password longer than 255 bytes"));
            }
            let mut m = vec![1, u.len() as u8];
            m.extend_from_slice(u.as_bytes());
            m.push(p.len() as u8);
            m.extend_from_slice(p.as_bytes());
            (&*tcp).write_all(&m).map_err(|e| Error::io(&e, &what))?;
            read_exact(tcp, &mut r, deadline, proxy)?;
            if r[1] != 0 {
                return Err(err(proxy, "refused the credentials"));
            }
        }
        0xff => return Err(err(proxy, "accepts none of our authentication methods")),
        m => return Err(err(proxy, format!("chose an unknown method {m}"))),
    }
    let mut req = vec![5, 1, 0];
    let addr: Option<IpAddr> = host.parse().ok().or_else(|| if remote_dns { None } else { crate::transport::resolve(host, port).ok().and_then(|a| a.first().map(|s| s.ip())) });
    match addr {
        Some(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Some(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        None => {
            if host.len() > 255 {
                return Err(err(proxy, "host name longer than 255 bytes"));
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    (&*tcp).write_all(&req).map_err(|e| Error::io(&e, &what))?;
    let mut h = [0u8; 4];
    read_exact(tcp, &mut h, deadline, proxy)?;
    if h[1] != 0 {
        let why = match h[1] {
            1 => "general failure",
            2 => "connection not allowed by ruleset",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        };
        return Err(err(proxy, format!("refused CONNECT {host}:{port}: {why}")));
    }
    let rest = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            read_exact(tcp, &mut l, deadline, proxy)?;
            l[0] as usize + 2
        }
        _ => return Err(err(proxy, "sent an invalid reply")),
    };
    let mut skip = vec![0u8; rest];
    read_exact(tcp, &mut skip, deadline, proxy)
}
