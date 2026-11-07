//! The raw responder: the simoom runtime with the thinnest HTTP/1.1 framing on top, to measure
//! the runtime's ceiling against other servers (the "do-nothing" side of plan §6.3). Unlike the
//! `simoom-rt` `raw_http` example it binds any address and frames request bodies, so it serves
//! the S1 fixed reply (`GET`, 13 bytes) and the S3 echo (`POST`, the body back).
//!
//! It is not the simoom server: no header validation, no limits beyond the runtime's input cap.

use simoom_rt::{Backend, ConnInfo, Connection, Ctx, Runtime};
use std::net::SocketAddr;

const FIXED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";

/// Frames the request at the front of `d`: `(total length, body range)`, or `None` if incomplete.
/// `Err` on a request the responder cannot frame.
pub fn frame_request(d: &[u8]) -> Result<Option<(usize, usize, usize)>, ()> {
    let mut i = 0;
    let head = loop {
        let Some(p) = d[i..].iter().position(|&b| b == b'\r') else { return Ok(None) };
        let at = i + p;
        if at + 4 > d.len() {
            return Ok(None);
        }
        if &d[at..at + 4] == b"\r\n\r\n" {
            break at + 4;
        }
        i = at + 1;
    };
    let mut clen = 0usize;
    for line in d[..head].split(|&b| b == b'\n').skip(1) {
        if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
            let v = std::str::from_utf8(&line[15..]).map_err(|_| ())?.trim();
            clen = v.parse().map_err(|_| ())?;
        } else if line.len() > 18 && line[..18].eq_ignore_ascii_case(b"transfer-encoding:") {
            return Err(());
        }
    }
    if d.len() < head + clen {
        return Ok(None);
    }
    Ok(Some((head + clen, head, head + clen)))
}

struct Raw;

impl Connection for Raw {
    fn on_data(&mut self, cx: &mut Ctx<'_>, data: &[u8]) -> usize {
        let mut pos = 0;
        loop {
            match frame_request(&data[pos..]) {
                Ok(Some((len, b0, b1))) => {
                    if b1 > b0 {
                        let body = &data[pos + b0..pos + b1];
                        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len());
                        let mut out = cx.buffer(head.len() + body.len());
                        out.extend_from_slice(head.as_bytes());
                        out.extend_from_slice(body);
                        cx.send(out);
                    } else {
                        cx.send_static(FIXED);
                    }
                    pos += len;
                }
                Ok(None) => return pos,
                Err(()) => {
                    cx.send_static(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    cx.close();
                    return data.len();
                }
            }
        }
    }
}

/// Serves until the process is killed.
pub fn serve(addr: SocketAddr, threads: usize, backend: Backend, cpus: Option<Vec<usize>>) -> Result<(), String> {
    let rt = Runtime::builder()
        .configure(|c| {
            c.threads = threads;
            c.driver.backend = backend;
            c.listen.backlog = 65_535;
            if let Some(cpus) = cpus {
                c.pin_threads = true;
                c.cpus = Some(cpus);
            }
        })
        .listen(addr, |_: &ConnInfo| Some(Box::new(Raw) as Box<dyn Connection>))
        .start()
        .map_err(|e| format!("start: {e}"))?;
    eprintln!("simoom-bench raw: {} loops on {:?}, back end {:?}", rt.loops().len(), rt.local_addrs(), rt.backend());
    println!("READY");
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_requests_with_and_without_bodies() {
        let g = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(frame_request(g), Ok(Some((g.len(), g.len(), g.len()))));
        assert_eq!(frame_request(&g[..10]), Ok(None));
        let p = b"POST /echo HTTP/1.1\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(frame_request(p), Ok(Some((p.len(), p.len() - 2, p.len()))));
        assert_eq!(frame_request(&p[..p.len() - 1]), Ok(None));
        assert_eq!(frame_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), Err(()));
    }
}
