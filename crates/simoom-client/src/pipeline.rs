//! HTTP/1.1 pipelining (RFC 9112 §9.3.2), opt-in through [`Client::pipeline`].
//!
//! Requests are written back to back on one connection before their responses are read, which
//! saves a round trip per request on high-latency links. Only idempotent methods are accepted
//! (GET, HEAD, OPTIONS, TRACE, PUT, DELETE), with in-memory bodies: if the server closes the
//! connection part way, the requests it did not answer are sent again on a new connection,
//! which is safe only for idempotent requests. Bodies of the responses are read whole.

use crate::body::{Inner as BodyInner, Response, ResponseBody};
use crate::client::Client;
use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::h1::Out;
use crate::types::{Body, Request};
use simoom_http1::{BodyDecoder, Framing};
use std::sync::Arc;
use std::time::Instant;

fn idempotent(m: &str) -> bool {
    matches!(m, "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE")
}

impl Client {
    /// Sends `reqs` pipelined on one HTTP/1.1 connection to their common origin and returns
    /// the responses in order, bodies read. Every request must be idempotent and have an
    /// in-memory body (or none), and all must go to the same origin; otherwise each result is
    /// an [`ErrorKind::InvalidRequest`] error. Redirects are not followed; status checks
    /// (`ok_status`) apply per response. Unanswered requests are retried on a new connection
    /// (at most twice per request).
    pub fn pipeline(&self, reqs: Vec<Request>) -> Vec<Result<Response>> {
        let n = reqs.len();
        if n == 0 {
            return Vec::new();
        }
        let first = reqs[0].url.origin();
        let bad = reqs.iter().find_map(|r| {
            if !idempotent(&r.method) {
                Some(format!("pipelining needs idempotent methods, not {}", r.method))
            } else if !r.body.replayable() {
                Some("pipelining needs in-memory bodies".to_string())
            } else if r.url.origin() != first {
                Some("pipelined requests must share one origin".to_string())
            } else if r.url.is_secure() && !cfg!(feature = "tls") {
                Some("https needs the `tls` feature".to_string())
            } else {
                None
            }
        });
        if let Some(m) = bad {
            return (0..n).map(|_| Err(Error::new(ErrorKind::InvalidRequest, m.clone()))).collect();
        }
        let mut reqs = reqs;
        let mut out: Vec<Option<Result<Response>>> = (0..n).map(|_| None).collect();
        let mut tries = vec![0u8; n];
        let mut next = 0;
        while next < n {
            match self.pipeline_once(&mut reqs[next..]) {
                Ok(done) => {
                    let got = done.len();
                    for (i, r) in done.into_iter().enumerate() {
                        let r = match (&reqs[next + i].ok_status).as_ref().or(self.config().ok_status.as_ref()) {
                            Some(ranges) => r.and_then(|resp| resp.error_for_status(ranges)),
                            None => r,
                        };
                        out[next + i] = Some(r);
                    }
                    next += got;
                    if got == 0 {
                        // nothing answered on a fresh connection: give up on the next request
                        tries[next] += 1;
                        if tries[next] > 2 {
                            out[next] = Some(Err(Error::new(ErrorKind::Closed, format!("the server closed every connection before answering: {}", reqs[next].url))));
                            next += 1;
                        }
                    }
                }
                Err(e) => {
                    for o in out.iter_mut().skip(next) {
                        *o = Some(Err(e.clone()));
                    }
                    break;
                }
            }
        }
        out.into_iter().map(|o| o.unwrap_or_else(|| Err(Error::new(ErrorKind::Closed, "not sent")))).collect()
    }

    /// One connection: writes every request, reads responses until the connection ends.
    /// Returns the responses obtained (a prefix of `reqs`).
    fn pipeline_once(&self, reqs: &mut [Request]) -> Result<Vec<Result<Response>>> {
        let cfg = self.config();
        let url = reqs[0].url.clone();
        let deadline = cfg.timeout.map(|t| Instant::now() + t);
        let mut conn = self.connect_h1_raw(&url, deadline)?;
        let mut buf = Vec::with_capacity(256 * reqs.len());
        for r in reqs.iter() {
            let headers = self.headers_for(r);
            let o = Out {
                method: &r.method,
                url: &r.url,
                absolute: conn.absolute,
                headers: &headers,
                extra: &[],
                proxy_auth: None,
                expect_continue: false,
                expect_timeout: cfg.expect_timeout,
                idle: cfg.read_timeout,
                close: false,
            };
            crate::h1::H1Conn::write_head(&o, &r.body, &mut buf)?;
            if let Body::Bytes(b) = &r.body {
                buf.extend_from_slice(b);
            }
        }
        conn.io.write_all(&buf).map_err(|e| Error::io(&e, &url))?;
        let mut done = Vec::new();
        for r in reqs.iter() {
            conn.idle = cfg.read_timeout;
            let head = match conn.read_head(&r.method, deadline, &r.url) {
                Ok(h) => h,
                Err(e) if e.kind == ErrorKind::Closed => return Ok(done),
                Err(e) if matches!(e.kind, ErrorKind::Timeout(TimeoutKind::ResponseHead)) => {
                    done.push(Err(e));
                    return Ok(done);
                }
                Err(e) => {
                    done.push(Err(e));
                    return Ok(done);
                }
            };
            let mut body = Vec::new();
            let mut trailers = None;
            if head.framing != Framing::None && !head.upgraded {
                let mut dec = BodyDecoder::new(head.framing, &crate::h1::limits(cfg.max_head));
                loop {
                    match conn.read_body_vec(&mut dec, &mut body, &mut trailers, cfg.read_timeout, deadline, &r.url) {
                        Ok(0) if trailers.is_some() => break,
                        Ok(_) => {}
                        Err(e) => {
                            done.push(Err(e));
                            return Ok(done);
                        }
                    }
                }
            }
            let mut rb = ResponseBody::new(BodyInner::Bytes(body, 0), cfg.max_body);
            rb.set_trailers(trailers);
            done.push(Ok(Response { status: head.status, version: head.version, reason: head.reason, headers: head.headers, url: Arc::new(r.url.clone()), body: rb }));
            if !head.keep_alive {
                return Ok(done);
            }
        }
        Ok(done)
    }
}
