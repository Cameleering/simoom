//! Full-duplex calls on HTTP/2 and HTTP/3: send and receive body bytes at the same time, with
//! trailers both ways (what gRPC needs).

use crate::error::{Error, ErrorKind, Result, TimeoutKind};
use crate::mux::Mux;
use crate::types::Headers;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The sending half of a [`Call`], usable from another thread.
#[derive(Clone)]
pub struct CallSender {
    mux: Arc<Mux>,
    id: u64,
    write_timeout: Option<Duration>,
}

impl std::fmt::Debug for CallSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallSender").field("stream", &self.id).finish()
    }
}

impl CallSender {
    fn deadline(&self) -> Option<Instant> {
        self.write_timeout.map(|t| Instant::now() + t)
    }

    /// Sends body bytes, waiting for flow-control credit.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.mux.write(self.id, data, false, self.deadline())
    }

    /// Ends the request body.
    pub fn finish(&self) -> Result<()> {
        self.mux.write(self.id, &[], true, self.deadline())
    }

    /// Ends the request body with trailers.
    pub fn finish_with_trailers(&self, trailers: &[(&str, &str)]) -> Result<()> {
        let t: Vec<(Vec<u8>, Vec<u8>)> = trailers.iter().map(|(n, v)| (n.to_ascii_lowercase().into_bytes(), v.as_bytes().to_vec())).collect();
        self.mux.send_trailers(self.id, &t)
    }

    /// Cancels the call (RST_STREAM CANCEL / STOP_SENDING).
    pub fn cancel(&self) {
        self.mux.finish(self.id);
    }
}

/// A full-duplex call. Created by [`crate::Client::call`]. Dropping it cancels the stream if
/// it has not finished.
pub struct Call {
    sender: CallSender,
    head: Option<(u16, Headers)>,
    trailers: Option<Headers>,
    read_timeout: Option<Duration>,
    done: bool,
    on_head: Option<HeadHook>,
}

/// A hook run once on the response head.
pub(crate) type HeadHook = Box<dyn FnOnce(u16, &Headers) -> Result<()> + Send>;

impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call").field("stream", &self.sender.id).field("head", &self.head).finish()
    }
}

impl Call {
    pub(crate) fn new(mux: Arc<Mux>, id: u64, read_timeout: Option<Duration>, write_timeout: Option<Duration>) -> Call {
        Call { sender: CallSender { mux, id, write_timeout }, head: None, trailers: None, read_timeout, done: false, on_head: None }
    }

    /// Runs `f` once with the response head when it arrives (interceptors); an error from it is
    /// returned by [`Call::response`].
    pub(crate) fn on_head(&mut self, f: HeadHook) {
        self.on_head = Some(f);
    }

    /// A sender for another thread.
    pub fn sender(&self) -> CallSender {
        self.sender.clone()
    }

    /// Sends body bytes.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.sender.send(data)
    }

    /// Ends the request body.
    pub fn finish(&self) -> Result<()> {
        self.sender.finish()
    }

    /// Ends the request body with trailers.
    pub fn finish_with_trailers(&self, trailers: &[(&str, &str)]) -> Result<()> {
        self.sender.finish_with_trailers(trailers)
    }

    /// Waits for the response head: status and headers.
    pub fn response(&mut self) -> Result<(u16, &Headers)> {
        self.response_until(self.read_timeout.map(|t| Instant::now() + t))
    }

    /// Waits for the response head until `deadline`.
    pub fn response_until(&mut self, deadline: Option<Instant>) -> Result<(u16, &Headers)> {
        if self.head.is_none() {
            let h = self.sender.mux.head(self.sender.id, deadline, TimeoutKind::ResponseHead)?;
            if let Some(f) = self.on_head.take() {
                f(h.0, &h.1)?;
            }
            self.head = Some(h);
        }
        let (s, h) = self.head.as_ref().ok_or_else(|| Error::new(ErrorKind::Closed, "no response"))?;
        Ok((*s, h))
    }

    /// Reads response body bytes (after the head); `Ok(0)` at the end, when
    /// [`Call::trailers`] are available.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.head.is_none() {
            self.response()?;
        }
        let d = self.read_timeout.map(|t| Instant::now() + t);
        let (n, t) = self.sender.mux.read(self.sender.id, buf, d, TimeoutKind::Idle)?;
        if let Some(t) = t {
            self.done = true;
            self.trailers = Some(t);
        }
        Ok(n)
    }

    /// Like [`Call::read`], waiting at most until `deadline` for bytes.
    pub fn read_until(&mut self, buf: &mut [u8], deadline: Option<Instant>) -> Result<usize> {
        if self.done {
            return Ok(0);
        }
        let (n, t) = self.sender.mux.read(self.sender.id, buf, deadline, TimeoutKind::Idle)?;
        if let Some(t) = t {
            self.done = true;
            self.trailers = Some(t);
        }
        Ok(n)
    }

    /// Response trailers, after the body was read to the end.
    pub fn trailers(&self) -> Option<&Headers> {
        self.trailers.as_ref()
    }

    /// Cancels the call.
    pub fn cancel(&self) {
        self.sender.cancel();
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.sender.mux.finish(self.sender.id);
    }
}
