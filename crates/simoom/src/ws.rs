//! WebSocket connections after [`crate::Reply::websocket`]: RFC 6455 over HTTP/1.1, and RFC 8441
//! (extended CONNECT) over HTTP/2. The handler runs on the loop thread; [`WsHandle`] reaches it
//! from other threads.
//!
//! [`WsCore`] is the protocol-independent part (frames, messages, the closing handshake); the
//! HTTP/1.1 connection runs it as a [`Layer`] ([`WsLayer`]), the HTTP/2 connection on one stream.

use crate::conn::{Io, Layer};
use crate::handle::{Envelope, Msg, Route};
use crate::server::Shared;
use simoom_http1::ws::{self as codec, FrameDecoder, Opcode, Role, WsEvent, WsLimits};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// A complete message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsMessage<'a> {
    /// A text message (valid UTF-8).
    Text(&'a str),
    /// A binary message.
    Binary(&'a [u8]),
}

/// Handles one WebSocket connection, on its loop thread. Must not block.
pub trait WebSocketHandler: 'static {
    /// The upgrade completed.
    fn on_open(&mut self, ws: &mut WebSocket<'_>) {
        let _ = ws;
    }
    /// A whole message arrived (fragments are joined; pings are answered automatically).
    fn on_message(&mut self, ws: &mut WebSocket<'_>, msg: WsMessage<'_>);
    /// The connection is closing: the peer's close code (1005 when it sent none, 1006 when the
    /// connection was lost).
    fn on_close(&mut self, code: u16, reason: &str) {
        let _ = (code, reason);
    }
}

/// Commands from a [`WsHandle`].
pub(crate) enum WsCmd {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Close(u16, String),
}

/// The connection, inside a [`WebSocketHandler`] callback.
pub struct WebSocket<'w> {
    out: &'w mut Vec<u8>,
    closing: &'w mut bool,
    route: &'w Route,
    conn: u64,
    token: u64,
    deflate: &'w mut Deflate,
}

/// The permessage-deflate codec of a WebSocket, when negotiated (feature `ws-deflate`).
#[cfg(feature = "ws-deflate")]
pub(crate) type Deflate = Option<simoom_http1::ws::deflate::PerMessage>;
#[cfg(not(feature = "ws-deflate"))]
pub(crate) type Deflate = ();

/// Writes one data message, compressed when the extension is on and it is worth it.
#[inline]
fn write_message(out: &mut Vec<u8>, deflate: &mut Deflate, op: Opcode, payload: &[u8]) {
    #[cfg(feature = "ws-deflate")]
    if let Some(d) = deflate {
        if d.worth(payload.len()) {
            let c = d.compress(payload);
            codec::write_frame_compressed(out, true, op, &c, None);
            return;
        }
    }
    let _ = deflate;
    codec::write_frame(out, true, op, payload, None);
}

/// The `sec-websocket-extensions` answer and the codec for a client's offers (`None, None`
/// without the feature, the server option, or an acceptable offer).
#[allow(unused_variables)]
pub(crate) fn negotiate_deflate(sh: &Shared, offers: Option<&[u8]>) -> (Option<String>, Deflate) {
    #[cfg(feature = "ws-deflate")]
    {
        use simoom_http1::ws::deflate::{negotiate, PerMessage, Side};
        if let (Some(cfg), Some(o)) = (&sh.ws_deflate, offers) {
            if let Some((p, resp)) = negotiate(o, cfg) {
                return (Some(resp), Some(PerMessage::new(Side::Server, &p, cfg)));
            }
        }
        (None, None)
    }
    #[cfg(not(feature = "ws-deflate"))]
    (None, ())
}

impl std::fmt::Debug for WebSocket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocket").field("closing", &*self.closing).finish()
    }
}

impl WebSocket<'_> {
    /// Sends a text message.
    pub fn send_text(&mut self, text: &str) {
        if !*self.closing {
            write_message(self.out, self.deflate, Opcode::Text, text.as_bytes());
        }
    }

    /// Sends a binary message.
    pub fn send_binary(&mut self, data: &[u8]) {
        if !*self.closing {
            write_message(self.out, self.deflate, Opcode::Binary, data);
        }
    }

    /// Sends a ping (at most 125 bytes).
    pub fn ping(&mut self, data: &[u8]) {
        if !*self.closing && data.len() <= 125 {
            codec::write_frame(self.out, true, Opcode::Ping, data, None);
        }
    }

    /// Starts the closing handshake with `code` (for example 1000) and `reason`.
    pub fn close(&mut self, code: u16, reason: &str) {
        if !*self.closing {
            *self.closing = true;
            if !codec::write_close(self.out, code, reason, None) {
                codec::write_close(self.out, 1000, "", None);
            }
        }
    }

    /// True once a close was sent.
    pub fn is_closing(&self) -> bool {
        *self.closing
    }

    /// A handle to send from other threads.
    pub fn handle(&self) -> WsHandle {
        WsHandle { route: self.route.clone(), conn: self.conn, token: self.token }
    }
}

/// Sends on a WebSocket from any thread. Messages to a closed connection are dropped.
#[derive(Clone, Debug)]
pub struct WsHandle {
    route: Route,
    /// The HTTP/3 connection (0 otherwise).
    conn: u64,
    /// 0 on HTTP/1.1; the stream id on HTTP/2 and HTTP/3.
    token: u64,
}

impl WsHandle {
    fn cmd(&self, c: WsCmd) -> bool {
        self.route.send(self.conn, self.token, Msg::Ws(c))
    }
    /// Sends a text message.
    pub fn send_text(&self, text: impl Into<String>) -> bool {
        self.cmd(WsCmd::Text(text.into()))
    }
    /// Sends a binary message.
    pub fn send_binary(&self, data: impl Into<Vec<u8>>) -> bool {
        self.cmd(WsCmd::Binary(data.into()))
    }
    /// Sends a ping.
    pub fn ping(&self, data: impl Into<Vec<u8>>) -> bool {
        self.cmd(WsCmd::Ping(data.into()))
    }
    /// Closes the connection.
    pub fn close(&self, code: u16, reason: impl Into<String>) -> bool {
        self.cmd(WsCmd::Close(code, reason.into()))
    }
}

/// What a [`WsCore`] call produced: bytes to send, and whether the transport (the HTTP/1.1
/// connection, or the HTTP/2 stream) should end.
pub(crate) struct WsIo {
    pub(crate) out: Vec<u8>,
    pub(crate) close: bool,
    /// A handler callback panicked (a close 1011 went out).
    pub(crate) panicked: bool,
    pub(crate) now: u64,
    pub(crate) route: Route,
    pub(crate) conn: u64,
    pub(crate) token: u64,
}

impl WsIo {
    pub(crate) fn new(route: Route, conn: u64, token: u64, now: u64) -> WsIo {
        WsIo { out: Vec::new(), close: false, panicked: false, now, route, conn, token }
    }
}

/// One WebSocket: the frame decoder, the message being assembled, and the closing handshake.
pub(crate) struct WsCore {
    handler: Box<dyn WebSocketHandler>,
    dec: FrameDecoder,
    inbuf: Vec<u8>,
    msg: Vec<u8>,
    text: bool,
    max: u64,
    closing: bool,
    /// When our close frame went out (0: not yet): the peer has a few seconds to answer.
    close_sent_at: u64,
    done: bool,
    notified: bool,
    deflate: Deflate,
    /// The current message is compressed.
    compressed: bool,
}

/// How long to wait for the peer's close frame after ours.
const CLOSE_WAIT_NS: u64 = 5_000_000_000;

impl WsCore {
    pub(crate) fn new(handler: Box<dyn WebSocketHandler>, max_message: u64, deflate: Deflate) -> WsCore {
        let limits = WsLimits { max_frame: max_message, max_message };
        let dec = FrameDecoder::new(Role::Server, limits);
        #[cfg(feature = "ws-deflate")]
        let dec = {
            let mut dec = dec;
            dec.set_permessage_deflate(deflate.is_some());
            dec
        };
        WsCore { handler, dec, inbuf: Vec::new(), msg: Vec::new(), text: false, max: max_message, closing: false, close_sent_at: 0, done: false, notified: false, deflate, compressed: false }
    }

    /// Runs a handler callback with a [`WebSocket`] writing into the output.
    fn with_ws(&mut self, w: &mut WsIo, f: impl FnOnce(&mut dyn WebSocketHandler, &mut WebSocket<'_>)) {
        let ok = {
            let mut ws = WebSocket { out: &mut w.out, closing: &mut self.closing, route: &w.route, conn: w.conn, token: w.token, deflate: &mut self.deflate };
            catch_unwind(AssertUnwindSafe(|| f(&mut *self.handler, &mut ws))).is_ok()
        };
        if !ok {
            w.panicked = true;
            self.fail(w, 1011);
        }
        self.note_close(w);
    }

    fn note_close(&mut self, w: &WsIo) {
        if self.closing && self.close_sent_at == 0 {
            self.close_sent_at = w.now.max(1);
        }
    }

    fn fail(&mut self, w: &mut WsIo, code: u16) {
        if !self.closing {
            self.closing = true;
            codec::write_close(&mut w.out, code, "", None);
        }
        self.finish(code, "");
        w.close = true;
    }

    fn finish(&mut self, code: u16, reason: &str) {
        self.done = true;
        if !self.notified {
            self.notified = true;
            let h = &mut self.handler;
            let _ = catch_unwind(AssertUnwindSafe(|| h.on_close(code, reason)));
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    pub(crate) fn start(&mut self, w: &mut WsIo) {
        self.with_ws(w, |h, ws| h.on_open(ws));
    }

    pub(crate) fn input(&mut self, w: &mut WsIo, data: &[u8]) {
        if self.done {
            return;
        }
        self.inbuf.extend_from_slice(data);
        let mut pos = 0;
        loop {
            let mut buf = std::mem::take(&mut self.inbuf);
            let r = self.dec.decode(&mut buf[pos..]);
            let step = match r {
                Err(e) => {
                    self.inbuf = buf;
                    self.fail(w, e.close_code());
                    return;
                }
                Ok((n, ev)) => {
                    pos += n;
                    match ev {
                        WsEvent::NeedMore => None,
                        WsEvent::Data { text, payload, fin } => {
                            if self.msg.is_empty() {
                                self.text = text;
                                self.compressed = self.dec.message_compressed();
                            }
                            if (self.msg.len() + payload.len()) as u64 > self.max {
                                Some(Err(1009))
                            } else {
                                self.msg.extend_from_slice(payload);
                                Some(Ok(fin))
                            }
                        }
                        WsEvent::Ping(p) => {
                            if !self.closing {
                                codec::write_frame(&mut w.out, true, Opcode::Pong, p, None);
                            }
                            Some(Ok(false))
                        }
                        WsEvent::Pong(_) => Some(Ok(false)),
                        WsEvent::Close { code, reason } => {
                            let reason = reason.to_string();
                            if !self.closing {
                                self.closing = true;
                                codec::write_close(&mut w.out, code.unwrap_or(1000), "", None);
                            }
                            self.inbuf = buf;
                            self.finish(code.unwrap_or(1005), &reason);
                            w.close = true;
                            return;
                        }
                    }
                }
            };
            self.inbuf = buf;
            match step {
                None => break,
                Some(Err(code)) => {
                    self.fail(w, code);
                    return;
                }
                Some(Ok(true)) => {
                    let msg = std::mem::take(&mut self.msg);
                    let text = self.text;
                    #[cfg(feature = "ws-deflate")]
                    let msg = if self.compressed {
                        let mut plain = Vec::new();
                        let r = match &mut self.deflate {
                            Some(d) => d.decompress(&msg, &mut plain),
                            None => Err(simoom_http1::ws::WsError::ReservedBits),
                        };
                        let r = r.and_then(|_| if text && std::str::from_utf8(&plain).is_err() { Err(simoom_http1::ws::WsError::InvalidUtf8) } else { Ok(()) });
                        if let Err(e) = r {
                            self.fail(w, e.close_code());
                            return;
                        }
                        plain
                    } else {
                        msg
                    };
                    self.with_ws(w, |h, ws| {
                        let m = if text { WsMessage::Text(std::str::from_utf8(&msg).unwrap_or("")) } else { WsMessage::Binary(&msg) };
                        h.on_message(ws, m);
                    });
                    let mut msg = msg;
                    msg.clear();
                    self.msg = msg;
                    if self.done {
                        return;
                    }
                }
                Some(Ok(false)) => {}
            }
        }
        self.inbuf.drain(..pos);
    }

    pub(crate) fn command(&mut self, w: &mut WsIo, cmd: WsCmd) {
        if self.closing {
            return;
        }
        match cmd {
            WsCmd::Text(t) => write_message(&mut w.out, &mut self.deflate, Opcode::Text, t.as_bytes()),
            WsCmd::Binary(b) => write_message(&mut w.out, &mut self.deflate, Opcode::Binary, &b),
            WsCmd::Ping(p) if p.len() <= 125 => codec::write_frame(&mut w.out, true, Opcode::Ping, &p, None),
            WsCmd::Ping(_) => {}
            WsCmd::Close(code, reason) => {
                self.closing = true;
                if !codec::write_close(&mut w.out, code, &reason, None) {
                    codec::write_close(&mut w.out, 1000, "", None);
                }
            }
        }
        self.note_close(w);
    }

    /// The transport ended without a closing handshake.
    pub(crate) fn eof(&mut self, w: &mut WsIo) {
        self.finish(1006, "");
        w.close = true;
    }

    /// The server is stopping: close 1001.
    pub(crate) fn stop(&mut self, w: &mut WsIo) {
        if !self.closing {
            self.closing = true;
            codec::write_close(&mut w.out, 1001, "", None);
        }
        self.finish(1001, "");
        w.close = true;
    }

    pub(crate) fn tick(&mut self, w: &mut WsIo) {
        if self.close_sent_at != 0 && w.now >= self.close_sent_at + CLOSE_WAIT_NS {
            self.finish(1006, "");
            w.close = true;
        }
    }

    pub(crate) fn deadline(&self) -> u64 {
        if self.close_sent_at != 0 && !self.done {
            self.close_sent_at + CLOSE_WAIT_NS
        } else {
            u64::MAX
        }
    }

    pub(crate) fn closed(&mut self) {
        self.finish(1006, "");
    }
}

impl Drop for WsCore {
    fn drop(&mut self) {
        // however the stream or connection went away, the handler hears about it once
        self.finish(1006, "");
    }
}

/// A WebSocket on an HTTP/1.1 connection, after the `101`.
pub(crate) struct WsLayer {
    core: WsCore,
}

impl WsLayer {
    pub(crate) fn new(handler: Box<dyn WebSocketHandler>, max_message: u64, deflate: Deflate) -> WsLayer {
        WsLayer { core: WsCore::new(handler, max_message, deflate) }
    }

    fn run(&mut self, io: &mut Io<'_, '_>, f: impl FnOnce(&mut WsCore, &mut WsIo)) {
        let mut w = WsIo::new(Route::Conn(io.cx.handle()), 0, 0, io.now);
        f(&mut self.core, &mut w);
        if !w.out.is_empty() {
            io.write(&w.out);
        }
        if w.panicked {
            crate::server::bump(&io.sh.counters(io.li).panics);
        }
        if w.close {
            io.close = true;
        }
    }
}

impl Layer for WsLayer {
    fn start(&mut self, io: &mut Io<'_, '_>) {
        self.run(io, |c, w| c.start(w));
    }

    fn input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize {
        if !self.core.is_done() {
            self.run(io, |c, w| c.input(w, data));
        }
        data.len()
    }

    fn message(&mut self, io: &mut Io<'_, '_>, env: Envelope) {
        let Msg::Ws(cmd) = env.msg else { return };
        self.run(io, |c, w| c.command(w, cmd));
    }

    fn eof(&mut self, io: &mut Io<'_, '_>) {
        self.run(io, |c, w| c.eof(w));
    }

    fn stop(&mut self, io: &mut Io<'_, '_>) {
        self.run(io, |c, w| c.stop(w));
    }

    fn tick(&mut self, io: &mut Io<'_, '_>) {
        if io.now >= self.core.deadline() {
            self.run(io, |c, w| c.tick(w));
        }
    }

    fn deadline(&self, _now: u64, _sh: &Shared) -> u64 {
        self.core.deadline()
    }

    fn wants_pause(&self) -> bool {
        false
    }

    fn closed(&mut self) {
        self.core.closed();
    }
}
