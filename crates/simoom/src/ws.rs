//! WebSocket connections (RFC 6455) after [`crate::Reply::websocket`]: the handler runs on the
//! loop thread; [`WsHandle`] reaches it from other threads.

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
    route: &'w dyn Fn() -> Route,
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
            codec::write_frame(self.out, true, Opcode::Text, text.as_bytes(), None);
        }
    }

    /// Sends a binary message.
    pub fn send_binary(&mut self, data: &[u8]) {
        if !*self.closing {
            codec::write_frame(self.out, true, Opcode::Binary, data, None);
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
        WsHandle { route: (self.route)() }
    }
}

/// Sends on a WebSocket from any thread. Messages to a closed connection are dropped.
#[derive(Clone, Debug)]
pub struct WsHandle {
    route: Route,
}

impl WsHandle {
    fn cmd(&self, c: WsCmd) -> bool {
        self.route.send(0, 0, Msg::Ws(c))
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

pub(crate) struct WsLayer {
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
}

/// How long to wait for the peer's close frame after ours.
const CLOSE_WAIT_NS: u64 = 5_000_000_000;

impl WsLayer {
    pub(crate) fn new(handler: Box<dyn WebSocketHandler>, max_message: u64) -> WsLayer {
        let limits = WsLimits { max_frame: max_message, max_message };
        WsLayer { handler, dec: FrameDecoder::new(Role::Server, limits), inbuf: Vec::new(), msg: Vec::new(), text: false, max: max_message, closing: false, close_sent_at: 0, done: false, notified: false }
    }

    /// Runs a handler callback with a [`WebSocket`] writing into the connection output.
    fn with_ws(&mut self, io: &mut Io<'_, '_>, f: impl FnOnce(&mut dyn WebSocketHandler, &mut WebSocket<'_>)) {
        let mut out = Vec::new();
        let route_cx = io.cx.handle();
        let route = move || Route::Conn(route_cx.clone());
        let ok = {
            let mut ws = WebSocket { out: &mut out, closing: &mut self.closing, route: &route };
            catch_unwind(AssertUnwindSafe(|| f(&mut *self.handler, &mut ws))).is_ok()
        };
        io.write(&out);
        if !ok {
            crate::server::bump(&io.sh.counters(io.li).panics);
            self.fail(io, 1011);
        }
        self.note_close(io);
    }

    fn note_close(&mut self, io: &Io<'_, '_>) {
        if self.closing && self.close_sent_at == 0 {
            self.close_sent_at = io.now.max(1);
        }
    }

    fn fail(&mut self, io: &mut Io<'_, '_>, code: u16) {
        if !self.closing {
            self.closing = true;
            let mut out = Vec::with_capacity(4);
            codec::write_close(&mut out, code, "", None);
            io.write(&out);
        }
        self.finish(code, "");
        io.close = true;
    }

    fn finish(&mut self, code: u16, reason: &str) {
        self.done = true;
        if !self.notified {
            self.notified = true;
            let h = &mut self.handler;
            let _ = catch_unwind(AssertUnwindSafe(|| h.on_close(code, reason)));
        }
    }
}

impl Layer for WsLayer {
    fn start(&mut self, io: &mut Io<'_, '_>) {
        self.with_ws(io, |h, ws| h.on_open(ws));
    }

    fn input(&mut self, io: &mut Io<'_, '_>, data: &[u8]) -> usize {
        if self.done {
            return data.len();
        }
        self.inbuf.extend_from_slice(data);
        let mut pos = 0;
        loop {
            let mut buf = std::mem::take(&mut self.inbuf);
            let r = self.dec.decode(&mut buf[pos..]);
            let step = match r {
                Err(e) => {
                    self.inbuf = buf;
                    self.fail(io, e.close_code());
                    return data.len();
                }
                Ok((n, ev)) => {
                    pos += n;
                    match ev {
                        WsEvent::NeedMore => None,
                        WsEvent::Data { text, payload, fin } => {
                            if self.msg.is_empty() {
                                self.text = text;
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
                                let mut out = Vec::with_capacity(p.len() + 2);
                                codec::write_frame(&mut out, true, Opcode::Pong, p, None);
                                io.write(&out);
                            }
                            Some(Ok(false))
                        }
                        WsEvent::Pong(_) => Some(Ok(false)),
                        WsEvent::Close { code, reason } => {
                            let reason = reason.to_string();
                            if !self.closing {
                                self.closing = true;
                                let mut out = Vec::with_capacity(4);
                                codec::write_close(&mut out, code.unwrap_or(1000), "", None);
                                io.write(&out);
                            }
                            self.inbuf = buf;
                            self.finish(code.unwrap_or(1005), &reason);
                            io.close = true;
                            return data.len();
                        }
                    }
                }
            };
            self.inbuf = buf;
            match step {
                None => break,
                Some(Err(code)) => {
                    self.fail(io, code);
                    return data.len();
                }
                Some(Ok(true)) => {
                    let msg = std::mem::take(&mut self.msg);
                    let text = self.text;
                    self.with_ws(io, |h, ws| {
                        let m = if text { WsMessage::Text(std::str::from_utf8(&msg).unwrap_or("")) } else { WsMessage::Binary(&msg) };
                        h.on_message(ws, m);
                    });
                    let mut msg = msg;
                    msg.clear();
                    self.msg = msg;
                    if self.done {
                        return data.len();
                    }
                }
                Some(Ok(false)) => {}
            }
        }
        self.inbuf.drain(..pos);
        data.len()
    }

    fn message(&mut self, io: &mut Io<'_, '_>, env: Envelope) {
        let Msg::Ws(cmd) = env.msg else { return };
        if self.closing {
            return;
        }
        let mut out = Vec::new();
        match cmd {
            WsCmd::Text(t) => codec::write_frame(&mut out, true, Opcode::Text, t.as_bytes(), None),
            WsCmd::Binary(b) => codec::write_frame(&mut out, true, Opcode::Binary, &b, None),
            WsCmd::Ping(p) if p.len() <= 125 => codec::write_frame(&mut out, true, Opcode::Ping, &p, None),
            WsCmd::Ping(_) => {}
            WsCmd::Close(code, reason) => {
                self.closing = true;
                if !codec::write_close(&mut out, code, &reason, None) {
                    codec::write_close(&mut out, 1000, "", None);
                }
            }
        }
        io.write(&out);
        self.note_close(io);
    }

    fn eof(&mut self, io: &mut Io<'_, '_>) {
        self.finish(1006, "");
        io.close = true;
    }

    fn stop(&mut self, io: &mut Io<'_, '_>) {
        if !self.closing {
            self.closing = true;
            let mut out = Vec::with_capacity(4);
            codec::write_close(&mut out, 1001, "", None);
            io.write(&out);
        }
        self.finish(1001, "");
        io.close = true;
    }

    fn tick(&mut self, io: &mut Io<'_, '_>) {
        if self.close_sent_at != 0 && io.now >= self.close_sent_at + CLOSE_WAIT_NS {
            self.finish(1006, "");
            io.close = true;
        }
    }

    fn deadline(&self, _now: u64, _sh: &Shared) -> u64 {
        if self.close_sent_at != 0 {
            self.close_sent_at + CLOSE_WAIT_NS
        } else {
            u64::MAX
        }
    }

    fn wants_pause(&self) -> bool {
        false
    }

    fn closed(&mut self) {
        self.finish(1006, "");
    }
}
