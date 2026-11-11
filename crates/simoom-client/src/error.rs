//! Errors.

use std::fmt;
use std::io;

/// Which timeout ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutKind {
    /// The TCP (or QUIC) connection was not established in time.
    Connect,
    /// The TLS handshake did not finish in time.
    Tls,
    /// No response head arrived in time after the request was sent.
    ResponseHead,
    /// No bytes arrived for longer than the idle (socket read) timeout.
    Idle,
    /// The whole request, redirects included, took longer than its deadline.
    Total,
    /// No pooled connection became free in time.
    Pool,
}

/// What went wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The URL could not be parsed or has an unsupported scheme.
    InvalidUrl,
    /// A request field (method, target, header name or value) is not valid HTTP.
    InvalidRequest,
    /// Name resolution failed or every address refused the connection.
    Connect,
    /// A timeout ran out.
    Timeout(TimeoutKind),
    /// The TLS handshake or record layer failed (certificate verification included).
    Tls,
    /// The proxy refused the CONNECT tunnel or answered with something else.
    Proxy,
    /// The peer broke the protocol (malformed response, HTTP/2 or HTTP/3 error).
    Protocol,
    /// The connection closed before the response was complete.
    Closed,
    /// The peer reset the stream (HTTP/2 or HTTP/3) with this code.
    Reset(u64),
    /// More redirects than allowed.
    TooManyRedirects,
    /// The response status is outside the accepted ranges (Camel `throwExceptionOnFailure`).
    Status(Box<StatusError>),
    /// A response body could not be decoded (`Content-Encoding`).
    Decode,
    /// The request or stream was cancelled locally.
    Cancelled,
    /// A feature this build left out (the message names the cargo feature).
    Unsupported,
    /// Another I/O error.
    Io(io::ErrorKind),
    /// A WebSocket protocol violation or a closed WebSocket.
    WebSocket,
}

/// The details of a response whose status was not accepted: the fields of Camel's
/// `HttpOperationFailedException`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusError {
    /// The request URI.
    pub uri: String,
    /// The status code.
    pub status: u16,
    /// The reason phrase (the standard one when the server sent none, as on HTTP/2 and HTTP/3).
    pub status_text: String,
    /// The `Location` header, if any.
    pub location: Option<String>,
    /// The response body (possibly empty).
    pub body: Vec<u8>,
    /// The response headers.
    pub headers: Vec<(String, String)>,
}

/// A client error: a kind and a message that names the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// A human-readable message.
    pub message: String,
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// A new error.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Error {
        Error { kind, message: message.into() }
    }

    pub(crate) fn timeout(k: TimeoutKind, what: impl fmt::Display) -> Error {
        let m = match k {
            TimeoutKind::Connect => "connect timed out",
            TimeoutKind::Tls => "TLS handshake timed out",
            TimeoutKind::ResponseHead => "timed out waiting for the response head",
            TimeoutKind::Idle => "read timed out",
            TimeoutKind::Total => "request deadline exceeded",
            TimeoutKind::Pool => "timed out waiting for a pooled connection",
        };
        Error::new(ErrorKind::Timeout(k), format!("{m}: {what}"))
    }

    pub(crate) fn io(e: &io::Error, what: impl fmt::Display) -> Error {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => Error::new(ErrorKind::Connect, format!("connection refused: {what}")),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe => {
                Error::new(ErrorKind::Closed, format!("connection closed ({e}): {what}"))
            }
            k => Error::new(ErrorKind::Io(k), format!("{e}: {what}")),
        }
    }

    pub(crate) fn protocol(msg: impl fmt::Display, what: impl fmt::Display) -> Error {
        Error::new(ErrorKind::Protocol, format!("{msg}: {what}"))
    }

    /// True for timeouts of any kind.
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, ErrorKind::Timeout(_))
    }

    /// True when the connection could not be established (Camel's `ConnectException`).
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect | ErrorKind::Timeout(TimeoutKind::Connect))
    }

    /// The status error, when the status was not accepted.
    pub fn status(&self) -> Option<&StatusError> {
        match &self.kind {
            ErrorKind::Status(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let k = match e.kind {
            ErrorKind::Timeout(_) => io::ErrorKind::TimedOut,
            ErrorKind::Closed => io::ErrorKind::UnexpectedEof,
            ErrorKind::Connect => io::ErrorKind::ConnectionRefused,
            ErrorKind::Io(k) => k,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(k, e)
    }
}
