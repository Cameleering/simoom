//! Interceptors: code that sees every request before it is sent and every response head after
//! it arrives. Cookie jars, authentication schemes with challenges (Digest, NTLM, refreshing
//! bearer tokens) and request logging plug in here
//! (`ClientBuilder::interceptor`, feature `hooks`).
//!
//! Interceptors run for each attempt: the first send, every redirect hop and every retry, in
//! the order they were added. `on_response` runs after the response head arrived and before
//! redirects are followed or the status is checked.

use crate::body::Response;
use crate::types::Request;

/// What to do after [`Interceptor::on_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Go on (follow a redirect, check the status, return the response).
    Continue,
    /// Send the request again (for example with credentials added in `before_send` after a
    /// `401` challenge). Honoured only when the body is replayable and at most
    /// [`MAX_INTERCEPTOR_RETRIES`] times per request; otherwise the response is returned.
    Retry,
    /// Fail the request with an [`ErrorKind::Protocol`](crate::ErrorKind::Protocol) error
    /// naming this reason (for example a Digest `rspauth` that does not match: the response
    /// did not come from a server that knows the credentials).
    Fail(&'static str),
}

/// The most retries interceptors may ask for in one request.
pub const MAX_INTERCEPTOR_RETRIES: usize = 3;

/// A request and response hook. Both methods have empty defaults.
pub trait Interceptor: Send + Sync {
    /// Called before each attempt, with the request about to go out (headers may be added or
    /// changed; the URL is the one of this attempt).
    fn before_send(&self, req: &mut Request) {
        let _ = req;
    }

    /// Called when a response head arrived (the body is not read yet; `Set-Cookie`,
    /// `WWW-Authenticate` and the status are available).
    fn on_response(&self, req: &Request, resp: &Response) -> Action {
        let _ = (req, resp);
        Action::Continue
    }
}
