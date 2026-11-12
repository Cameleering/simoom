# Parity: the HTTP client (C5, C6 client half, C10 client rows)

_2026-11-09. Items from `docs/BUGS.md`, "Complete HTTP stack for Cameleer". Each row names
Cameleer's code (read in `E:\Work\DataHQ\Code\Rust-camel`), what `crates/simoom-client`
provides, and the test that proves it. Test paths are under `crates/simoom-client/tests/` unless
they say otherwise; "unit" means the `#[cfg(test)]` module of the named source file._

## What it is

`simoom-client` is a std-only HTTP/1.1, HTTP/2 and HTTP/3 client and WebSocket client on top of
simoom's sans-io crates: simoom-http1's response parser, body decoder, head writer and `ws` codec;
simoom-h2's client role; simoom-quic's client endpoint with simoom-h3; simoom-tls's client
(ALPN, SNI, verification always on, client certificates, a custom root store, resumption); and
simoom-compress for `gzip`/`deflate` responses.

- **Blocking API** (`Client`, `RequestBuilder`, `Response`, `ResponseBody: Read`): requests run on
  the caller's threads. An HTTP/2 or HTTP/3 connection is shared by threads (`src/mux.rs`): with
  one stream in flight the waiting thread reads the socket itself; with two or more a pump thread
  reads for all of them and wakes only the threads whose streams it touched, and it exits when
  the connection is quiet again, so an idle connection has no thread.
- **Non-blocking API** (`rt::RtClient`, feature `rt`): HTTP/1.1 requests (plain and TLS) run on
  simoom-rt event loops and finish with a callback; idle connections are kept per loop.
- **Full-duplex calls** (`Client::call` → `Call`, `CallSender`) on HTTP/2 and HTTP/3: request and
  response bodies stream at the same time, trailers both ways (what gRPC needs).
- **WebSocket client** (`Client::websocket` → `WsBuilder` → `WebSocket`).

| cargo feature | adds |
|---|---|
| `client-h1` (default) | HTTP/1.1: pool, chunked, 100-continue, proxies, redirects |
| `client-h2` (default) | HTTP/2: h2c prior knowledge, h2 through ALPN, multiplexing, PING keepalive, `Client::call` |
| `client-ws` (default) | the WebSocket client |
| `tls` (default) | `https`, `wss`: TLS 1.3 with X25519, P-256, RSA, AES-GCM |
| `compress` (default) | `Accept-Encoding: gzip, deflate` and streaming decoding |
| `tls-extra` | P-384 and Ed25519 certificates, ChaCha20-Poly1305 |
| `client-h3` | HTTP/3, forced or through `Alt-Svc` |
| `rt` | `rt::RtClient` on simoom-rt loops |

## C5: the HTTP client, against `cameleer-http/src/client.rs`

| Cameleer | simoom-client | test |
|---|---|---|
| `Url::parse` (`http`/`https`, IPv6, default ports), `authority`, `host_header`, `request_target`, `join` (absolute, `//`, `/`, relative) | `Url::parse` (also `ws`/`wss`, userinfo kept as Basic credentials, invalid bytes refused), the same accessors, `join` with RFC 3986 dot-segment removal, `origin` | unit `url.rs` `parse_urls`, `join_references`, `percent` |
| `parse_authority` | `url::parse_authority` (stricter: `[v6]junk` refused) | unit `url.rs` `parse_urls` |
| `connect(host, port, timeout)`: each resolved address in turn | `transport::tcp_connect` (deadline shared by all addresses; `localhost` tries IPv4 first) | `http1.rs` `timeouts` (refused → `Error::is_connect`) |
| `map_io_error` → `ConnectException`, `SocketTimeoutException`, IO | `ErrorKind::Connect`, `ErrorKind::Timeout(TimeoutKind::…)`, `Closed`, `Tls`, `Io(kind)`; `Error::is_connect`, `is_timeout` | `http1.rs` `timeouts`, `invalid_requests_and_responses` |
| `ProxyAddr::parse` (`host:port`, `http://user:pass@host:port`, percent-decoded credentials, only `http` proxies) | `ProxyAddr::parse`, `new`, `with_credentials`, `authorization` | unit `proxy.rs` `proxy_config_and_no_proxy` |
| `ProxyConfig` (`http`, `https`, `no_proxy`), `from_env` / `from_vars` (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, lower-case too), `bypass` (names, `.suffix`, `*`, IPs, CIDR), `proxy_for` | the same, plus `tunnel_http` (CONNECT for plain HTTP too); `ws` uses the `http` proxy, `wss` the `https` proxy, both tunnelled | unit `proxy.rs`; `http1.rs` `proxies_connect_absolute_form_and_no_proxy` |
| `open_stream`: CONNECT tunnel for `https` (`Proxy-Authorization: Basic`), absolute form for plain `http` | the same; a 407 or other refusal is `ErrorKind::Proxy` with the status; bytes after the proxy's head are refused | `proxies_connect_absolute_form_and_no_proxy` (absolute form, tunnelled http, https via CONNECT, wrong credentials → 407, `NO_PROXY` CIDR) |
| `default_tls_config`: system trust store, full verification, ALPN `http/1.1` | `TlsOptions::default()` (`RootStore::system()`), verification cannot be turned off; ALPN `h2, http/1.1` by default, `http/1.1` with `HttpVersion::Http1`, `h2` with `Http2` | `http2.rs` `https_with_alpn_h2_and_http1`, `certificate_verification_is_always_on` |
| key material from `sslContextParameters` (client certificate for mutual TLS) | `TlsOptions::client_cert` (`CertifiedKey` chain and key) | `http2.rs` `client_certificates` (HTTP/1.1 and HTTP/2; refused without one) |
| `tls_server_name` (`SSLContextParameters.serverName`): SNI and hostname check | `TlsOptions::server_name` | `certificate_verification_is_always_on` (connect by address, verify `localhost`) |
| `HttpClient::connect_timeout` (30 s), `read_timeout` (60 s, overridden per request) | `Config::connect_timeout` (30 s), `read_timeout` (60 s), plus `tls_timeout`, `response_timeout`, `write_timeout`, `timeout` (whole request), `pool_timeout`; per request `RequestBuilder::timeout`, `response_timeout` | `http1.rs` `timeouts` (response head, idle read in the body, whole-request deadline with a trickling body, TLS handshake), `max_connections_and_pool_timeout` |
| `follow_redirects` (off), `max_redirects` (10); 301/302/303 turn non-HEAD into GET without body; 307/308 keep both | the same; also: a redirect to another origin drops `Authorization`, `Proxy-Authorization`, `Cookie` and `Host`; a streamed (non-replayable) body returns the 307/308 instead of following; `TooManyRedirects` past the limit (Cameleer returned the last 3xx) | `http1.rs` `redirects` |
| `Limits::max_body_bytes` (256 MiB default) | `Config::max_body` (256 MiB default), also caps decompressed size | `large_response_streams_with_small_reads`, `response_decompression` (bomb) |
| `chunked_requests` (Camel `chunked=true`) | `RequestBuilder::chunked(true)`; any `Body::Reader` without a length is chunked | `streamed_request_bodies_chunked_and_sized`, `chunked_option_streams_in_memory_bodies` |
| `keep_alive` with a process-wide pool, 30 s idle, 16 idle per origin; a reused connection that fails before the response is retried once (not on timeouts); proxied, server-name-override and chunked requests got their own connection | a pool per `Client` (clones share it) for every request kind: idle timeout 30 s, `pool_max_idle_per_origin` (20, Camel `connectionsPerRoute`), `max_connections_per_origin` with waiting (`pool_timeout`), `max_requests_per_connection`; idle connections older than 1 s are checked without blocking before reuse (TLS records that arrived while idle are processed); retried once when nothing of the response arrived and the body is replayable | `keep_alive_pool_reuses_connections`, `max_connections_and_pool_timeout`, `max_requests_per_connection`, `stale_pooled_connection_is_retried` |
| `HttpConnection` (one keep-alive connection: `send`, `set_timeout`, `is_closed`, `is_tls`) | `Client` with `max_connections_per_origin(1)`; `Response::version`, `PoolStats` | `max_connections_and_pool_timeout` |
| `request`, `get`, `post`, `execute` | `Client::request`, `get`, `post`, `put`, `delete`, `head`, `patch`, `execute(Request)` | `http1.rs` `get_post_headers_query` |
| `read_response` (1xx skipped, framing per RFC 9112, trailers dropped) | `h1::H1Conn` on simoom-http1's strict `parse_response` and `BodyDecoder`; 1xx skipped (`100` drives `Expect`); trailers kept: `Response::trailers` | `chunked_and_close_delimited_responses_and_trailers`, `fuzz.rs` |
| — (no `Expect` support) | `RequestBuilder::expect_continue(true)`: waits up to `Config::expect_timeout` (1 s) for `100 Continue`; a final answer first means the body is never sent | `expect_continue` (simoom, a refusing server, a server that ignores `Expect`) |
| `connect_tunnel` reads the proxy's head byte by byte | reads in chunks with simoom-http1's parser, refuses data after the head | `proxies_connect_absolute_form_and_no_proxy` |

## C5: Camel `http` producer options and headers (`cameleer-http/src/producer.rs`)

The producer stays in Cameleer (it maps an `Exchange` to a request); the table shows what each
option or header uses in simoom-client.

| Camel option / header | simoom-client | test |
|---|---|---|
| `CamelHttpMethod`, `httpMethod`, default `POST` with a body and `GET` without | `Client::request(method, url)` (any token) | `get_post_headers_query` |
| `CamelHttpUri` (unless `bridgeEndpoint`), `CamelHttpPath`, `CamelHttpQuery` / `CamelHttpRawQuery`, extra endpoint parameters appended to the query | `Url` (`path`, `query` fields), `Url::join`, `percent_encode`, `RequestBuilder::query` | unit `url.rs`; `get_post_headers_query` (encoded query) |
| `CamelHttpResponseCode`, `CamelHttpResponseText` | `Response::status`, `Response::reason` (standard phrase on HTTP/2 and HTTP/3) | `get_post_headers_query`, `status_checks_like_throw_exception_on_failure` |
| response headers to message headers (`skipResponseHeaders`), repeated headers | `Response::headers` (`Headers::get_all` keeps repeats in order) | `get_post_headers_query` (`x-multi`) |
| `throwExceptionOnFailure` (true), `okStatusCodeRange` (`200-299`), `HttpOperationFailedException` (uri, statusCode, statusText, redirectLocation, responseBody, responseHeaders; message `HTTP operation failed invoking … with statusCode: …, redirectLocation: …`) | `Config::ok_status` / `RequestBuilder::ok_status(ranges)`, `accept_any_status()`, `parse_status_ranges`; `ErrorKind::Status(StatusError { uri, status, status_text, location, body, headers })` with the same message; `Response::error_for_status` | `status_checks_like_throw_exception_on_failure`, unit `types.rs` |
| `connectTimeout`, `socketTimeout` / `soTimeout` / `responseTimeout` | `connect_timeout`, `read_timeout`, `response_timeout` | `timeouts` |
| `followRedirects` | `follow_redirects` | `redirects` |
| `copyHeaders`, `skipRequestHeaders` (message headers sent as request headers) | `RequestBuilder::header` / `headers` | `get_post_headers_query` |
| `userAgent` (default `cameleer/<version>`) | `Config::user_agent` (sent when the request has none) | `get_post_headers_query` |
| `authUsername` / `authPassword`, `authMethod=Basic` | `RequestBuilder::basic_auth`; also `user:pass@` in the URL; `bearer_auth` | `get_post_headers_query` |
| `chunked` | `RequestBuilder::chunked` | `chunked_option_streams_in_memory_bodies` |
| `getWithBody`, `deleteWithBody` | any method may carry a body | `chunked_option_streams_in_memory_bodies` (GET with a body) |
| `ignoreResponseBody` | drop the `Response` (the connection is kept when the rest is already buffered, else closed) | `keep_alive_pool_reuses_connections` |
| `disableStreamCache` (body read lazily from the connection, `cameleer_tls::stream_body`) | `Response::into_body()` → `ResponseBody: Read + Send`, reading only what is asked for | `large_response_streams_with_small_reads` |
| stream-handle request body sent chunked without buffering | `Body::reader` / `Body::sized_reader` | `streamed_request_bodies_chunked_and_sized` (3 MB both ways) |
| `customHostHeader`, `preserveHostHeader` | a `Host` header on the request is kept (HTTP/1.1 `Host`, HTTP/2 and HTTP/3 `:authority`) | `chunked_option_streams_in_memory_bodies` (custom host) |
| `sslContextParameters`, `useGlobalSslContextParameters`, `camel.ssl.*` | `TlsOptions` (`roots`, `client_cert`, `server_name`, `resumption`); keystores (PKCS#12, JKS) come with C2 | `certificate_verification_is_always_on` |
| `proxyHost`, `proxyPort`, `proxyAuthUsername`, `proxyAuthPassword`; `useSystemProperties=true` | `ProxyConfig::new(ProxyAddr::new(..).with_credentials(..))`; `ProxyConfig::from_env()` | `proxies_connect_absolute_form_and_no_proxy` |
| `httpVersion=HTTP/2` (h2c prior knowledge for `http`, ALPN `h2` required for `https`) | `HttpVersion::Http2` (same semantics; an error names the missing ALPN) | `h2c_prior_knowledge_and_multiplexing`, `http2_required_but_server_speaks_http1` |
| `contentCompressionDisabled=false`: `Accept-Encoding: gzip, deflate`, decode `gzip`, `x-gzip`, `deflate` (zlib or raw), drop `Content-Encoding` | feature `compress`, `Config::decompress` (true): the same, streaming, bounded by `max_body`; `Content-Length` dropped too; an unknown coding is passed through undecoded (Cameleer failed) | `response_decompression` |
| request body compressed when the message has `Content-Encoding: gzip`/`deflate` | stays in the producer: `simoom_compress::compress` then `Body::Bytes` | — |
| `connectionClose`, `connectionsPerRoute` | `keep_alive(false)` (`Connection: close`), `pool_max_idle_per_origin` | `keep_alive_pool_reuses_connections` |
| per-producer HTTP/1.1 pool and one HTTP/2 connection per target | one `Client` per producer | `many_threads_share_one_client` |

## C5: HTTP/2 client, against `cameleer-grpc/src/h2/client.rs`

| Cameleer | simoom-client | test |
|---|---|---|
| `H2Connection::connect` (h2c prior knowledge) | `HttpVersion::Http2` on an `http` URL | `http2.rs` `h2c_prior_knowledge_and_multiplexing` |
| `connect_tls` (ALPN `h2`, error when not chosen) | `https` with `Auto` (ALPN `h2`, `http/1.1`) or `Http2` (ALPN `h2` only) | `https_with_alpn_h2_and_http1` |
| `connect_upgrade` (HTTP/1.1 `Upgrade: h2c`) | **not done** (simoom-h2 has `Connection::client_upgrade`; nothing in Cameleer's producer uses it) | — |
| a thread per connection reading frames; streams multiplexed | a thread only while two or more streams are in flight (`mux.rs`); `max_multiplexed_per_origin` (1) | `h2c_prior_knowledge_and_multiplexing` (16 concurrent slow requests on one connection in about one request's time) |
| `open_stream_timeout` (waits for a free stream slot) | `Mux::open` waits until `pool_timeout` | `dropping_a_body_cancels_the_stream` (120 concurrent requests, server limit 100) |
| `request`: retries on `REFUSED_STREAM` | retries on `REFUSED_STREAM` (and HTTP/3 `H3_REQUEST_REJECTED`), and on a connection going away before the stream opened, when the body is replayable | `refused_streams_are_retried_and_goaway_opens_a_new_connection` |
| `read_response`: 1xx skipped, body, trailers | the same; trailers in `Response::trailers` | `response_trailers_over_h2` |
| flow control in the connection thread | DATA released as the application reads (`ResponseBody`), so a slow reader holds back the sender; uploads wait for WINDOW_UPDATE | `large_bodies_both_ways_with_flow_control` (6 MB down, 5 MB and 3 MB streamed up, two downloads read alternately) |
| a complete response followed by `RST_STREAM(NO_ERROR)` kept (INTEROP bug 20) | kept; an upload cut off by the reset stops and the response is read (RFC 9113 §8.1) | `complete_response_then_rst_stream_no_error_is_kept` (simoom U11, client side) |
| GOAWAY marks the connection closed; next request opens a new one | the same; the connection leaves the pool | `refused_streams_are_retried_and_goaway_opens_a_new_connection` |
| `ping(timeout)` → RTT | internal `Mux::ping`, used by the keepalive (`Config::keepalive_interval`, `keepalive_timeout`); an unanswered PING closes the connection | `keepalive_pings_idle_connections`, `keepalive_closes_a_dead_connection` |
| `close`, `is_closed`, `active_streams`, `peer_max_concurrent_streams` | `Client::close_idle`, `Client::pool_stats` | `https_with_alpn_h2_and_http1` |

## C9 (client side): gRPC calls, against `cameleer-grpc/src/grpc/client.rs`

| Cameleer | simoom-client | test |
|---|---|---|
| `start_call(path, metadata, deadline)` → `ClientCall` | `Client::call(method, url, headers)` → `Call` (HTTP/2 or HTTP/3; `te: trailers` passes through) | `http2.rs` `duplex_call_streams_both_ways` |
| `ClientCall::send`, `close_send`, `cancel`, `sender()` → `CallSender` (another thread) | `Call::send`, `finish`, `finish_with_trailers`, `cancel`, `sender()` → `CallSender: Clone + Send` | `duplex_call_streams_both_ways` (each message echoed before the request ends) |
| `response_headers`, `recv` (messages), `status` / `metadata` from trailers | `Call::response()` / `response_until(deadline)`, `Call::read`, `Call::trailers()` (gRPC framing and `grpc-status` stay in Cameleer) | `duplex_call_streams_both_ways` (`grpc-status: 0`) |
| `unary`, `server_streaming`, `streaming` | built on `Call` in Cameleer | — |

## C6 (client half): WebSocket client, against `cameleer-protocols/src/websocket`

| Cameleer | simoom-client | test |
|---|---|---|
| `WsConnection::connect_secure(host, port, path, timeout, headers, tls)` (`ws://`, `wss://` with verification) | `Client::websocket(url).header(..).connect()`: the client's connect/TLS timeouts, `TlsOptions`, proxies (CONNECT tunnel, also for `wss`) | `websocket.rs` `wss_and_proxy_tunnel` |
| handshake: `Sec-WebSocket-Key`, accept check | key from the OS random source; `Upgrade`, `Connection` and `Sec-WebSocket-Accept` checked (`simoom_http1::ws::accept_key`); a refused handshake reports the status | `refused_and_broken_handshakes` |
| `subProtocol` / `subProtocols` | `WsBuilder::protocol` (offered in order), `WebSocket::protocol`; a protocol not offered is refused | `client_close_handshake_and_subprotocol` |
| masking of client frames | a fresh mask per frame (OS-seeded generator) | every `websocket.rs` test (simoom's server refuses unmasked frames) |
| `maxMessageSize` (incoming, 64 MiB), `maxFrameSize` (outgoing fragmentation, 64 KiB) | `WsBuilder::max_message` (64 MiB), `frame_size` (64 KiB) | `echo_text_binary_fragmented_ping_close` (300 KB message in fragments) |
| `read_message` (text, binary; pings answered) | `WebSocket::recv` / `recv_timeout` → `Message::{Text, Binary, Ping, Pong, Close}`; pings answered automatically and reported | `echo_text_binary_fragmented_ping_close` |
| send text, binary, ping; close | `send_text`, `send_binary`, `ping`, `pong`, `send_close`, `close(code, reason, wait)` (waits for the peer's Close) | `client_close_handshake_and_subprotocol` |
| a reader thread and producer sends at the same time | `send_*` and `recv` take `&self`: one reader and any number of senders in parallel | `concurrent_sender_and_receiver` |
| protocol errors (masked server frame, reserved bits, bad UTF-8) close the connection | the same, with the RFC close code sent (1002, 1007, 1009) | `refused_and_broken_handshakes` (masked server frame) |
| `reconnectInterval` (client consumers) | stays in Cameleer (reconnect by calling `connect` again) | — |
| WebSocket over HTTP/2 (RFC 8441), not in Cameleer | `WsBuilder::http2(true)`: extended CONNECT (`:protocol websocket`) on the client's shared HTTP/2 connection, h2c or h2; refused cleanly when the server does not announce `SETTINGS_ENABLE_CONNECT_PROTOCOL` | `websocket_over_http2` (h2c and h2 against simoom's `websocket-h2`, two WebSockets and a request on one connection, refusal by a server without the setting) |

## C10 client rows that are not HTTP clients

| Cameleer | status |
|---|---|
| `cameleer-http/src/netty.rs` producer (`netty:tcp`, `netty:udp`) | not HTTP: stays in Cameleer (it can move to the C11 TLS stream adapter) |
| `cameleer-http/src/rest.rs` REST producer (`producerComponentName=http`) | goes through the `http` producer above |
| `cameleer-grpc/src/auth.rs` JWT / Google client interceptors | headers on the call: `Headers`, `RequestBuilder::bearer_auth` |
| `cameleer-tls/src/stream_body.rs` (stream handles in message bodies) | Cameleer keeps the registry; `ResponseBody` is the `Read + Send` it registers |

## Beyond Cameleer

- HTTP/3 (`client-h3`): forced (`HttpVersion::Http3`) or through `Alt-Svc` (`Config::alt_svc`):
  the first request goes over TCP, `Alt-Svc: h3=":port"` is remembered for its `ma`, later
  requests use QUIC; a failed QUIC connect marks the alternative broken for 5 minutes and falls
  back to TCP. Tests: `http3.rs` `forced_http3_round_trips` (2.5 MB down, 1.5 MB up, trailers,
  streaming, 10 concurrent on one connection), `alt_svc_moves_an_origin_to_http3`,
  `alt_svc_falls_back_when_quic_is_unreachable`.
- The non-blocking client (`rt`): `rt.rs` `requests_on_event_loops_reuse_connections` (200
  concurrent requests on one loop), `https_on_event_loops`, `errors_timeouts_and_stale_connections`.
- **Connection quality (L5):** Happy Eyeballs (RFC 8305: families interleaved, a new attempt
  every `happy_eyeballs_delay`, 250 ms), `dns_timeout` (10 s; the system resolver runs on a
  helper thread), a background evictor per pool that closes idle sockets (shared and
  thread-cached), h2c through HTTP/1.1 `Upgrade` (`h2c_upgrade`, an `OPTIONS *` probe; servers
  without h2c stay on HTTP/1.1), SOCKS5 proxies (`socks5://`, `socks5h://`, RFC 1928 with RFC 1929
  credentials, also under `https` and `wss`), retries with exponential backoff and jitter for
  idempotent requests (`retries`, `retry_backoff`, `retry_statuses`, `Retry-After`). Tests:
  `src/dns.rs` unit tests, `http1.rs` `socks5_proxies`, `retries_with_backoff_for_idempotent_requests`,
  `idle_sockets_are_evicted_in_the_background`, `http2.rs` `h2c_through_upgrade`.
- **Pipelining (L3):** `Client::pipeline(Vec<Request>)` writes idempotent requests back to back on
  one HTTP/1.1 connection and reads the answers in order; unanswered ones are resent on a new
  connection. Test `http1.rs` `pipelining` (the server sees all five requests before answering;
  it closes after three, the last two go on a second connection).
- **`RtClient` parity (L4):** on the loops: HTTP/1.1 plain and TLS, redirects, `gzip`/`deflate`,
  HTTP proxies in absolute form and `CONNECT`/SOCKS5 tunnels (set up on the connector thread); on
  the client's worker threads through the blocking engine: HTTP/2, HTTP/3, streamed request
  bodies (`send_request`) and streamed responses (`send_streaming`). Tests `rt.rs`
  `redirects_proxies_and_decompression_on_the_loop`,
  `http2_streamed_bodies_and_streamed_responses_on_workers`.
- **More connections past a stream threshold:** `streams_per_connection` with
  `max_multiplexed_per_origin` opens another HTTP/2 or HTTP/3 connection once one carries that
  many streams (off by default). Test `http2.rs` `more_connections_past_a_stream_threshold`.
- **Interceptors** (`src/hooks.rs`, `ClientBuilder::interceptor`): `before_send` on every attempt
  and `on_response` with `Retry`; the cookie jar and the authentication schemes sit on it. Test
  `http1.rs` `interceptors_see_requests_and_can_retry`.
- **System roots on Windows:** `RootStore::system()` (simoom-tls) falls back to the Windows `ROOT`
  certificate store through crypt32 (`simoom_sys::certstore`, the only new unsafe code, with
  SAFETY comments); macOS is covered by `/etc/ssl/cert.pem`, which it ships, and
  `SSL_CERT_FILE`. Tests `simoom-sys` `certstore::tests`, `http2.rs` `system_roots_are_loaded`.
- Fuzzing: `fuzz.rs` serves mutated responses in random pieces over loopback (5,000 cases by
  default, `SIMOOM_FUZZ_ITERS` for more); no panic, no hang, accepted bodies match their framing.
- Interop (`SIMOOM_INTEROP=1`, `interop.rs`): Python `http.server` (HTTP/1.0, files, HEAD, 404,
  directory redirect) on Windows and Linux; nginx 1.24 on WSL2 (keep-alive on one connection,
  3 MB files, 5 MB sized and 1 MB chunked uploads, `Expect`, redirects, TLS with ALPN h2 and
  http/1.1, 16 concurrent h2 requests on one connection, PING keepalive answered).

### Standalone-library conveniences (`docs/BUGS.md` L1, L2, L6)

Neither Cameleer nor Camel's `http` component has these; they are here because simoom-client is
for third parties too. Each sits on the interceptor hook (`src/hooks.rs`), in its own module
(`src/cookie.rs`, `src/auth.rs`, `src/multipart.rs`, `src/encode.rs`).

| feature | simoom-client | test |
|---|---|---|
| L1 cookie jar (`cookies`) | `cookie::CookieJar` (RFC 6265bis), opt-in with `ClientBuilder::cookie_jar(Arc<CookieJar>)`, shareable between clients and threads | unit `cookie.rs` (9 tests), `cookies.rs` |
| `Set-Cookie` parsing | strict §5.6: CTLs refuse the cookie, name+value ≤ 4096, attribute values ≤ 1024, cookie-date algorithm, `Max-Age` over `Expires`, 400-day cap; `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned` | unit `cookie_dates`, `parse_and_send_basics`, `overwrite_expiry_and_max_age` |
| domain and path matching, host-only cookies | §5.1.3, §5.1.4, default path; IP hosts exact only | unit `matching_helpers`, `domain_rules_and_public_suffixes` |
| public suffixes | conservative default: a `Domain` that is one label or an IP address (other than the host) is refused; `PublicSuffixList::parse` (Mozilla PSL format, wildcards, exceptions) for exact rules; no list embedded | unit `domain_rules_and_public_suffixes` |
| storage rules | replace on (name, domain, host-only, path, partition) keeping the creation time; an expired cookie deletes; Secure only from secure origins (loopback counts, as in browsers); no insecure shadowing of Secure cookies; `__Secure-` and `__Host-`; `SameSite=None` and `Partitioned` need Secure | unit `secure_prefixes_and_shadowing`, `overwrite_expiry_and_max_age` |
| SameSite and partitions | every request is same-site by default; `with_top_level_site` makes other sites cross-site (Strict withheld, Lax only with safe methods, cross-site responses cannot set Lax or Strict) and keys `Partitioned` cookies | unit `same_site_and_partitions` |
| limits | 50 per domain, 3000 in all (`with_limits`); expired first, then least recently used | unit `order_limits_and_eviction` |
| sending order, the caller's `Cookie` | longest path first, then oldest; a `Cookie` header the caller set is kept and the jar's cookies appended; recomputed on every redirect hop and retry | unit `order_limits_and_eviction`; `cookies.rs` `login_redirect_paths_and_logout` (a 302 that sets the session, path scoping, HTTP/2, `Max-Age=0`), `cross_origin_redirect_gets_that_origins_cookies_only`, `many_threads_share_a_jar` |
| export and import | Netscape `cookies.txt` (curl, wget), `#HttpOnly_`, an optional 8th column for SameSite and partition | unit `export_import_round_trip`; `cookies.rs` (import into a second client) |
| L2 authentication | `auth::Auth` with `ClientBuilder::auth(Arc<Auth>)`: answers `401` (origin) and `407` (proxy, absolute form and `CONNECT` tunnels), remembers the scheme per origin and authenticates later requests up front | `auth.rs` |
| challenge parsing | RFC 9110 §11: several challenges per field and across fields, token68, quoted-string escapes | unit `auth.rs` `challenge_parsing` |
| Digest (`auth-digest`) | RFC 7616: SHA-256, SHA-512-256, MD5 and their `-sess` variants, the strongest offered wins; `qop=auth`, `auth-int` (`digest_auth_int`), the RFC 2069 form; nonce counting with up-front requests; `stale=true` retried; `userhash`; `username*` (RFC 8187); `opaque`; `nextnonce` from `Authentication-Info`; a `rspauth` that does not match fails the request (`ErrorKind::Protocol`, through the new `hooks::Action::Fail`). SHA-512/256 was added to simoom-tls `crypto::sha2` (`Sha512::new512_256`) | unit `rfc7616_and_rfc2617_vectors` (RFC 7616 §3.9.1 MD5 and SHA-256, RFC 2617 §3.5; §3.9.2 cross-checked with Python hashlib because the values printed in the RFC match no SHA-512/256 implementation); `auth.rs` `digest_every_algorithm_nonce_counts_and_stale`, `digest_auth_int_wrong_password_and_streamed_first_request` |
| NTLMv2 (`auth-ntlm`) | MS-NLMP Negotiate, Challenge (bounds-checked parser), Authenticate; NTLMv2 and LMv2 responses; MD4 and HMAC-MD5 from simoom-tls `crypto::legacy` (moves to ksar); the handshake runs on one HTTP/1.1 connection, reused from the pool afterwards | unit `ms_nlmp_ntlmv2_vectors` (MS-NLMP 4.2.4: NTOWFv2, LMv2, NTProofStr, session base key); `auth.rs` `ntlm_handshake_on_one_connection` |
| Bearer | `Auth::bearer(origin, provider)`: a `TokenProvider` (or a closure `Fn(bool) -> Option<String>`) bound to one origin, refreshed once on a `Bearer` challenge | unit `bearer_and_basic_flow`; `auth.rs` `bearer_refresh_and_basic_on_challenge` |
| Basic on challenge | `Auth::basic`, only over https, to loopback hosts, or with `basic_over_http` | `bearer_refresh_and_basic_on_challenge` |
| proxy authentication | `proxy_basic`, `proxy_digest`, `proxy_ntlm`: a `407` in absolute form through the interceptor; a `407` on `CONNECT` answered on the same connection while the tunnel opens | `auth.rs` `proxy_digest_absolute_form_and_tunnel`, `proxy_ntlm_tunnel` |
| interceptors beyond `execute` | WebSocket handshakes (HTTP/1.1 with retry on a 401, HTTP/2 and HTTP/3 without) and `Client::call` run the interceptors; Digest `rspauth` is checked | `server_auth.rs` `interceptors_on_websocket_handshakes`, `interceptors_on_calls`, `client_refuses_a_wrong_rspauth` |
| against simoom's server auth | `simoom::auth` (facade `auth`) with this client: every Digest algorithm with `rspauth`, `nextnonce`, `stale=true`, `auth-int`, Basic, Bearer | `server_auth.rs` |
| a real implementation | curl run against the same in-test servers: their checks accept curl's Digest, and curl's NTLM where the curl build has it | `auth.rs` `curl_is_accepted_by_the_test_servers` |
| L6 multipart (`multipart`) | `multipart::Multipart` and `Part`: text, bytes, files, parts streamed from readers (with or without a length), extra part headers, a 190-bit random boundary checked against in-memory parts, WHATWG escaping of names and file names; `RequestBuilder::multipart` | unit `multipart.rs`; `bodies.rs` `multipart_round_trips` (simoom's server, HTTP/1.1 and HTTP/2, a 300 KB streamed part, sized and chunked) |
| form-urlencoded | `encode::form_urlencode`, `form_urldecode` (WHATWG), `RequestBuilder::form` | unit `encode.rs`; `bodies.rs` `form_urlencoded_round_trip` |
| request-body compression | `RequestBuilder::compress(Coding)` and `compress_level`: gzip and deflate (`compress`), br (`compress-br`), zstd (`compress-zstd`) through simoom-compress; in-memory bodies keep a length, streamed bodies compress as they are sent | `bodies.rs` `request_body_compression` (every coding, both body kinds, decoded and compared) |

## Benchmark

`scripts/client-bench.sh` (WSL2 Ubuntu 24.04 on a Ryzen 5 5600X, 12 logical CPUs, Windows 11
host): simoom's `bench_server` example (fixed 13-byte reply, 4 loops) pinned to CPUs 0-3; the
client pinned to CPUs 4-7, closed loop: `threads` threads share one client and send `GET /`
back to back for 5 s. simoom-client is `examples/client_bench.rs`; Cameleer is
`bench/competitors/cameleer-client-min` (its `HttpClient` keep-alive pool for HTTP/1.1,
cameleer-grpc's `H2Connection` for h2c, one connection like simoom). CPU = the client process's
user + system time per request (`/proc/self/stat`). Rounds alternate simoom and Cameleer
(`ROUNDS=3`), so both see the same machine state.

**Measurement caveat.** Other agents built and benchmarked on the same machine throughout, and a
stray test process kept a host core at 100% during the "after" runs; absolute numbers moved by
up to 2x between runs (Cameleer's own HTTP/1.1 single-thread figure ranged from 6,200 to 17,400
req/s). Compare the two clients within a run, not across runs. "Before" is the first report's
quietest run; "after" is the median of three interleaved rounds from the cleanest after-run
(load average 0.6-1.7 at the start) for h2c, and the last full run for HTTP/1.1.

### Before (first report)

| protocol | threads | simoom req/s | Cameleer req/s | simoom CPU µs/req | Cameleer CPU µs/req |
|---|---:|---:|---:|---:|---:|
| HTTP/1.1 | 1 | 15,374 / 16,684 | 17,265 / 17,393 | 33.7 / 31.1 | 29.2 / 29.1 |
| HTTP/1.1 | 4 | 60,930 / 69,496 | 64,138 / 50,926 | 22.7 / 25.9 | 29.2 / 38.3 |
| HTTP/1.1 | 16 | 137,854 / 150,241 | 180,591 / 176,558 | 27.3 / 25.8 | 21.6 / 22.0 |
| h2c | 1 | 16,107 / 16,283 | 10,297 / 8,931 | 31.8 / 31.7 | 58.3 / 67.4 |
| h2c | 4 | 18,467 / 19,071 | 25,533 / 26,472 | 82.5 / 82.5 | 62.3 / 61.0 |
| h2c | 16 | 16,599 / 17,867 | 42,620 / 42,756 | 98.8 / 90.9 | 61.7 / 61.1 |

### After

| protocol | threads | simoom req/s | Cameleer req/s | simoom CPU µs/req | Cameleer CPU µs/req |
|---|---:|---:|---:|---:|---:|
| HTTP/1.1 (quiet run, 2 rounds) | 1 | 17,562 / 16,756 | 17,224 / 16,473 | 28.8 / 30.2 | 28.7 / 30.6 |
| HTTP/1.1 (quiet run, 2 rounds) | 16 | 178,122 / 173,748 | 182,590 / 182,191 | 21.7 / 22.3 | 21.1 / 20.8 |
| HTTP/1.1 (loaded run, 3 rounds) | 4 | 28,985 / 23,880 / 41,388 | 33,213 / 28,455 / 24,686 | 55.0 / 30.9 / 37.9 | 38.5 / 39.6 / 67.0 |
| h2c (3 rounds) | 1 | 11,559 / 12,671 / 15,048 | 8,431 / 8,419 / 9,491 | 43.4 / 40.4 / 33.4 | 72.1 / 72.7 / 62.8 |
| h2c (3 rounds) | 4 | 24,075 / 26,678 / 28,127 | 19,551 / 22,646 / 20,555 | 56.1 / 51.0 / 48.7 | 78.8 / 69.3 / 76.8 |
| h2c (3 rounds) | 16 | 33,853 / 29,108 / 35,075 | 31,657 / 33,762 / 31,172 | 48.7 / 53.8 / 47.7 | 79.1 / 76.5 / 81.4 |

What changed:

- **HTTP/2 with many threads**, the gap of the first report: the connection lock is no longer
  the bottleneck. Each stream has a slot with its own lock and condition variable; headers,
  body bytes and trailers are moved there under short connection-lock sections, and the
  requesting thread reads and waits on its slot only. Writes leave the lock: output is queued
  and written by whichever thread holds the write lock, and threads that find it taken leave
  their bytes for it (frames ready together go out in one write). Finished streams are retired
  without the lock; the pool's checks are atomics. Result: at 4 threads simoom-client is now
  ahead of Cameleer in throughput (1.2-1.3x) at 30% less CPU per request; at 16 threads it is
  ahead in two of three rounds and at 35-40% less CPU per request in all three. Cameleer reached
  42,700 req/s at 16 threads on the quiet machine of the first report; simoom-client's best
  after-run figure is 37,900 (in a loaded run where Cameleer reached 29,200-37,700), so a
  quiet-machine rerun is still owed for the 16-thread headline.
- **HTTP/1.1**: parity at 1 and 16 threads on the quiet run (within 1-5%, CPU per request equal
  within noise), from 15-20% behind at 16 threads. Changes: the receive buffer is no longer zeroed
  on every read; request heads are written straight into the output (no `format!`, no target or
  `Host` strings); header lists are one buffer plus an index (two allocations per response);
  bodies read whole (`bytes()`) append decoded pieces directly; error context is formatted only
  on errors; the pool key uses a fast hasher and is shared, not cloned; and a thread that sends
  back to back gets its own idle connection back from a per-thread cache without the pool lock
  (when connections per origin are unlimited; the evictor still closes it when idle).
- With `streams_per_connection` and `max_multiplexed_per_origin` (not the default, so not in the
  tables) a 16-thread client spreads over several connections and server loops.

curl 8.5.0 on the same server, one process, sequential with keep-alive: 8,479 req/s (HTTP/1.1)
and 8,686 req/s (h2c), a sanity check of the single-thread range. h2load is not installed there.

Reproduce: `scripts/client-bench.sh` (`SECS`, `THREADS`, `PROTOS`, `ROUNDS`, `SERVER_CPUS`,
`CLIENT_CPUS`); `client_bench` also takes `--conns N --streams S`.

## Size

`scripts/size-client.sh` on WSL2 Ubuntu 24.04 (x86-64, `dist` profile: fat LTO, `panic=abort`,
stripped): `examples/size_get.rs` (one GET; a WebSocket connection with `client-ws`; an
event-loop request with `rt`) minus an empty `fn main` (`examples/client_empty.rs`). No budget of
its own; `scripts/size.sh` and its server rows are unchanged.

| features | added (first report) | added (round 2) | added (now) |
|---|---:|---:|---:|
| `client-h1` (plain HTTP/1.1) | 174,144 | 288,408 | 171,936 |
| `client-h1,tls` | 538,184 | 643,376 | 527,760 |
| `client-h1,tls,compress` | 566,720 | 671,976 | 576,136 |
| `client-h1,client-h2,tls` | 709,288 | 809,120 | 702,944 |
| `client-h1,client-ws,tls` | 571,232 | 675,672 | 560,392 |
| default (`client-h1,client-h2,client-ws,tls,compress`) | 770,040 | 882,336 | 798,648 |
| `client-h1,client-h3` | 930,864 | 1,018,032 | 920,008 |
| `client-h1,tls,rt` | 753,720 | 872,520 | 776,704 |
| default + `cookies` / `auth-digest` / `auth-ntlm` / `multipart` | - | 923,624 / 924,944 / 922,240 / 907,160 | 844,176 / 873,136 / 866,032 / 823,488 |
| `full` | 1,271,592 | 1,670,824 | 1,695,656 |
| server + client (default features), client's share | 277,784 | 367,168 | 275,640 |

Targets: `client-h1` at most 190 KB, default at most 800 KB. Everything a plain request does not
need is a cargo feature, off by default and in `full`:

| feature | what it compiles |
|---|---|
| `happy-eyeballs` | racing the addresses of a name (`Config::happy_eyeballs_delay`; without it addresses are tried in order) |
| `dns-timeout` | the resolver on a helper thread (`Config::dns_timeout`; without it resolution blocks the caller) |
| `socks` | SOCKS5 proxies (`socks5://`, `socks5h://`; without it they fail with `Unsupported`) |
| `retry` | retries with backoff (`Config::retries` is ignored without it) |
| `pipeline` | `Client::pipeline` |
| `h2c-upgrade` | h2c through `Upgrade` (`Config::h2c_upgrade`) |
| `evict` | the background thread that closes idle pooled connections (without it they are closed when next checked out, or by the HTTP/2 keepalive thread) |
| `hooks` | interceptors (`ClientBuilder::interceptor`); turned on by `cookies` and `auth` |
| `auth` | `auth::Auth` (Basic, Bearer, proxy `CONNECT` challenges); turned on by `auth-digest` and `auth-ntlm` |
| `encode` | `RequestBuilder::form`, `RequestBuilder::compress` and the `encode` module (needs `compress`) |

A custom `Decoder` (`ClientBuilder::decoder`) needs `compress`. The `compress` row grew by about
20 KB with the codec rework in simoom-compress (another agent's work), so the default row has
about 1 KB to spare; the h2 driver is the next place to look if it has to shrink further.

Measured on 2026-11-09 against a copy of the tree in which simoom-compress builds (its
`codec.rs` has a `drive_oneshot` without the `brotli`/`zstd` cfg of the trait it uses; the
copy adds the cfg).

### Allocations per HTTP/1.1 request

`examples/client_allocs.rs` (the counting allocator of simoom-sys, 10,000 keep-alive GETs
against `bench_server`): 13.0 allocations per request on `client-h1`. Removed this round: the
copy of the request headers with the client defaults (now written beside the request's fields),
the head buffer (reused per connection), the reason phrase (borrowed when it is the standard
one), the origin key on a thread-cache hit (the cached connection is compared field by field
first), and the HTTP/2 header list on HTTP/1.1 requests. Left: URL parsing, the response
headers, the response's own URL, the body box and buffer.

## Not done

- **TLS 1.2 and keystores**: the client uses whatever simoom-tls offers (TLS 1.3 today); TLS 1.2
  is C1 and PKCS#12/JKS are C2, both other agents' work. macOS roots come from
  `/etc/ssl/cert.pem` and `SSL_CERT_FILE`, not the keychain (`SecTrustCopyAnchorCertificates` is
  not wired: no macOS machine to test it).
- **The non-blocking client** (`rt`): HTTP/2, HTTP/3, streamed request bodies and streamed
  responses run on worker threads through the blocking engine, not on the loops; name resolution,
  TCP and tunnels run on one connector thread per client; interceptors do not apply.
- **HTTP/3**: no 0-RTT (refused on purpose), no connection migration, no HTTP/3 through proxies;
  only the `h3` Alt-Svc token (not drafts); the Alt-Svc cache is in memory per client.
- **Pipelining** is an explicit batch API (`Client::pipeline`), not transparent for concurrent
  `send` calls.
- **Cookies, authentication and body helpers, not done:** the interceptors run in the blocking
  client, on WebSocket handshakes (HTTP/1.1 retries on a new connection, so NTLM cannot
  authenticate a WebSocket; HTTP/2 and HTTP/3 handshakes are not retried) and on `Client::call`
  (`before_send`, and `on_response` when the head arrives; no retry, the body streams), but not
  in `rt::RtClient`; no embedded
  public suffix list (load one with `PublicSuffixList::parse`); sites are compared without the
  scheme; NTLM has no MIC, channel bindings, signing or sealing; no Negotiate/Kerberos; Digest
  `rspauth` is not checked for `qop=auth-int`; an origin challenge after an NTLM proxy challenge in absolute form
  needs more than the 3 interceptor retries; a first request with a streamed body cannot answer
  a challenge (later ones authenticate up front).
- **h2load** is not installed on the WSL machine (no package installs were made), so the HTTP/2
  sanity check is Cameleer's client only; curl covers HTTP/1.1.
