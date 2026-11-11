# Parity: server extras (C6 server half, C7, C8, C9)

_2026-11-09. Items from `docs/BUGS.md`, "Complete HTTP stack for Cameleer"; these are the C10 rows
for them. Each row names Cameleer's code (read in `E:\Work\DataHQ\Code\Rust-camel`), what simoom
provides and the test that proves it._

## C8: content compression (`crates/simoom-compress`, facade feature `compression`)

### The codec, against Cameleer's `cameleer-core/src/dataformat/compress.rs`

| Cameleer | simoom | test |
|---|---|---|
| `inflate_raw` / `inflate`: stored, fixed and dynamic blocks, bit-at-a-time Huffman decoding, one-shot only | `Decoder` (streaming, resumable at any byte, 10/8-bit lookup tables with second-level tables) and `decompress` (one-shot, output buffer is the history) | `simoom-compress/tests/roundtrip.rs` `rfc1951_fixed_and_stored_vectors`, `streaming_in_pieces_matches_one_shot` |
| `deflate(level)`: hash chains, greedy, fixed Huffman only (or stored at level 0) | `Encoder`: hash chains, lazy matching (levels 4-9), zlib's level table, stored/fixed/dynamic blocks chosen by size, length-limited codes, sync flush | `round_trip_every_level_and_format`, `sync_flush_makes_data_decodable`, `deflate.rs` `length_limit_holds` |
| `gzip_compress` / `gzip_decompress` (multi-member, FEXTRA/FNAME/FCOMMENT/FHCRC skipped, trailing zero padding) | `Format::Gzip`: the same, FHCRC verified, ISIZE and CRC-32 checked, streaming | `rfc1950_and_rfc1952_headers`, `multi_member_gzip_and_trailing_bytes`, `zlib_produced_dynamic_blocks` (Python zlib output) |
| `zlib_compress` / `zlib_decompress` (raw DEFLATE accepted as a fallback; FDICT refused; Adler-32 checked only when present) | `Format::Zlib` (Adler-32 always checked) and `Format::ZlibOrRaw` (zlib if the header is valid, else raw: HTTP `deflate` from servers that send raw) | `zlib_or_raw_detects_both`, `errors_are_reported` |
| `crc32`, `adler32` | `crc32`, `adler32`, incremental `Crc32`, `Adler32` (slicing-by-8 CRC) | `checksum.rs` `known_values` |
| `inflate_limited` (an internal size limit, not exposed) | `Decoder::with_limit`, `decompress(.., limit)`: a decompression-bomb limit; output never passes it | `decompression_bomb_is_stopped`, fuzz invariant |
| no streaming either way | `Decoder::decode` (into a `Vec`), `Decoder::decode_into` (into a slice: a fixed per-call bound), `Encoder::encode` / `flush` / `finish`; memory bounded (decoder: 64 KiB window + ~8 KiB tables; encoder: ~256 KiB) | `streaming_in_pieces_matches_one_shot` (1-byte input, 61-byte output slices) |
| no fuzzing | std-only seeded mutation fuzzer: one-shot vs streamed (two ways) agreement, limits, no panic | `tests/fuzz.rs` (3 × 200,000 inputs run clean in release) |
| ZIP (`zip_create`, `zip_read`), the `gzipDeflater` / `zipDeflater` / `zipFile` data formats | not in scope (data formats stay in Cameleer; they can call `simoom_compress`) | — |

**Brotli and zstd (owner decision, 2026-11-09: added for third-party users).** Cameleer
supports neither for HTTP (its producer offers `gzip, deflate`; zstd appears only in its Kafka
client, which refuses it), so these are "beyond Cameleer" rows; see the Brotli and zstd section
below.

### Speed and ratio

`cargo run --release -p simoom-compress --example bench_compress` (gzip format, both
implementations in the same binary; each figure the best of 5 timed runs; Ryzen 5 5600X, Windows
11). Compress = input MB/s, decompress = output MB/s, ratio = compressed / original. Each side
decodes the other's output (asserted). zlib 1.3.1 through Python on the same files
(`examples/zlib_baseline.py`) as a sanity check.

| input (1 MiB) | level | simoom ratio | Cameleer ratio | zlib ratio | simoom compress | Cameleer compress | zlib compress | simoom decompress | Cameleer decompress | zlib decompress |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| JSON | 1 | 0.220 | 0.237 | 0.220 | 194 | 108 | 145 | 507 | 182 | 536 |
| JSON | 6 | 0.165 | 0.227 | 0.165 | 71 | 70 | 54 | 584 | 193 | 360 |
| JSON | 9 | 0.159 | 0.222 | 0.159 | 17 | 31 | 11 | 456 | 189 | 369 |
| access log | 1 | 0.167 | 0.170 | 0.167 | 247 | 111 | 172 | 471 | 215 | 647 |
| access log | 6 | 0.122 | 0.164 | 0.122 | 85 | 86 | 72 | 697 | 207 | 403 |
| access log | 9 | 0.115 | 0.162 | 0.115 | 31 | 62 | 27 | 696 | 212 | 758 |
| Rust source | 1 | 0.310 | 0.310 | 0.314 | 163 | 83 | 100 | 363 | 149 | 396 |
| Rust source | 6 | 0.252 | 0.302 | 0.255 | 50 | 34 | 40 | 277 | 81 | 413 |
| Rust source | 9 | 0.251 | 0.300 | 0.253 | 16 | 43 | 14 | 377 | 100 | 434 |
| machine code (319 KiB) | 1 | 0.491 | 0.532 | 0.490 | 60 | 62 | 61 | 202 | 94 | 259 |
| machine code | 6 | 0.462 | 0.529 | 0.462 | 37 | 53 | 25 | 305 | 74 | 333 |
| machine code | 9 | 0.460 | 0.528 | 0.460 | 9 | 44 | 12 | 239 | 112 | 334 |
| random | 1 | 1.000 | 1.054 | 1.000 | 62 | 45 | 45 | 1517 | 62 | 1426 |
| random | 6 | 1.000 | 1.054 | 1.000 | 62 | 25 | 44 | 1439 | 36 | 1794 |
| random | 9 | 1.000 | 1.054 | 1.000 | 33 | 29 | 43 | 645 | 54 | 1441 |

- **Ratio:** the same as zlib's at every level (within 0.003), 13-27% smaller output than
  Cameleer at levels 6 and 9 (Cameleer has no dynamic Huffman blocks and no lazy matching);
  incompressible data costs 5 bytes per 64 KiB instead of Cameleer's 5.4% growth.
- **Decompression:** 2.3-4.7x Cameleer on text, 25-40x on stored data; within zlib's range
  (faster on JSON, slower on source and machine code).
- **Compression:** 1.3-2.3x Cameleer at level 1 (and smaller output). Level 6 runs at
  0.65-1.15x Cameleer's level-6 speed (equal on JSON and logs, slower on source and machine
  code, where its lazy matching finds much more) for 13-27% smaller output. Level 9 is slower
  than Cameleer's level 9 because it searches 16x longer chains (zlib's table), for 16-28%
  smaller output. At or above zlib's speed at levels 1 and 6.
- The machine was shared with other builds: a second run moved individual figures by up to
  ±20% but kept every comparison above.

### The server side (facade feature `compression`)

Cameleer's HTTP server compresses nothing (no `Accept-Encoding` handling in
`cameleer-http/src/server.rs`, `http.rs` or `platform.rs`); its producer's request-side
compression (`Content-Encoding: gzip|deflate` on a request compresses the body) is client
work (C5).

| behaviour | simoom | test |
|---|---|---|
| `Accept-Encoding` with q-values, `*`, `x-gzip`, `identity`; gzip wins ties | `compress::choose` | `compress.rs` `accept_encoding_negotiation` |
| thresholds: size (`Compression::min_size`, default 1 KiB) and content type (text, JSON, XML, JS, `+json`/`+xml`, SVG, extra types); no type, images, audio, video, archives left alone | `compress::eligible` | `content_types`, `whole_bodies` |
| not when the service set `content-encoding` or `content-range`, `cache-control: no-transform`, status 1xx/204/206/304, or when compressing doesn't make it smaller | `compress::eligible`, `apply` | `whole_bodies`, `tests/compression.rs` `negotiated_responses_on_http1` |
| `vary: accept-encoding` on every response that could be compressed (also uncompressed ones); strong `etag` made weak | `add_vary`, `mark` | same |
| immediate replies, deferred (`Responder::send`, compressed on the responder's thread), offloaded (`blocking`, `Reply::offload`), streamed (`Compression::streams`, sync flush per write, off by default) | `Reply::finish`, `Responder::send` / `stream`, `BodySink` | `deferred_offloaded_and_streamed_replies`, `streamed_chunks_arrive_promptly` |
| HTTP/1.1, HTTP/2 (and HTTP/3: the same `Reply` path) | protocol independent | `negotiated_responses_on_http1`, `negotiated_responses_on_http2` |
| request bodies: `Request::decoded_body(limit)` (buffered; up to two codings; 415/413/400 through `DecodeBodyError::status`), `Request::take_decoded_body(limit)` / `DecodedRead` (streamed) | opt-in API, zero cost when unused | `request_bodies_are_decoded_on_request`, `streamed_request_bodies_are_decoded`, `compress.rs` `request_codings` |

## C6 (server half): WebSocket over HTTP/2 (RFC 8441)

Cameleer has none: `cameleer-grpc/src/h2/mod.rs` lists "RFC 8441 extended CONNECT" under "Not
implemented", and `cameleer-http` has WebSocket on HTTP/1.1 only. simoom goes beyond parity here.

| behaviour | simoom | test |
|---|---|---|
| `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` from servers that enable it (`Config::enable_connect_protocol`, simoom-h2 feature `connect-protocol`, on by default there; the facade enables it with its `websocket-h2` feature); clients never send it | `simoom-h2` `local_settings` | `simoom-h2/tests/extended.rs` `server_announces_and_accepts_extended_connect` |
| `:protocol` accepted only when enabled; extended CONNECT needs `:scheme`, `:path`, `:authority`; malformed → stream error | `Headers::protocol`, `Headers::finish` | `headers.rs` `extended_connect`, `protocol_pseudo_header_needs_the_setting` |
| the peer's setting: 0 or 1, never 0 after 1 (PROTOCOL_ERROR) | `apply_settings`, `Connection::peer_connect_protocol` | `enable_connect_protocol_values_are_checked` |
| client role: `send_extended_connect` (refused with `ConnectProtocolDisabled` before the server allows it) | `simoom-h2` | `websocket_tunnel_end_to_end` |
| facade: `Request::is_websocket_upgrade` true for `:protocol websocket`; `Reply::websocket` / `websocket_with_protocol` answer 200 (with `sec-websocket-protocol`) and run the same `WebSocketHandler` on the stream; other streams carry on | `h2.rs` `Target::websocket`, `ws.rs` `WsCore` (shared with HTTP/1.1) | `tests/h2_websocket.rs` `websocket_over_http2` |
| `WsHandle` from other threads (routed by stream id), fragmentation across DATA frames, ping/pong, closing handshake ending the stream, flow-controlled output | same | same |
| client reset → handler `on_close(1006)`; client END_STREAM without close → 1006 and the stream ends; server stop → 1001; `Reply::websocket` on a plain request → 400 | same | `http2_websocket_refusals_and_lost_peers` |

## C7: HTTP/2 PING keepalive

Cameleer's HTTP/2 answers PINGs and sends them on request (`H2Connection::ping`), but has no
keepalive timer (`cameleer-grpc/src/h2/conn.rs`); simoom adds one.

| behaviour | simoom | test |
|---|---|---|
| after `keepalive_interval_ms` without any frame from the peer, send a PING; any received byte counts as activity | `simoom-h2` `Connection::keepalive`, `poll_timeout`, `handle_timeout` | `simoom-h2/tests/extended.rs` `keepalive_pings_a_quiet_peer_and_closes_a_dead_one` |
| no answer within `keepalive_timeout_ms` → GOAWAY(NO_ERROR), `Event::Closed`, `wants_close` | same | same |
| off by default; works for either role (the client half of C7 is the client agent's wiring) | `Config::keepalive_interval_ms: None` | `keepalive_is_off_by_default_and_works_on_clients` |
| facade (feature `h2-keepalive`): `Limits::h2_keepalive` (default `None`) and `Limits::h2_keepalive_timeout` (default 20 s); a dead client's connection is closed and its streams cancelled, a live one with a long call stays | `server.rs` (h2 `Config`), `H2Layer::tick` / `deadline` (existing timer path) | `tests/grpc.rs` `ping_keepalive_closes_dead_connections_and_keeps_live_ones` |

## C9: gRPC parity

What `cameleer-grpc` (`src/grpc/{server,client,mod}.rs`, over its own `src/h2`) needs from
HTTP/2, server side. Message framing, status codes, `grpc-timeout` parsing and protobuf stay in
Cameleer's gRPC layer; they sit on top of these.

| need (where in cameleer-grpc) | simoom | test |
|---|---|---|
| h2c prior knowledge and h2 over TLS with ALPN `h2` (`GrpcServer::bind` with or without TLS) | facade `http2` (+ `tls`) | `tests/http2.rs`, `tests/tls.rs` |
| request headers: `:method POST`, `:path /Service/Method`, `content-type: application/grpc`, `te: trailers`, `user-agent`, `grpc-timeout`, `grpc-encoding`, `grpc-accept-encoding`, metadata (`-bin` values passed as sent) (`server.rs` `handle`) | `Request::header` / `headers`; `te: trailers` is the one `te` value HTTP/2 allows and it reaches the service | `tests/grpc.rs` `unary_streaming_and_trailers_only` (`x-seen-te`, `x-seen-timeout`) |
| response headers then DATA then trailers `grpc-status`, `grpc-message`, custom trailer metadata (`ServerCall::finish`) | `Reply::trailer` (U5), `Response::trailer`, `BodySink::finish_with_trailers` | `unary_streaming_and_trailers_only` |
| trailers-only responses (`finish` before any message: one HEADERS with END_STREAM) | `Reply::header(..).empty()`: one HEADERS frame with END_STREAM | same (`header_end`) |
| server streaming (`ServerCall::send` per message) | `Reply::stream` + `BodySink::write`, no `content-length`, backpressure through `stream_buffer` | same (5 messages + trailers) |
| client streaming and bidi (`ServerCall::recv` reading DATA as it comes) | `Request::take_body` → `BodySource` with flow-control credit as it is read; request trailers reach the service (bug 14) | `client_streaming_with_flow_control` (~200 KB through a 1 KiB body buffer) |
| flow control both ways (stream and connection windows, WINDOW_UPDATE) | `simoom-h2` windows, auto-tuning, release on consumption | `client_streaming_with_flow_control`, `simoom-h2/tests/roundtrip.rs` |
| message framing with the compressed flag; `grpc-encoding: gzip` / `deflate` per message (`frame_message_with`, `MessageDecoder`, using Cameleer's compress.rs) | framing is gRPC-layer (stays in Cameleer); the codec can be `simoom_compress` (gzip, zlib) | `per_message_compression` (flag 1, gzip both ways) |
| many concurrent calls on one connection; `SETTINGS_MAX_CONCURRENT_STREAMS` | `Limits::max_concurrent_streams` | `unary_streaming_and_trailers_only` (20 calls) |
| deadlines and cancellation: client RST_STREAM(CANCEL) ends the call (`H2Error::StreamReset` → `Cancelled`) | `Responder::is_cancelled` / `on_cancel` (U2), `BodySource` fails, `BodySink` writes fail | `cancellation_by_rst_stream_reaches_the_responder` |
| server-side deadline (`grpc-timeout` → `deadline`) | the service reads `grpc-timeout`; `Limits::defer_timeout` is a server-wide cap (504) | `unary_streaming_and_trailers_only` (header passed) |
| aborting a call (`H2Stream::reset`) | `BodySink::abort` → RST_STREAM(INTERNAL_ERROR) | `tests/http2.rs` |
| max message size (`maxMessageSize`, default 4 MiB) | gRPC layer; `Limits::max_body` bounds buffered bodies | — |
| header list limits | `Limits::max_header_list` (SETTINGS_MAX_HEADER_LIST_SIZE, enforced both ways, bug 9) | `simoom-h2/tests/conformance.rs` |
| PING answered; GOAWAY graceful stop (`GrpcServer::stop`) | `simoom-h2`; `ServerHandle::stop` | `tests/http2.rs` |
| keepalive for long streams (not in Cameleer) | C7 above | `ping_keepalive_closes_dead_connections_and_keeps_live_ones` |
| client role (`GrpcClient`): `te: trailers`, `grpc-timeout`, trailers, RST_STREAM(NO_ERROR) after a complete response (U11) | `simoom-h2` client role; the HTTP client is C5 (client agent) | the client agent's tests |

## Beyond Cameleer: Brotli and zstd (simoom-compress features `brotli`, `zstd`; facade features of the same names)

| behaviour | simoom | test |
|---|---|---|
| Brotli decoder (RFC 7932): stream header and window sizes 2^10-2^24, meta-blocks (compressed, uncompressed, metadata), simple and complex prefix codes, block switching in all three categories, context modes and context maps (with RLE and inverse move-to-front), distance codes with NPOSTFIX/NDIRECT and the distance ring, the 122,784-byte static dictionary with all 121 transforms | `brotli/decode.rs` (transactions over the carried input: resumes at any byte; a retry re-reads at most one prefix code or context map) | `tests/brotli_zstd.rs` `brotli::reference_streams_decode`: 28 streams from the reference implementation (brotli 8.0.4, qualities 0-11, windows 2^10, 2^16, 2^22, 2^24), in one go, in random pieces and byte by byte into small slices |
| the dictionary | DEFLATE-compressed in the binary (58,898 bytes), inflated once on first use | `brotli::tests::dictionary_matches_the_rfc` (SHA-256 `20e42eb1…`, RFC 7932 Appendix A) |
| Brotli encoder, qualities 0-11 | `brotli/encode.rs`: LZ77 (hash chains, lazy from 5), meta-blocks of 1 MiB with one prefix code per category, last-distance and implicit-distance commands, uncompressed meta-blocks for incompressible data, flush through an empty metadata block. No context modelling or dictionary references, so output is 5-12% larger than the reference at the same quality | `brotli::our_streams_round_trip` (every quality, flushes), and the reference decoder decoded every stream we produced (8 inputs × 7 qualities, scripted check) |
| zstd decoder (RFC 8878): frames, skippable frames, several frames in a row, raw/RLE/compressed blocks, Huffman literals (direct and FSE-coded weights, one or four streams, treeless reuse), FSE sequences (predefined, RLE, fitted, repeated tables), repeat offsets, content size and XXH64 checksum, dictionaries (`Decoder::add_dictionary`: zstd-format by id, or raw content) | `zstd/decode.rs`, `zstd/fse.rs` (input carried per unit, a block at most 128 KiB) | `zstd::reference_streams_decode`: 25 streams from libzstd 1.5.7 (levels 1, 3, 9, 19, with and without checksum); `fse::tests` (XXH64 vectors, FSE table round trips) |
| zstd encoder, levels 1-22 | `zstd/encode.rs`, `zstd/fast.rs`: zstd's fast (1) and double-fast (2-3) match finders with zstd's parameters, chained (4-5), lazy (6+), Huffman literals with direct or FSE weights, sequences in predefined/RLE/fitted FSE tables (whichever is smallest), repeat offsets, checksum | `zstd::our_streams_round_trip`, and libzstd decoded every stream we produced (8 inputs × 6 levels, scripted check) |
| bombs and memory | output limit as for DEFLATE; window caps `Decoder::window_limit` (defaults: Brotli 16 MiB, every valid stream; zstd 8 MiB, RFC 9659); the decoder holds up to twice the window, growing only as output arrives | `limits_windows_and_errors` (both formats: 8 MiB of zeros under a 1 MiB limit; a 16 MiB-window stream refused under a 4 MiB cap; truncation at every byte) |
| fuzzing | std-only mutation fuzzer seeded with the reference and our own streams: one-shot vs streamed agreement, limits, no panic | `tests/fuzz_brotli_zstd.rs` (3 × 200,000 inputs per decoder, clean in release) |
| HTTP: `br` and `zstd` negotiated with q-values; among equal q-values the server's order (`Compression::preference`, default zstd, br, gzip, deflate), zstd/br only from `Compression::modern_min_size` (1 KiB) up; request bodies in br and zstd decode through `Request::decoded_body` | facade `compress.rs` | `compress.rs` `accept_encoding_negotiation`, `tests/compression.rs` `brotli_and_zstd_responses` |

Speed and ratio against the reference implementations on the same 1 MiB inputs (compress = input
MB/s, decompress = output MB/s; Brotli on Windows 11, both sides there; zstd on WSL2 Ubuntu,
both sides there; best of 5 runs on a shared machine, so treat figures as ±20%):

**Brotli** (simoom vs the brotli 8.0.4 crate, window 2^22)

| input (1 MiB; machine code 320 KiB) | level | simoom ratio | reference ratio | simoom compress | reference compress | simoom decompress | reference decompress |
|---|---:|---:|---:|---:|---:|---:|---:|
| json | 1 | 0.215 | 0.179 | 119.3 | 201.5 | 185.9 | 255.2 |
| json | 4 | 0.184 | 0.161 | 89.6 | 64.4 | 203.3 | 327.5 |
| json | 9 | 0.161 | 0.143 | 18.2 | 15.4 | 274.9 | 434.1 |
| json | 11 | - | 0.119 | - | 0.7 | - | 274.8 |
| log | 1 | 0.160 | 0.151 | 137.1 | 268.5 | 227.3 | 342.7 |
| log | 4 | 0.137 | 0.121 | 75.8 | 73.7 | 232.3 | 315.2 |
| log | 9 | 0.115 | 0.106 | 29.2 | 20.9 | 304.3 | 428.8 |
| log | 11 | - | 0.094 | - | 0.7 | - | 419.3 |
| source | 1 | 0.294 | 0.287 | 88.2 | 158.7 | 148.8 | 253.9 |
| source | 4 | 0.253 | 0.250 | 64.3 | 45.4 | 153.1 | 214.0 |
| source | 9 | 0.234 | 0.219 | 22.4 | 11.8 | 169.2 | 236.6 |
| source | 11 | - | 0.199 | - | 0.7 | - | 207.9 |
| binary | 1 | 0.498 | 0.517 | 50.7 | 82.1 | 81.9 | 135.0 |
| binary | 4 | 0.477 | 0.468 | 40.0 | 38.5 | 122.5 | 125.8 |
| binary | 9 | 0.463 | 0.432 | 24.6 | 8.7 | 116.0 | 142.6 |
| binary | 11 | - | 0.396 | - | 0.7 | - | 133.7 |

**zstd** (simoom vs libzstd 1.5.7), after the speed pass of 2026-11-09 (see below for what
changed). Before = the first version, after = now, both against libzstd in the same interleaved
run (best of 3, WSL2, load average under 1). All encoders write the content checksum. "dec own" is
each decoder on its own encoder's stream ("before" also allocated a fresh output per call, as the
old benchmark did; "after" reuses it, as libzstd's harness does); "dec same" is ours and libzstd's
decoder on libzstd's stream.

| input (1 MiB; machine code 320 KiB) | level | ratio before / after / libzstd | compress MB/s before / after / libzstd | compress x before -> after | dec own MB/s before / after / libzstd | dec same stream ours / libzstd (x) |
|---|---:|---|---|---|---|---|
| json | 1 | 0.214 / 0.162 / 0.155 | 203 / 341 / 679 | 0.30 -> 0.50 | 371 / 1219 / 1754 | 1344 / 1707 (0.79) |
| json | 2 | 0.213 / 0.160 / 0.162 | 203 / 328 / 601 | 0.34 -> 0.54 | 382 / 1365 / 1574 | 1223 / 1548 (0.79) |
| json | 3 | 0.187 / 0.161 / 0.159 | 159 / 324 / 522 | 0.31 -> 0.62 | 729 / 1342 / 1728 | 1326 / 1734 (0.76) |
| json | 9 | 0.163 / 0.163 / 0.140 | 50 / 51 / 77 | 0.65 -> 0.66 | 815 / 1540 / 1970 | 1484 / 1976 (0.75) |
| log | 1 | 0.162 / 0.139 / 0.139 | 251 / 452 / 766 | 0.33 -> 0.59 | 455 / 1645 / 2209 | 1679 / 2228 (0.75) |
| log | 2 | 0.160 / 0.138 / 0.137 | 250 / 390 / 712 | 0.35 -> 0.55 | 459 / 1621 / 2112 | 1588 / 2130 (0.75) |
| log | 3 | 0.143 / 0.140 / 0.138 | 186 / 372 / 574 | 0.32 -> 0.65 | 895 / 1542 / 1972 | 1530 / 1975 (0.77) |
| log | 9 | 0.119 / 0.119 / 0.106 | 82 / 87 / 103 | 0.80 -> 0.85 | 1025 / 1933 / 2826 | 2162 / 2869 (0.75) |
| source | 1 | 0.293 / 0.292 / 0.288 | 150 / 252 / 451 | 0.33 -> 0.56 | 294 / 1106 / 1508 | 1144 / 1518 (0.75) |
| source | 2 | 0.287 / 0.267 / 0.276 | 151 / 209 / 378 | 0.40 -> 0.55 | 409 / 1139 / 1387 | 1049 / 1381 (0.76) |
| source | 3 | 0.259 / 0.261 / 0.261 | 120 / 199 / 303 | 0.40 -> 0.66 | 469 / 1063 / 1395 | 1076 / 1407 (0.76) |
| source | 9 | 0.237 / 0.237 / 0.229 | 47 / 50 / 64 | 0.74 -> 0.79 | 358 / 1112 / 1553 | 1178 / 1573 (0.75) |
| binary | 1 | 0.491 / 0.508 / 0.521 | 125 / 251 / 464 | 0.27 -> 0.54 | 317 / 1050 / 1325 | 1130 / 1344 (0.84) |
| binary | 2 | 0.485 / 0.494 / 0.499 | 99 / 176 / 347 | 0.29 -> 0.51 | 259 / 1050 / 1293 | 1071 / 1294 (0.83) |
| binary | 3 | 0.472 / 0.479 / 0.479 | 66 / 120 / 255 | 0.26 -> 0.47 | 271 / 984 / 1176 | 933 / 1163 (0.80) |
| binary | 9 | 0.458 / 0.458 / 0.462 | 42 / 43 / 73 | 0.58 -> 0.59 | 282 / 930 / 1178 | 980 / 1189 (0.82) |
| random | 1 | 1.000 / 1.000 / 1.000 | 371 / 698 / 2786 | 0.13 -> 0.25 | 9646 / 13534 / 13362 | 13497 / 13271 (1.02) |
| random | 3 | 1.000 / 1.000 / 1.000 | 320 / 607 / 2560 | 0.13 -> 0.24 | 10686 / 13785 / 13468 | 13732 / 13442 (1.02) |
| random | 9 | 1.000 / 1.000 / 1.000 | 35 / 37 / 512 | 0.07 -> 0.07 | 11078 / 13728 / 13468 | 13669 / 13268 (1.03) |

Brotli decoding after the same pass (Windows 11, both decoders on the reference's stream, best
of 3; compression is unchanged from the table above):

| input | quality | ours MB/s | reference MB/s | x (before: own stream, same run) |
|---|---:|---:|---:|---|
| json | 1 | 250 | 287 | 0.87 |
| json | 5 | 387 | 388 | 1.00 |
| json | 9 | 426 | 472 | 0.90 |
| log | 1 | 355 | 391 | 0.91 |
| log | 5 | 612 | 548 | 1.12 |
| log | 9 | 685 | 542 | 1.26 |
| source | 1 | 206 | 274 | 0.75 |
| source | 5 | 219 | 286 | 0.77 |
| source | 9 | 244 | 316 | 0.77 |
| binary | 1 | 185 | 170 | 1.08 |
| binary | 5 | 144 | 188 | 0.76 |
| binary | 9 | 143 | 188 | 0.76 |

Our own Brotli decode in the same run, before -> after: json q1/q5/q9 203/263/302 -> 236/387/422
MB/s, log 280/305/346 -> 372/581/640, source 162/195/228 -> 197/262/264, binary 127/142/130 ->
178/137/194.

- **Brotli:** output 1-12% larger than the reference at the same quality (we have no context
  modelling, block splitting or dictionary references; on machine code ours is smaller at
  quality 1); our encoder is faster from quality 4 up and 0.54-0.70x at quality 1 (unchanged by
  the speed pass); our decoder runs at 0.75-1.26x the reference.
- **zstd:** output within 5% of libzstd at levels 1-3 (JSON level 1: +4.2%, was +38%), within
  3% at level 9 on text, smaller on machine code. Compression at levels 1-3 runs at
  0.47-0.66x libzstd on compressible input (was 0.26-0.40x) and 0.25x on random input (was 0.13x);
  decompression at 0.75-0.84x on compressible input (was 0.2-0.4x) and 1.02x on stored blocks.
  Both directions are verified against libzstd byte for byte (libzstd decoded every stream we
  produced at levels 1, 2, 3, 5, 9 and 19 on all five inputs after the pass).

**Third pass (2026-11-09, owner: "Yes, close the gap").** The hot loops are now unchecked
pointer code in `simoom_sys::codec`, each `unsafe` block with its invariant: `zstd_sequences`
(the sequence decode/execute loop: lengths, offsets and the bitstream checked per sequence,
copies into the 32 bytes of slack), `huf4` (the four-stream Huffman fast loop), `zstd_fast`
(the level 1-3 match finders) and `zstd_seq_stream` (the sequence bitstream writer). The safe
implementations in simoom-compress stay as the reference: `codec::set_safe_only` switches a
thread to them, every fuzz input is decoded both ways and compared, and the round-trip tests
compare compressed bytes and output both ways and for both BMI2 settings; libzstd decodes our
output at levels 1, 2, 3, 5, 9 and 19. A debug build (overflow checks, debug assertions) of the
whole suite with 20,000 fuzz inputs per decoder passes in WSL; Miri and AddressSanitizer need a
nightly toolchain, which this machine does not have (offline). BMI2 copies are kept only for the
two decode loops (about 4% fewer instructions); the earlier duplicated kernels were removed (no
measured gain), which brought the zstd row back down by 33 KB. Results (interleaved, best of 3):
decoding libzstd's streams 0.77-0.83x on text and 0.83-0.91x on machine code (instructions per
byte 1.24-1.27x libzstd's); compression at levels 1/3 0.55/0.70x JSON, 0.62/0.71x logs, 0.62/0.73x
source, 0.61/0.50x machine code (instructions 1.5-1.8x). Not done: the Brotli quality 0-1
fragment compressor and the Brotli source-code decode path.

**Second pass (2026-11-09, BMI2 approved in simoom-sys).** `simoom_sys::bits::with_bmi2` runs a
`Kernel` (safe code, `#[inline(always)]`) inside a function compiled with BMI1, BMI2 and LZCNT
when the CPU has them (runtime detection; otherwise the same code built for the base target);
`set_scalar_only` (per thread) forces the base build, and the round-trip tests and the fuzzers
check both builds agree. The zstd sequence loop, the Huffman literal loops and the encoder's block
stage run as kernels. Plus: one bounds check per match copy, branchless repeat-offset lookup in
the encoder, literals gathered 16 bytes at a time, fewer bit-writer flushes. Interleaved
wall-clock after this pass (WSL2, best of 3, against libzstd in the same run): compression at
levels 1/3 is 0.53/0.67x on JSON, 0.62/0.68x on logs, 0.59/0.68x on source, 0.59/0.49x on machine
code (0.53-0.55x on random input); decoding libzstd's streams is 0.74-0.77x on text and
0.80-0.86x on machine code. Per byte, our decoder executes 1.39-1.45x libzstd's instructions and
our level-1 encoder 2.1-2.3x. BMI2 changed the instruction count by about 2%: the excess is not
in bit extraction but in register pressure (the sequence loop keeps about 19 values live: spills
and reloads are about a third of its hot instructions), bounds checks on the slices, and the
two-copies-per-sequence structure; libzstd's Huffman decoding on x86-64 is hand-written
assembly (`huf_decompress_amd64.S`). Moving the copies into `unsafe` helpers in simoom-sys was
tried and measured slower (16-byte loops around a variable length), so they stay safe. Brotli:
running its decoder as a BMI2 kernel and batching literals per block type were tried and measured
no faster or slower, and were taken out.

**The speed pass (2026-11-09), what changed.** Decoder: one-shot decoding into the caller's
buffer (no window copy), output room reserved from the frame's content size; a 64-bit backward
bit reader refilled once per sequence (zstd's `BIT_DStream`); sequence tables with base values
and extra bits folded in, the three in one 2048-entry table indexed by masked absolute states;
sequences decoded and executed in one pass (overlapping a match copy's latency with the next
decode) with 16-byte literal and match copies into slack and zstd's 8-byte spreading for offsets
under 16; Huffman literals through an 11-bit table with constant shifts, and zstd's fast
four-stream loop (left-aligned containers with a marker bit, five symbols per stream per refill).
Brotli: a literal loop without per-literal block-switch or context work when the meta-block has
one literal block type. Encoder: zstd's fast (level 1, ported loop) and double-fast (levels 2-3)
match finders with zstd's parameters, zstd's quick "not worth a Huffman code" test and a
size estimate before coding literals, a bit writer that stores whole words, fixed-size FSE
encoding tables. Measured with instruction and cycle counts per byte (`perf stat`) as well as
wall time, since the machine was shared: per output byte our decoder executes 1.4-1.5x
libzstd's instructions (libzstd also uses BMI2 through runtime dispatch and assembly Huffman
loops on x86-64, which safe std-only Rust without `unsafe` cannot select at run time); our
level-1 encoder executes about 2.3x.

**What the client should call (C5):** `simoom_compress::Format::from_content_encoding(token)`
maps `gzip`, `x-gzip`, `deflate`, `br` and `zstd` (the last two with the features on) to a
format; then `Decoder::with_limit(format, limit)`, optionally `.window_limit(bytes)`, and
`decode` / `decode_into` / `finish` as for gzip. Offer `Accept-Encoding: zstd, br, gzip, deflate`
when the features are on. simoom-client already forwards `simoom-compress/brotli` and
`simoom-compress/zstd` through its `compress-br` and `compress-zstd` features.

## Beyond Cameleer: L7 server helpers (facade features `multipart`, `cookies`, `conditional`, `cors`)

| behaviour | simoom | test |
|---|---|---|
| `multipart/form-data` (RFC 7578): a streaming sans-io `MultipartParser` (holds one part head and a delimiter's length of content), `parse` and `Request::multipart` for buffered bodies; preamble, transport padding, epilogue, quoted and RFC 5987 `filename*`; limits on parts, header size, part size and total (413 through `MultipartError::status`) | `multipart.rs` | `multipart::tests` (one go and 1-13-byte pieces, limits, malformed bodies), `tests/server_helpers.rs` `multipart_uploads` (buffered, and 200 KB streamed through a `BodySource`) |
| cookies (RFC 6265bis): `Request::cookie` / `cookies` across every `Cookie` header, `SetCookie` with `Expires`, `Max-Age`, `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`, removal cookies; names, values and attributes validated (an invalid cookie makes the reply a 500); `Reply::cookie`, `Response::cookie` | `cookie.rs`, `httpdate.rs` | `cookie::tests`, `httpdate::tests`, `cookies_in_and_out` |
| conditional requests (RFC 9110 §13): `If-Match`, `If-Unmodified-Since`, `If-None-Match` (weak comparison), `If-Modified-Since` in the RFC's order; HTTP dates in all three formats | `conditional.rs` `Request::preconditions` | `conditional_and_range_requests` (304 for ETag and date, 412) |
| range requests (RFC 9110 §14): `bytes=` with suffix and open ranges, merging, at most 16 ranges (more get the whole body), `If-Range` (strong ETag or date), 206 with `Content-Range`, `multipart/byteranges` for several ranges, 416 with `bytes */len`; `Reply::content` does conditional + range + `Accept-Ranges` in one call | `conditional.rs` `Request::ranges`, `Reply::content` | `conditional::tests`, `conditional_and_range_requests` |
| CORS: `Cors` wraps any service; allowed origins (list or any), methods, request headers (list or any), exposed headers, credentials (echoes the origin instead of `*`), `Max-Age`, Private Network Access; preflights answered with 204; `Vary: Origin` when the answer depends on it | `cors.rs` | `cors_preflight_and_actual` |

## Beyond Cameleer: L2 server-side authentication (facade feature `auth`)

| behaviour | simoom | test |
|---|---|---|
| Basic (RFC 7617): `basic_credentials` (UTF-8, control characters refused), `Basic::new(realm, lookup)` with the stored password compared in constant time (unknown users against a dummy), `challenge` with `charset="UTF-8"` | `auth.rs` | simoom-client `tests/server_auth.rs` `basic_and_bearer`, `curl_against_server_auth` |
| Digest (RFC 7616): one challenge per algorithm (SHA-256, SHA-512-256, MD5, each with `-sess`), `qop=auth` and optionally `auth-int` (buffered bodies), `opaque`, `charset=UTF-8`; `username*` (RFC 8187); the lookup returns a password or a stored HA1 | `auth.rs` `Digest` | unit `auth::tests::digest_verify_counts_stale_and_rspauth` (answers computed independently for each algorithm, wrong password, uri, user, forged nonce, unoffered algorithm, auth-int with and without a buffered body, stored HA1); `server_auth.rs` `digest_every_algorithm_with_rspauth` |
| stateless nonces: issue time + 8 random bytes + HMAC-SHA-256 (truncated to 16 bytes) under a per-process key or `Digest::secret` (shared by instances); valid credentials on an expired nonce get `stale=true`; `nextnonce` in `Authentication-Info` after half the TTL | `auth.rs` | unit (stale after the TTL, `nextnonce` after half, nonces of another key refused, a shared secret across two instances); `server_auth.rs` `digest_stale_nextnonce_auth_int_and_refusals` (the client follows `nextnonce` and answers `stale=true`) |
| replay protection: a 64-wide window of nonce counts per nonce (a repeated or too-old `nc` is refused, overtaking requests pass), a bounded table that forgets expired nonces first | `auth.rs` `Digest::count` | unit `digest_verify_counts_stale_and_rspauth`, `nonce_count_table_is_bounded` |
| `rspauth` (`qop=auth`), `qop`, `nc`, `cnonce` in `Authentication-Info` | `auth.rs` | unit (rspauth recomputed); `server_auth.rs` (the client checks it); curl's `-i` output shows it |
| Bearer (RFC 6750): `bearer_token` (token68 syntax checked); `Auth::bearer(realm, validate)`, `error="invalid_token"` when a token was refused | `auth.rs` | `basic_and_bearer`, `interceptors_on_calls` |
| `Auth::wrap(service)` / `wrap_with_user(handler)` (a `Service`, like `Cors::wrap`): unauthenticated requests get 401 with every configured challenge (Digest first, then Basic, then Bearer); success adds `Authentication-Info` and calls the handler with the user; `Auth::authenticate` for routers that decide themselves | `auth.rs` `AuthService` | `server_auth.rs` (Digest, Basic, Bearer, WebSocket upgrades behind it) |
| against real clients | curl `--digest` (MD5 with Windows' Schannel curl; MD5 and SHA-256 with curl 8.5 on Linux) and `--basic` accepted, a wrong password gets 401 | | `server_auth.rs` `curl_against_server_auth`. curl before 8.8 answers `SHA-512-256` with a SHA-256 hash (checked by hand against curl 8.5), so that row is skipped with a note; simoom-client covers SHA-512-256 |

## Beyond Cameleer: L8 WebSocket over HTTP/3 and permessage-deflate

| behaviour | simoom | test |
|---|---|---|
| WebSocket over HTTP/3 (RFC 9220): simoom-h3 sends SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) when `Config::enable_connect_protocol` is set, refuses `:protocol` otherwise (H3_MESSAGE_ERROR), checks the peer's value (0/1); `Http3::peer_connect_protocol` for clients | `simoom-h3` `frame.rs`, `lib.rs` | `frame::tests::settings_roundtrip_and_errors` |
| server: facade feature `websocket-h3`: `Reply::websocket` accepts `:protocol websocket` streams on QUIC, dispatched at once (the stream stays open), the same `WebSocketHandler`, `WsHandle` routed by connection and stream, 1001 on stop | facade `h3.rs`, `ws.rs` | simoom-client `tests/ws_h3.rs` (handshake, a pushed message from another thread, echoes up to 200 KB, close) |
| client: `WsBuilder::http3(true)` (simoom-client `client-h2` + `client-h3`): extended CONNECT on the client's shared HTTP/3 connection | simoom-client `h3.rs` `open_extended`, `ws.rs` | same |
| permessage-deflate (RFC 7692) codec, shared by server and client: negotiation (`negotiate`, `offer`, `accept_response`: context takeover options, window bits 8-15, malformed or duplicate parameters decline the offer), `PerMessage` (sync-flush DEFLATE with the `00 00 FF FF` tail removed, context takeover or not, a window-bits cap on the compressor, inflated size bounded as it inflates); `FrameDecoder::set_permessage_deflate` accepts RSV1 on a message's first frame and leaves the UTF-8 check to after inflating | simoom-http1 feature `permessage-deflate` (`ws::deflate`), simoom-compress `Encoder::with_window_bits` | `ws::deflate::tests` (the RFC 7692 §7.2.3.1 and §7.2.3.2 examples, round trips with and without context takeover and with a 9-bit window, a bomb) |
| server: facade feature `ws-deflate`, `Builder::websocket_deflate(WsDeflate)`; on HTTP/1.1, HTTP/2 and HTTP/3 WebSockets; messages under `min_size` go out uncompressed; inflated messages bounded by `Limits::max_ws_message` (1009) | facade `ws.rs`, `h1.rs`, `h2.rs`, `h3.rs` | `tests/ws_deflate.rs` (negotiation, five compressed messages with context takeover shrinking later ones, uncompressed messages alongside, RSV1 without the extension gives 1002, a 4 MiB bomb gives 1009) |
| client: simoom-client feature `client-ws-deflate`, `WsBuilder::permessage_deflate(cfg)`; offers, validates the answer (an extension not offered fails the connection), compresses and inflates | simoom-client `ws.rs` | simoom-client `tests/ws_deflate.rs` (HTTP/1.1 and HTTP/2 against the simoom server; a server without the option), `tests/ws_h3.rs` (over HTTP/3) |

## Sizes

`scripts/size.sh` (x86-64 Linux, WSL2 Ubuntu 24.04, `dist` profile, bytes added over an empty
`fn main`). `examples/hello.rs` turns compression on when the feature is set, so the
`compression` rows measure a server that compresses responses (request decoding is an opt-in
API and costs nothing unless called).

| row | added bytes | budget | status |
|---|---:|---:|---|
| `http1` | 224,512 | 256,000 | ok |
| `http1,compression` | 270,376 (+45,864) | 321,536 | ok |
| `default` | 406,480 | 1,048,576 | ok |
| `default,compression` | 455,256 (+48,776) | 1,114,112 | ok |
| `default,websocket-h2` | 414,000 (+7,520) | 1,048,576 | ok |
| `default,h2-keepalive` | 407,424 (+944) | 1,048,576 | ok |
| `full` | 1,074,368 | 1,048,576 | over by 25,792 |
| `full,compression` | 1,123,624 (+49,256) | 1,114,112 | over by 9,512 (because `full` is) |

What this work adds to builds that leave the new features out: 704 bytes on `default` (the
WebSocket code shared by HTTP/1.1 and HTTP/2; measured by building the same tree with these
changes reverted: 706,712 against 707,416 bytes), nothing on HTTP/1.1-only builds. The
`full` row and `http1,io-uring` (over by 2,200) were over budget in the same run because of
other work in progress in the tree (TLS 1.2, the client, the adoption features); this work
contributes at most those 704 bytes to `full` and nothing to `http1,io-uring`.

The `compression` rows are held to the budget of the build they join plus 64 KiB. WebSocket over
HTTP/2 and keepalive are features of their own (`websocket-h2`, `h2-keepalive`, mapping to
simoom-h2's `connect-protocol` and `keepalive`), not in `default` or `full`, so the existing
rows keep their budgets; a build for Cameleer turns on what it uses.

Sizes of the features added on 2026-11-09 evening (same method, `examples/hello.rs` exercising
each one: Brotli and zstd also decode request bodies, so decoders and the Brotli dictionary are
counted):

| row | added bytes | over its base | budget | status |
|---|---:|---:|---:|---|
| `http1` | 222,832 | - | 256,000 | ok |
| `http1,multipart` | 240,512 | +17,680 | 288,768 | ok |
| `http1,cookies` | 227,464 | +4,632 | 288,768 | ok |
| `http1,conditional` | 247,152 | +24,320 | 288,768 | ok |
| `http1,cors` | 233,680 | +10,848 | 288,768 | ok |
| `default` | 404,488 | - | 1,048,576 | ok |
| `default,compression` | 453,808 | +49,320 | 1,114,112 | ok |
| `default,brotli` (gzip, deflate and Brotli, both directions) | 603,296 | +149,488 over `compression` | 1,212,416 | ok |
| `default,zstd` (gzip, deflate and zstd, both directions) | 560,680 | +106,872 over `compression` (+27,256 from the speed passes: the fast match finders, the pointer-code loops in simoom-sys next to the safe reference loops, BMI2 copies of the two decode loops only) | 1,114,112 | ok |
| `default,ws-deflate` | 470,288 | +65,800 | 1,114,112 | ok |
| `http1,http3,websocket` | 810,208 | - | 1,048,576 | ok |
| `http3,websocket-h3` | 819,504 | +9,296 over `http1,http3,websocket` | 1,048,576 | ok |

(`websocket-h3` includes `websocket`, which includes HTTP/1.1, so the row is compared with
HTTP/1.1 + HTTP/3 + WebSocket.)

Authentication (2026-11-09, same method; `examples/hello.rs` puts Digest, Basic and Bearer in
front of the service with `auth`): `http1` 222,832, `http1,auth` 273,688 (+50,856: MD5,
SHA-256, SHA-512/256 and HMAC from simoom-tls, the Digest verifier and the wrapper); budget
`http1` + 64 KiB = 321,536, ok.

## Not done

- Server authentication: no `userhash` (it would need every user name), no `rspauth` for
  `qop=auth-int` (it covers the response body), no RFC 2069 form without `qop`, no NTLM or
  Negotiate on the server, no proxy (`407`) side.
- The Brotli encoder has no context modelling, block splitting or dictionary references (output
  1-12% larger than the reference at the same quality); the zstd encoder has no dictionary
  support (decoding dictionaries works) and no long-distance matching.
- Speed targets not reached after three passes (2026-11-09; the third with the owner's approval
  of pointer code in simoom-sys): zstd decoding 0.77-0.91x libzstd (target 0.9x; 1.24-1.27x its
  instructions per byte); zstd compression at levels 1-3 0.50-0.73x (target 0.8x; 1.5-1.8x its
  instructions, mostly the match finder and the sequence bookkeeping around the writer); Brotli
  decoding 0.75-0.77x on source code and machine code at qualities 5-9; Brotli quality-1
  compression 0.54-0.70x with up to 20% larger output (the reference's one-pass fragment
  compressor for qualities 0-1 is not built). libzstd's remaining edge is its hand-tuned
  loops (assembly Huffman decoding on x86-64, fewer live values per sequence).
- WebSocket over HTTP/3 has no close-handshake timeout on the server (QUIC's idle timeout ends
  an abandoned stream); HTTP/1.1 and HTTP/2 have the 5 s wait.
- Once, under heavy machine load, simoom-client's WebSocket-over-HTTP/3 test spun a core
  instead of finishing; it passed in 35 later runs and the cause was not found.
- Request bodies are not decoded automatically: the service calls `Request::decoded_body` or
  `take_decoded_body` (the facade's request headers are a read-only view, so an automatic decode
  would leave a stale `content-encoding` visible).
- Streamed-response compression holds about 256 KiB per running stream (the encoder's window,
  hash chains and symbol buffer); it is off by default for that reason. A smaller-memory encoder
  mode (zlib's `memLevel`) is not built.
- The client half of C7 (simoom-h2 supports it for either role; the client agent wires it).
- No CPU-specific CRC-32 (PCLMULQDQ would need `unsafe`, which belongs in simoom-sys).
