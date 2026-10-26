# Timeouts and limits

The timers and body limits use nginx's names, units and defaults, and mean what
they mean in nginx, with the differences listed below. `keepalive_timeout 0`
disables keep-alive, and `client_max_body_size 0` removes the body limit.

| Directive | Default | Set in | Bounds | When it expires |
|---|---|---|---|---|
| `client_header_timeout` | 60s | top level | the whole request header, counted from its first byte (from accept, for the first request) | 408 when part of the header arrived, otherwise the connection closes |
| `keepalive_timeout` | 75s | top level | idle time between two requests on a connection | the connection closes |
| `keepalive_requests` | 1000 | top level | requests served on one connection | the last one answers `Connection: close` |
| `send_timeout` | 60s | top level | time between two successive writes to the client | the connection closes |
| `large_client_header_buffers` | 4 8k | top level | request line up to 8k, each header field up to 8k, the header section up to 4 × 8k | 414 for a long request line, 400 for a long field or section |
| `lingering_close` | on | top level | when a connection lingers after its response: `on` only when request data was left unread, `always` after every response to a request, `off` never | the connection closes |
| `lingering_time` | 30s | top level | total time of one lingering close | the connection closes |
| `lingering_timeout` | 5s | top level | silence, with no client data, that one lingering close waits for | the connection closes |
| `client_body_timeout` | 60s | top level, site | time between two successive reads of the request body | 408 |
| `client_max_body_size` | 1m | top level, site | the request body | 413, before the body is read when `Content-Length` says so |
| `proxy_connect_timeout` | 60s | top level, site | connecting to the upstream | 504 |
| `proxy_read_timeout` | 60s | top level, site | the wait for the response head, and between two successive response reads | 504 before the head; after it, the connection closes |
| `proxy_send_timeout` | 60s | top level, site | time between two successive writes to the upstream | 504 before the response head |

The `decision` `timeout` is not in this table. It bounds one backend call, and
it is described in [Configuration](/configuration#decision-block).

An upstream that cannot be reached, or that resets the connection, still gets
502. Expired timers and oversized requests appear in the access log. `$status` is
the status sent, and `$reason` names the cause: `header_timeout`, `body_timeout`,
`body_too_large`, `unreadable_body`, `uri_too_long` or `header_too_large`.
`$upstream_error` names the upstream failure, as listed in [Logging](/logging#variables).

## Differences from nginx

- The connection timers and header limits are top-level only. They apply before
  the `Host` selects a site, so a `site` that sets one is a configuration error.
- The `proxy_read_timeout` clock starts when the request is handed to the upstream
  client, so it includes connecting. `proxy_connect_timeout` bounds the connect on
  its own.
- A zero time is rejected for every timer except `keepalive_timeout`.
- A connection whose `client_header_timeout` expires before it sent any byte of a
  request is closed without a response. The first request's clock starts when the
  connection is accepted.

## Lingering close

Lingering is nginx's `lingering_close`, with the same names and defaults. After a
response to a request whose body the router did not read, such as a 413, 403 or
408 sent early, the router writes its answer in full and half-closes the
connection. It then reads and discards what the client still sends, so the client
reads the response instead of a reset. The discard buffer is 4 KiB.

A lingering close ends when the client closes, after `lingering_timeout` without
data, or after `lingering_time` in total. No connection is held longer than
`lingering_time` after the close is decided. Connections that have not sent a
request byte, and idle keep-alive connections that time out, close at once in
every mode. A graceful shutdown waits for lingering closes that are in progress.

## Where each limit is enforced

- The header limits and the connection timers apply to the bytes before hyper
  parses them, in the socket wrapper (`src/transport.rs`).
- The body timer and `client_max_body_size` apply while the body is read
  (`src/body.rs`).
- The upstream timers apply in the upstream client (`src/proxy.rs`).

Request bodies are streamed. The router reads the first `inspect_body` bytes for
the decision and forwards the rest as the upstream reads it. A body over
`client_max_body_size` is refused with 413 when `Content-Length` shows it, before
anything is read. A chunked body that grows past the limit is cut off: the
upstream request is aborted and the client gets 413, unless the upstream has
already answered, in which case the connection closes. Memory per request is
bounded by `inspect_body` and a few buffers, not by the body size.

The header limits are checked on the first bytes of each request. A request
pipelined behind another on the same connection is not checked by them, only by
hyper's own buffer limit. hyper's limit of 100 header fields is unchanged.

## Concurrency

| Setting | Limits | Default |
|---|---|---|
| `max_connections` | client connections open at the same time | 1024 |
| `worker_threads` | runtime threads that run the proxy | one per CPU core |
| `decision` `max_concurrency` | decision-backend calls in flight at the same time | 64 |
| `decision` `queue_timeout` | how long a call may wait for one of those slots; no slot in that time is `backend_busy` | 0 (no queueing) |

A call that gets a slot then has the rest of `timeout`. A saturated backend is a
rate limit, and it follows `on_rate_limit`, not `on_decision_error`. A client that
already holds its `decision` `max_concurrency_per_client` share (default 8) is
refused at once as `client_busy`, which follows `on_client_busy` (default 429),
not `on_rate_limit`.

The [load measurement](/evaluation) shows the router with the default
`max_concurrency` and `max_connections`.
