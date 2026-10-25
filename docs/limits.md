# Limits

Request-rate and connection limits follow nginx's `limit_req` and `limit_conn`
modules. They run first, before the access list, the body and the rules. A
request that a limit refuses is never forwarded and never reaches the backend.

```nginx
limit_req_zone $client_ip zone=perip:10m rate=10r/s;
limit_conn_zone $client_ip zone=conns:10m;

site example.com {
    upstream http://upstream:80;

    location = /wp-login.php {
        limit_req zone=perip burst=2 nodelay;
        limit_req_status 429;
    }

    location /downloads/ {
        limit_conn conns 4;
    }
}
```

Here a burst of two password guesses on `/wp-login.php` passes, and the next one
gets 429. The rest of the site is not limited. The decision model cannot see how
often one client makes requests, so a limit like this is the control for guessing.

## Zones

A zone is defined at the top level with a key and a size.

- **`limit_req_zone <key> zone=<name>:<size> rate=<N>r/s|r/m;`** is a leaky bucket
  per key. `rate` is the rate at which a bucket drains.
- **`limit_conn_zone <key> zone=<name>:<size>;`** counts the requests in progress
  per key.

Zones may appear anywhere in the top level. Each name is used once across both
kinds. The size is the memory of the zone. A `limit_req` zone holds `size / 128`
states, and a `limit_conn` zone holds `size / 64`, the nginx state sizes. A size
that holds no state is an error.

### The key

The key is text and variables, and every variable is known before the body is
read:

- `$client_ip`: the address after realip selection. It is the analogue of nginx's
  `$binary_remote_addr`.
- `$remote_addr`: the TCP peer.
- `$site`, `$host` (normalized), `$method` and `$path` (decoded and dot-normalized,
  case kept).
- `$http_<name>`: a request header, with `_` for `-`.

Credential headers are refused in a key: `cookie`, `authorization`,
`proxy-authorization`, `x-api-key`, `x-auth-token`, and every name in
`redact_header`.

A key that comes out empty is not counted, as in nginx. Literal text keeps a key
non-empty, so `$http_x_tenant-` is counted even when the header is missing.

## Directives

These are written inside a `site` or a `location`, or at the top level, where a
level that does not set a directive inherits it.

- **`limit_req zone=<name> [burst=<n>] [nodelay | delay=<n>];`** applies a zone.
  It may repeat.
- **`limit_conn <zone> <number>;`** allows `number` requests in progress per key.
  It may repeat.
- **`limit_req_status <code>;`** and **`limit_conn_status <code>;`** set the status
  of a rejected request, 4xx or 5xx. The default is 503, and 429 is a common choice.
- **`limit_req_dry_run on|off;`** and **`limit_conn_dry_run on|off;`** make the
  limit count only. Nothing is rejected or delayed.
- **`limit_req_log_level`** and **`limit_conn_log_level`** set the error log
  severity of an event: `info`, `notice`, `warn` or `error` (the default). The
  router's error log has no notice level, so `notice` is written at info.

### Burst, delay and nodelay

`limit_req` without `burst` rejects every request beyond the rate. With `burst`,
the excess requests wait for their turn at the rate. Waiting does not block other
requests.

- `nodelay` lets the whole burst pass at once.
- `delay=<n>` lets the first `n` excess requests pass at once and makes the rest
  wait. It needs a `burst`, cannot exceed it, and cannot be combined with
  `nodelay`.

The bucket admits a request that finds it empty, and then up to `burst` more,
before it rejects. So `rate=1r/s burst=2 nodelay` admits three requests at once.
Over any time window, the requests admitted are at most the rate times the
window, plus `burst + 1`.

### Inheritance

A level that has any `limit_req` replaces the list it inherits, and the same holds
for `limit_conn`. Every other limit setting is inherited unless the level sets it.

## Location blocks

`location [=|~|~*|^~] <path> { ... }` may appear inside a `site`. The match
follows nginx.

1. An exact `=` match wins.
2. Otherwise the longest prefix is found. A `^~` prefix that matches ends the
   search.
3. Otherwise the regexes are tried in file order, and the first match wins.
4. Otherwise the longest prefix is used.

The path is the normalized request path. Plain paths are compared lowercased, as
`deny_path` is, and must start with `/`. A request is limited by every location that
any [reading of the path](/how-it-works#path-readings) selects, so `/login;x` is
limited by `location = /login`, and a request cannot escape a location's limits by
choosing another reading. The block response comes from the location that the
decoded path selects. A `~` regex matches the decoded path with
case kept, and `~*` ignores case. Regexes use the `regex` crate, which has no
backreferences or look-around, unlike nginx's PCRE. A repeated plain location is
an error, as in nginx.

Only the limit directives, `block_status`, `block_page`, `proxy_websocket` and
`proxy_set_header` may appear inside a `location`. Any other directive is an error
at its line.

## What happens to a limited request

- A request refused by `limit_req` or `limit_conn` gets the status of its
  directive. The access log records `action` `reject` and `reason` `limit_req` or
  `limit_conn`, and it is never forwarded.
- `$limit_req_status` is `PASSED`, `DELAYED`, `REJECTED`, `DELAYED_DRY_RUN` or
  `REJECTED_DRY_RUN`. `$limit_conn_status` is `PASSED`, `REJECTED` or
  `REJECTED_DRY_RUN`. When several zones apply, the worst outcome is shown. Both
  are available in a `log_format`, and the built-in `json` format does not include them.
- In a shadow site, and for a dry-run directive, every limit is a dry run. A
  request that would have been refused is forwarded, and the log and the debug
  header record `would_have=reject`.
- A delayed request waits asynchronously, then goes on through the pipeline. The
  delay counts against the client's timeouts.
- `limit_conn` counts a request from the moment its header is read until its
  response body is done, or the client drops the connection. A refused request is
  not counted.
- When a zone has no free state, the least recently used idle state is evicted
  first, as in nginx. If every state is in use, the request is refused with the
  configured status, and `$limit_req_status` or `$limit_conn_status` is
  `REJECTED`. The error log tells this apart from an ordinary excess with
  `limit_error=zone_exhausted`. The access log reason is still `limit_req` or
  `limit_conn`.

Limits are kept per process. A router that runs several processes keeps separate
counts. A reload keeps the counts of a zone that has the same name and size in the
new configuration, as described in [Configuration](/configuration#reload-and-log-reopen).
