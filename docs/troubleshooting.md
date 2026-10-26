# Troubleshooting

Each section starts with a symptom. It gives the likely cause and the fix. The access log is the first place to look, because each line records the decision and the reason for it. See [Logging](/logging) for every field.

## `-t` reports an error

**Cause:** the file has a syntax or validation error. The message names the file and line, and the last line says `test failed`.

```console
$ vigilant-heron -t -c vigilant-heron.conf
vigilant-heron: vigilant-heron.conf:6: unknown directive "upstrem" in site
configuration file vigilant-heron.conf test failed
```

**Fix:** go to the line named in the message and correct it. Every directive and its allowed values are listed in [Configuration](/configuration). Run `-t` again until it prints `test is successful`.

## The router does not start: a token variable is not set

**Cause:** the decision block names a token variable, such as `TYPESAFE_API_KEY` for the default Jev model, and that variable is unset or blank in the environment the router runs in. The `-t` check fails the same way.

**Fix:** set the variable in the same shell, service or container that starts the router. In Docker, pass it with `-e TYPESAFE_API_KEY`. The name is set with `api_token_env` in the `decision` block, if you use another variable.

## Every request returns 421

**Cause:** the `Host` header of the request matches no `site`. The router answers with `default_status`, which is 421 by default.

**Fix:** check the `Host` header that nginx or Cloudflare sends, and make sure a `site` lists that name. nginx needs `proxy_set_header Host $host;`. To send unknown hosts to one site instead, mark that site with `default_server;`.

## Every request returns 502

**Cause:** the router cannot reach the `upstream` address, or the upstream closes the connection. A connect timeout gives 504 instead.

**Fix:**

1. Test the upstream from the machine that runs the router, for example with `curl -i http://<upstream-address>/`.
2. In Docker, `127.0.0.1` is the container itself. Use the service name or the host's address in `upstream`.
3. Check that the upstream is listening on the port in the URL.

## Legitimate requests are blocked

**Cause:** a rule, a threshold or the access list matched the request. The access log says which one: `reason` and `rule_id` show the cause, and `would_have` shows what the router decided in shadow mode.

**Fix:** find the cause in the log, then choose the matching fix.

- `reason` is `rule` and `rule_id` starts with `vh-`: a built-in rule matched. Turn that one rule off with `disable_rule <id>;` in the site, or switch the whole set off with `builtin_rules off;`. Only the built-in ids can be named there.
- `reason` is `rule` and `rule_id` is your own id: edit or remove that `rule` block.
- `reason` is `model`: the decision model scored the request above a threshold. `block_threshold` (default 0.87) and `instruction_threshold` (default 0.8) are per site. Raise a threshold only after you have read the scores of the requests that were blocked.
- `reason` is `access_denied`: a `deny` line in the access list matched the client address. Check the `allow` and `deny` lines, in order.
- The path is blocked by `deny_path`: remove the prefix, or move the request to a `location` that does not use it.

To test a change without blocking anyone, set `mode shadow;` on the site, reload with `-s reload`, and watch `would_have` in the log. Use a `rule` with `action skip;` only for requests you have checked. A skip rule never lets through a request that a block rule matches.

## Attacks are not blocked

**Cause:** the site runs in shadow mode, which records decisions and forwards everything. Or the request matched no rule, and the model's scores stayed below the thresholds.

**Fix:** check `mode` in the site. In shadow mode, the log shows `would_have=block` for the requests that would be blocked. Set `mode enforce;` when you are satisfied, and reload. For a request that the rules do not catch, check its `attack` and `ai_instruction` scores in the log, and see [Decision backends](/decision-backends).

## The decision model is slow or rate-limited

**Cause:** the model answers slowly, rate-limits the router, or is busy with other calls. The `decision_error` field of the log shows which one: `timeout`, `rate_limited`, `backend_busy`, `client_busy`, `http_status` or `parse`.

**Fix:** these settings are in the `decision` block unless noted.

- `timeout` (default 300ms) is the time allowed for one decision. Raise it only if the model is consistently slow.
- `queue_timeout` (default 0, no queueing) is how long a call may wait for a free slot. It must not be longer than `timeout`. A request that waits longer gets `backend_busy`.
- `max_concurrency` (default 64) is the number of model calls in flight at once. Lower it if the model's rate limit is smaller.
- `on_rate_limit` and `on_decision_error` are per site. Both default to `allow`, so a request that the model cannot judge is forwarded. Set one to `block` if you prefer to refuse such requests. Rules still apply in either case.
- `on_client_busy` is per site and defaults to `block`. A client that holds more than `max_concurrency_per_client` calls (default 8) gets 429 (`decision_error=client_busy`) without the model. Behind a shared address, such as an office or school NAT, many people look like one client, so raise `max_concurrency_per_client`, or set `on_client_busy allow` to forward the excess without the model. Rules still apply.

## Client addresses are all the proxy's address

**Cause:** the router sees nginx or Cloudflare as the client. Then the access list, the limits and the logs all see one address.

**Fix:** tell the router which peer to trust, and which header carries the real address.

- nginx: `proxy_set_header X-Real-IP $remote_addr;` in nginx, and `real_ip_from 127.0.0.1; real_ip_header X-Real-IP;` in the router.
- Cloudflare: `real_ip_from` with the Cloudflare ranges you trust, and `real_ip_header CF-Connecting-IP;`.

See [Installation](/install#putting-it-behind-nginx-or-cloudflare) for the full snippets. With `real_ip_recursive on;`, the router reads the header from the right and skips trusted hops, which suits a chain of trusted proxies.

## WebSocket connections fail

**Cause:** WebSocket requests are screened as ordinary requests, and their `Upgrade` is dropped unless the site allows it. The default is `proxy_websocket off;`. The edge may also not pass the upgrade headers.

**Fix:**

1. Set `proxy_websocket on;` in the site, or in the `location` that serves the socket.
2. In nginx, use `proxy_http_version 1.1;`, and pass `Upgrade $http_upgrade` and `Connection $connection_upgrade`. See [Installation](/install#nginx-in-front).
3. A tunnel closes when neither side has sent a byte for `proxy_read_timeout` (60s by default). A tunnel that stays silent that long is closed, so raise the timeout if the connection is quiet for longer.

## The router does not write its pid file

**Cause:** the log shows `cannot write the pid file`. The router keeps running, but `-s` cannot find it. The directory of the `pid` path is not writable by the user that runs the router. The default path, `/run/vigilant-heron.pid`, is not writable by a normal user, and the Docker image runs as `nonroot`.

**Fix:** set a `pid` path in a directory that the user can write:

```nginx
pid /tmp/vigilant-heron.pid;
```

The commands also refuse a pid file that another user owns inside a shared directory such as `/tmp`, so put the pid file in a directory that only the router's user can write.

## Still stuck?

[Open an issue](https://github.com/coo-quack/vigilant-heron/issues) on GitHub. Include the output of `vigilant-heron -t`, the version from `vigilant-heron --version`, and the access log lines for the request, with any keys or tokens removed.
