---
name: vigilant-heron-rollout
description: >-
  Drives the rollout of vigilant-heron in front of a real site, phase by phase, from the
  first checks through a shadow trial to enforce mode, with the operator deciding every
  change to live traffic. Use it when asked to "put vigilant-heron in front of my site",
  "move from shadow mode to enforce", "review the shadow log" or "write a skip rule".
---

# vigilant-heron rollout

## Purpose

The guide [From shadow mode to enforce](../../docs/rollout.md) is the source of truth: read its section before each phase. This file holds only commands, gates and rules.

Outside the repository, replace `../../docs/<page>.md#<anchor>` with the published `https://coo-quack.github.io/vigilant-heron/<page>#<anchor>`.

Here `<file>` is the router's configuration, and `example.com` is the site's host name.

## Hard rules

- Ask the operator before any change to live traffic, to the web server, or to `mode enforce;`. Starting, stopping, restarting and reloading the router are changes to live traffic too.
- Never change live traffic before the way back has been tested.
- Never print or paste API tokens, secret header values or full client addresses into issues or chat.
- Do not identify the owner's traffic by IP address alone; use the User-Agent and request order, as [phase 3 of the guide](../../docs/rollout.md#3-reading-the-shadow-log) explains.
- Do not widen a skip rule without testing its near misses with `test-request`.
- Stop and report when a step fails, without working around it. Report a step as passed only after you ran it and read its output.

## Phases

Move on only when the gate is met and the operator has agreed to any change in the phase.

### Phase 1: Before you start

- **Goal:** the site, its clients, the proxies, the backend's latency, `timeout`, the cost and the evaluation are known.
- **Guide:** [1. Before you start](../../docs/rollout.md#1-before-you-start), and [`real_ip_from`](../../docs/install.md#putting-it-behind-nginx-or-cloudflare).
- **Run:** once a first draft of the file exists, `vigilant-heron -t -c <file>`.
- **Look for:** `test is successful`. With `TYPESAFE_API_KEY` unset, `-t` still exits 0, but the router refuses to start. Measure latency on the router's server.
- **Gate:** every item in the guide's step 1 checklist is true.

### Phase 2: Shadow beside the site

- **Goal:** nginx copies requests to the router in shadow mode; the site's answers do not change.
- **Guide:** [2. Shadow beside the site](../../docs/rollout.md#2-shadow-beside-the-site), and [the nginx mirror](../../docs/install.md#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).
- **Run:** ask the operator before editing nginx. Start the router, or run `vigilant-heron restart -c <file>` if it runs (`listen` is read only at startup). Ask the operator to schedule the job that stops the trial. Then send one ordinary request to the site.
- **Look for:** one JSON line per request in the access log, no doubled lines on `/`, and no CDN secret header in what the router receives.
- **Gate:** the guide's checklist is true, and the stop job is scheduled and named in the report.

### Phase 3: Reading the shadow log

- **Goal:** find what the router would block, and whether the backend keeps up.
- **Guide:** [3. Reading the shadow log](../../docs/rollout.md#3-reading-the-shadow-log), [Summarize a shadow log](../../docs/cli.md#summarize-a-shadow-log), and [the built-in formats](../../docs/logging.md#the-built-in-formats) for the fields.
- **Run:** `vigilant-heron shadow-report <access.json.1> <access.json>` (no `-c`). Its overview counts `reason` and `decision_error`; its per-hour part gives the p99 of `latency_ms`. List the blocks with `grep '"would_have":"block"' <access.json>`, count them, and read each line; the report lists only the first 50. If your `log_format` has `$block_query`, read it for each block, masking personal data you quote.
- **Look for:** one reason that dominates; decision timeouts clustered in an hour with little load; `client_busy` bursts from one client; a p99 above `timeout`. Do not pass `--full-addresses`, and mask any client address you quote, such as `203.0.113.x`.
- **Gate:** every `"would_have":"block"` line has been read, and the counts and p99 are recorded.

### Phase 4: Writing skip rules

- **Goal:** let known-safe request shapes skip the backend, as narrowly as possible.
- **Guide:** [4. Writing skip rules](../../docs/rollout.md#4-writing-skip-rules), [writing your own rule](../../docs/rules.md#write-your-own-rule), and [learning skip rules](../../docs/cli.md#learn-skip-rules-from-the-access-log).
- **Run:**
  1. `vigilant-heron suggest-skip-rules <access.json>`. It takes no `-c` and changes no file.
  2. Copy the candidates the operator approves into `rules.d/`. For WordPress, copy `examples/rules.d/wordpress.conf` instead, narrow its rules and add a `site` line to each.
  3. Run `vigilant-heron -t -c <file>`.
  4. Test the guide's example rule (`GET /products?id=<digits>`): `vigilant-heron -c <file> test-request --url 'https://example.com/products?id=42'`.
  5. Test these near misses: a quote (`id=42%27`), a script tag (`id=%3Cscript%3E`), an extra parameter (`id=42&x=1`), an encoded newline (`id=42%0A`), a `POST` (`--method POST`), and a longer path (`/products/extra`).
  6. Ask the operator to approve the reload. Then run `vigilant-heron -s reload -c <file>`, or `sudo systemctl reload vigilant-heron` under systemd.
- **Look for:** the `rules:` line reads `matched (skip)` with the rule's description only on the request the rule must skip. A near miss that matches `(skip)` is too wide. In the JSON access log, `reason` is `skip_rule` for a skipped request.
- **Gate:** every rule has a method, exact path and narrow query regex; no skip rule matches a credential-carrying `POST`; every near miss was tested; the file passes `-t`; the operator approved the reload.

### Phase 5: Putting the router in the request path

- **Goal:** the site's scripts pass through the router, with a tested way back.
- **Guide:** [5. Putting the router in the request path](../../docs/rollout.md#5-putting-the-router-in-the-request-path).
- **Run:** each nginx change, symlink switch, restart, stop and start needs the operator's approval. Run the guide's steps 1 to 4. For the router, run `vigilant-heron -t -c <file>`, then `vigilant-heron restart -c <file>`. To test the fallback, stop the router with `sudo systemctl stop vigilant-heron`, or `vigilant-heron stop -c <file>` for a background router, check that the site answers, and start it again.
- **Look for:** the outer nginx uses `proxy_next_upstream error;`, not the default `error timeout`, which would send a slow request past the router ([step 5 of the guide](../../docs/rollout.md#5-putting-the-router-in-the-request-path) explains why). A page and a login each have a log line, and `latency_ms` is compared with nginx's request time. While the router is stopped, the site still answers from the inner server.
- **Gate:** the guide's step 5 checklist is true, and the switch back was tested once.

### Phase 6: Switching to enforce

- **Goal:** enforce only after the upload limit and the way back are tested.
- **Guide:** [6. Switching to enforce](../../docs/rollout.md#6-switching-to-enforce).
- **Run:**
  1. Ask the operator for an explicit yes before changing the mode. Then run `vigilant-heron -t -c <file>`.
  2. Check the rule offline before the reload: `vigilant-heron -c <file> test-request --url 'https://example.com/?id=1%20UNION%20SELECT%20password%20FROM%20users'` should report `result: blocked with 403`.
  3. Ask the operator to approve the reload, then reload as in phase 4.
  4. Send the live test attack (guide, step 4) only with the operator's yes.
- **Look for:** a 403 for the live attack; no block or 429 from the owner's normal actions; an upload over the limit gets 413; a reported block is found by its `request_id` in the JSON log.
- **Gate:** every item in the guide's checklist is true, and the operator knows both ways back: `mode shadow;` with a reload, or the symlink to the direct upstream.

### Phase 7: Principles for running it safely

- **Goal:** the model only adds blocks; limits, fail-closed paths and redaction stay in place.
- **Guide:** [7. Principles for running it safely](../../docs/rollout.md#7-principles-for-running-it-safely), and [failure behavior](../../docs/security.md#failure-behavior).
- **Run:** `vigilant-heron -T -c <file>` prints the expanded configuration, with no token values. Run `vigilant-heron -c <file> test-request --url 'https://example.com/login'`. For a request that reaches the backend, the last line says what happens if the backend fails; if a rule or the static skip decides, it is the `result:` line.
- **Look for:** `fail_closed_path` covers the login and admin paths; `redact_field` lists the fields that carry personal data; `limit_req` and `limit_conn` limit each client; the configuration and binary are under version control.
- **Gate:** every item in the guide's step 7 checklist is true.

## Command quick reference

- `vigilant-heron -t -c <file>`: check the file without starting anything; exit 1 on error.
- `vigilant-heron -T -c <file>`: print the file with each include expanded.
- `vigilant-heron -c <file> test-request <request.http>`: report what the router would do with a saved request; `-` reads standard input.
- `vigilant-heron -c <file> test-request --url <url>`: the same, for a URL. `--host <name>` is needed for a path such as `/items?id=2`. `--method <m>` defaults to GET. `--header 'Name: value'` may repeat.
- `vigilant-heron suggest-skip-rules <access.json>`: candidates from the JSON access log. `--site <name>` narrows the report. It takes no `-c`.
- `vigilant-heron shadow-report <access.json>...`: summary of json access logs from a shadow trial. It takes no `-c`.
- `vigilant-heron -s reload -c <file>`: re-read the file; use the running router's `-c`. `-s` also takes `reopen`, `stop` and `quit`, each returning at once.
- `vigilant-heron stop -c <file>`: stop a background router. Only this command waits until the router has exited.
- `vigilant-heron start|restart -c <file>`: start or restart a background router. Under systemd, use `sudo systemctl reload|restart|stop vigilant-heron` instead.

## Report to the operator

End each phase with a short report:

```
Phase N: <name>, done or not done
Changed: files, lines and each site's mode
Measured: counts, p99 latency, input tokens, blocks read
Gate: met, or the items still false
Next: the next phase
Needs your decision: each open item as a yes-or-no question
```

Confirm that no token, secret header value or full client address appears in it.
