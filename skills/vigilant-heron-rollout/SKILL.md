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

This skill walks an agent through the rollout in [From shadow mode to enforce](../../docs/rollout.md) on a real server. The guide is the source of truth: read its section before each phase. This file holds only the commands, gates and rules.

The published copy is at https://coo-quack.github.io/vigilant-heron/rollout. The relative links below resolve only inside the repository. Outside it, replace `../../docs/<page>.md#<anchor>` with `https://coo-quack.github.io/vigilant-heron/<page>#<anchor>`.

In this file, `<file>` is the router's configuration file, and `example.com` stands for the site's host name.

## Hard rules

- Ask the operator before any change to live traffic, to the web server, or to `mode enforce;`.
- Never change live traffic before the way back has been tested.
- Never print or paste API tokens, secret header values or full client addresses into issues or chat.
- Do not identify the owner's traffic by IP address alone. Addresses change, and a cloud address does not show a partner. Use the User-Agent and the order of requests, as [phase 3 of the guide](../../docs/rollout.md#3-reading-the-shadow-log) explains.
- Do not widen a skip rule without testing its near misses with `test-request`.
- Stop and report when a step fails. Do not work around it.
- Report a step as passed only when you ran it and read its output.
- `listen` is read only at startup, so a change to it needs a restart, not a reload. See [Reload or restart](../../docs/cli.md#reload-or-restart).
- `-t` exits 0 when `TYPESAFE_API_KEY` is unset, and only warns. The router refuses to start without the variable.

## Phases

Move on only when the gate is met and the operator has agreed to any change in the phase.

### Phase 1: Before you start

- **Goal:** the site's files and clients, the proxies in front of the router, the backend's latency, `timeout`, the cost and the evaluation are known.
- **Guide:** [1. Before you start](../../docs/rollout.md#1-before-you-start), and [putting it behind nginx or Cloudflare](../../docs/install.md#putting-it-behind-nginx-or-cloudflare) for `real_ip_from`.
- **Run:** once a first draft of the file exists, `vigilant-heron -t -c <file>`.
- **Look for:** `test is successful`. Measure latency from the router's server, not from a workstation.
- **Gate:** every item in the guide's step 1 checklist is true.

### Phase 2: Shadow beside the site

- **Goal:** nginx copies each request to the router in shadow mode, and the site's answers do not change.
- **Guide:** [2. Shadow beside the site](../../docs/rollout.md#2-shadow-beside-the-site), and [the nginx mirror](../../docs/install.md#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).
- **Run:** ask the operator before editing nginx. Start the router, or restart it with `vigilant-heron restart -c <file>` if it already runs. Then send one ordinary request to the site.
- **Look for:** one JSON line per request in the router's access log, no two lines with the same time, client, method and path on `/`, and no CDN secret header in what the router receives.
- **Gate:** the guide's checklist is true, and the operator has named the job that stops the trial.

### Phase 3: Reading the shadow log

- **Goal:** find what the router would block, and whether the backend keeps up.
- **Guide:** [3. Reading the shadow log](../../docs/rollout.md#3-reading-the-shadow-log), and [the built-in formats](../../docs/logging.md#the-built-in-formats) for the fields.
- **Run:** count the lines by `reason` and by `decision_error`. List the blocks with `grep '"would_have":"block"' <access.json>`, count them, and read each line. `tail <access.json>` shows the latest. Compute the p99 of `latency_ms`, and sum `input_tokens`.
- **Look for:** one reason that dominates; decision timeouts clustered in an hour with little load, which points at the provider; `client_busy` bursts from one client; a p99 above `timeout`.
- **Gate:** every `"would_have":"block"` line has been read, and the counts and p99 are recorded.

### Phase 4: Writing skip rules

- **Goal:** let repeated, known-safe request shapes skip the backend, each one as narrow as possible.
- **Guide:** [4. Writing skip rules](../../docs/rollout.md#4-writing-skip-rules), [writing your own rule](../../docs/rules.md#write-your-own-rule), and [learning skip rules](../../docs/cli.md#learn-skip-rules-from-the-access-log).
- **Run:** `vigilant-heron suggest-skip-rules <access.json>`. It takes no `-c` and changes no file. Copy the candidates the operator approves into `rules.d/`, then run `vigilant-heron -t -c <file>`. Test the guide's example rule, which skips `GET /products?id=<digits>`, with `vigilant-heron -c <file> test-request --url 'https://example.com/products?id=42'`. Then test these near misses: a quote (`id=42%27`), a script tag (`id=%3Cscript%3E`), an extra parameter (`id=42&x=1`), an encoded newline (`id=42%0A`), a `POST` (`test-request --method POST --url ...`) and a longer path (`/products/extra`). Finally, run `vigilant-heron -s reload -c <file>`.
- **Look for:** the `rules:` line reads `matched (skip)` with the rule's description only on the request the rule must skip. A near miss that reports `matched (skip)` means the rule is too wide. In the access log the decision appears as `skip_rule`.
- **Gate:** every rule has a method, an exact path and a narrow query regex; no skip rule matches a `POST` that carries credentials; every near miss was tested; the file passes `-t`.

### Phase 5: Putting the router in the request path

- **Goal:** the site's scripts pass through the router, with a tested way back at each step.
- **Guide:** [5. Putting the router in the request path](../../docs/rollout.md#5-putting-the-router-in-the-request-path).
- **Run:** every nginx change and every switch of the upstream symlink needs the operator's approval. Run the commands in the guide's steps 1 to 4. For the router, run `vigilant-heron -t -c <file>`, then restart it. To test the fallback, stop the router with `sudo systemctl stop vigilant-heron`, or with `vigilant-heron stop -c <file>` for a background router. Check that the site answers, then start the router again.
- **Look for:** the inner server answers a script directly; a page and a login each have a line in the router's log; `latency_ms` is compared with nginx's request time; while the router is stopped, the site still answers from the inner server.
- **Gate:** every item in the guide's step 5 checklist is true, and the switch back has been tested once.

### Phase 6: Switching to enforce

- **Goal:** move from `mode shadow;` to `mode enforce;` only after the upload limit and the way back are tested.
- **Guide:** [6. Switching to enforce](../../docs/rollout.md#6-switching-to-enforce).
- **Run:** ask the operator for an explicit yes before changing the mode. Then run `vigilant-heron -t -c <file>`, and `vigilant-heron -s reload -c <file>`, or `sudo systemctl reload vigilant-heron` under systemd. Check the rule offline first with `vigilant-heron -c <file> test-request --url 'https://example.com/?id=1%20UNION%20SELECT%20password%20FROM%20users'`. Then send the live test attack from the guide's step 4.
- **Look for:** `result: blocked with 403` in the offline report; a 403 for the live attack; no block or 429 from the owner's login, saves, uploads or admin screens; an upload over the limit gets 413.
- **Gate:** every item in the guide's checklist is true, and the operator knows both ways back: `mode shadow;` with a reload, or the symlink pointed at the direct upstream.

### Phase 7: Principles for running it safely

- **Goal:** the model only adds blocks; limits, fail-closed paths and redaction stay in place.
- **Guide:** [7. Principles for running it safely](../../docs/rollout.md#7-principles-for-running-it-safely), and [failure behavior](../../docs/security.md#failure-behavior).
- **Run:** `vigilant-heron -T -c <file>` prints the expanded configuration, with no token values. Run `vigilant-heron -c <file> test-request --url 'https://example.com/login'` and read the last line, which says what happens when the decision fails.
- **Look for:** `fail_closed_path` covers the login and admin paths; `redact_field` lists the fields that carry personal data; `limit_req` and `limit_conn` limit each client; the configuration and the pinned binary are under version control.
- **Gate:** every item in the guide's step 7 checklist is true.

## Command quick reference

- `vigilant-heron -t -c <file>`: check the file, and start nothing. Exit 1 on an error.
- `vigilant-heron -T -c <file>`: print the file with each include expanded.
- `vigilant-heron -c <file> test-request <request.http>`: report what the router would do with a saved request. Use `-` to read the request from standard input.
- `vigilant-heron -c <file> test-request --url <url>`: the same, for a URL. `--host <name>` is needed for a path such as `/items?id=2`. `--method <m>` defaults to GET. `--header 'Name: value'` may repeat. `--client <address>` sets the address used by the access list.
- `vigilant-heron suggest-skip-rules <access.json>`: candidates from the JSON access log. `--site <name>` narrows the report. It takes no `-c`.
- `vigilant-heron -s reload -c <file>`: re-read the file. Use the same `-c` as the running router. `-s` also takes `reopen`, `stop` and `quit`, and returns at once. The word `stop` waits for the router to exit.
- `vigilant-heron start|stop|restart -c <file>`: for a background router only. Under systemd, use `sudo systemctl reload|restart|stop vigilant-heron` instead.

## Report to the operator

End each phase with a short report:

```
Phase N: <name>, done or not done
Changed: files and lines edited, and the mode of each site
Measured: counts, p99 latency, input tokens, and the blocks you read
Gate: met, or the items that are still false
Next: the next phase
Needs your decision: each open item as a yes-or-no question
```

Confirm that no token, secret header value or full client address appears in it.
