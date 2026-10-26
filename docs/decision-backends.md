# Decision backends

The `backend` in the `decision` block selects the protocol. The default is `jev`.
`jev` calls TypeSafe Jev, `clef` calls Cloudflare Clef on Workers AI, `strands`
calls a self-hosted Strands Decider server, and `http` posts a JSON protocol to a
URL of your choice. `jev`, `clef` and `strands` use the same System One request
and answer shapes, so they share one implementation.

## What the backend is asked

For each request that the rules do not decide, the router sends the sanitized
event described in [How it works](/how-it-works#what-the-backend-receives). The
System One backends ask three questions about it:

- whether the request is an attack (`attack`),
- whether the request addresses an AI or tries to change how it is judged
  (`ai_instruction`), and
- which category of attack it is (`category`, logged only).

The question wording lives in
[`src/system_one.rs`](https://github.com/coo-quack/vigilant-heron/blob/develop/src/system_one.rs).

## Jev (TypeSafe), the default

```nginx
decision {
    backend jev;
    model jev-latest;                       # any identifier of 1 to 100 characters from A-Za-z0-9._-
    url https://api.typesafe.ai/v1/systemone;
    api_token_env TYPESAFE_API_KEY;
    timeout 300ms;
}
```

With `backend jev`, every line except `backend` is optional, because the URL,
the model and the token variable have the defaults shown above. The answer is the
bare result, with no envelope. The router does not request TypeSafe's
long-context mode. Jev receives the sanitized event. Read [Security](/security)
before you enable it.

## Clef (Cloudflare Workers AI)

```nginx
decision {
    backend clef;
    model clef-flash;                       # or clef
    url https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/run/@cf/cloudflare/clef-flash;
    api_token_env CLOUDFLARE_AI_TOKEN;
    timeout 3000ms;
}
```

`model` is required with `clef`, and so are `url` and `api_token_env`. Clef
sends the sanitized event to Cloudflare, so read [Security](/security) first.

## Strands Decider (self-hosted)

[Strands Decider](https://github.com/strands-labs/strands-decider) is an
Apache-2.0 decision model that you run yourself. Its server serves
`POST /v1/systemone` and `GET /health`, and it speaks the System One shape, so
`backend strands` needs no other change. Start it with:

```sh
strands-decider serve <checkpoint> --device cuda --host 127.0.0.1 --port 8099
```

The published checkpoints are `StrandsAgents/strands-decider-2B-qwen3.5-v1-2610`
and `StrandsAgents/strands-decider-E4B-gemma4-v1-2610`. Then point the router at it:

```nginx
decision {
    backend strands;
    url http://127.0.0.1:8099/v1/systemone;
    timeout 1000ms;
}
```

With `backend strands`, `url` is required. `model` defaults to `strands-decider`.
`api_token_env` is optional. Without it, the router sends no `Authorization`
header. With it, the router sends the token as a bearer token, and the variable
must be set and not blank.

Read these before you run it:

- **The server has no authentication.** Keep it on `127.0.0.1` or on a private
  network. To reach it from elsewhere, put an authenticating proxy in front of
  it and set `api_token_env` so that the proxy receives the token.
- **The model sees 4,096 tokens.** The published checkpoints use a 4,096-token
  window. By default, a prompt longer than the window is cut at its end, and the
  server does not report it. An attacker can pad a request so that the part
  carrying the payload falls past the window. Lower `inspect_body`, for example
  `inspect_body 2k;`, or run the server with `--strict-window`. That option
  answers HTTP 422 for an overlong prompt instead, and the router treats it as a
  decision error, which `on_decision_error` handles.
- **Accuracy on this router's questions has not been measured yet.** The
  figures below come from JevBench, not from these questions.
- **Concurrent requests are not verified.** The server's documentation says its
  behaviour under concurrent requests is not verified and recommends it for
  local experiments only.

Latency was measured on one NVIDIA L4, over localhost, on the 231 JevBench
tasks. The 2B checkpoint took a p50 of 99 ms and a p95 of 436 ms. The E4B
checkpoint took a p50 of 132 ms and a p95 of 1,212 ms.

## Tokens

The token is never written in the configuration file. `api_token_env` names an
environment variable, and the router reads it when the configuration loads. The
process fails to start when the variable is unset or blank, and `-t` fails the
same way. The token is shown as `[REDACTED]` in logs and errors.

## HTTP protocol

With `backend http;`, the router posts JSON to the decision `url`:

```json
{"event": {
  "untrusted": {"method": "POST", "path": "/login", "query": null,
                "headers": [["user-agent", "…"]], "body": "user=alice&password=[REDACTED]"},
  "meta": {"host": "example.com", "client_ip": "203.0.113.7", "body_truncated": false}
}}
```

The backend answers with two scores, both between 0 and 1:

```json
{"attack": 0.02, "ai_instruction": 0.01}
```

A `"category"` string is optional and is logged when present. `model` and
`api_token_env` are not valid with `backend http`. Set `url` explicitly, because
`http` has no default URL.

## Thresholds

The policy compares the scores with two thresholds:

- `block_threshold` (default `0.87`) for `attack`.
- `instruction_threshold` (default `0.8`) for `ai_instruction`.

A request whose score reaches a threshold is blocked. Both thresholds are set per
site.

The evaluation in [Evaluation](/evaluation) gives the numbers behind the defaults.
In that measurement, Jev's `attack` score at `0.87` had a false positive rate of
1.8% on the dev split and 0.9% on the holdout split, and its recall was 0.871 and
0.892. The thresholds were chosen on the dev split, so only the holdout figures
are out of sample. The dataset is synthetic and small, so treat the numbers as a
starting point for your own traffic, not as a guarantee.

To choose thresholds for a site:

1. Run the site in `mode shadow;` for a period that includes your normal traffic.
2. Read `attack` and `ai_instruction` in the log, and compare the requests that
   would have been blocked with the ones you know are attacks.
3. Raise a threshold where ordinary requests are blocked, and lower it where
   attacks pass. Each change is a trade between false positives and misses.
4. Set the same thresholds in `enforce` mode only after the shadow results are
   acceptable.

## Timeouts and failures

Set `timeout` above the typical latency of the backend you chose. If a backend's
answers regularly arrive after `timeout`, every request becomes a decision error
and `on_decision_error` decides it. The evaluation report notes that a 150 ms
timeout would have turned most Clef-flash calls, measured from one location in
Japan, into allows that the model never judged. Measure the latency from your own
location before you pick a value.

`queue_timeout` controls how long a request waits for one of the `max_concurrency`
slots. The default of 0 means a request that finds no free slot is `backend_busy`
at once. See [How it works](/how-it-works#failure-behavior) for the failure settings.
