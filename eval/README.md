# Clef-flash evaluation

`eval/run.py` sends a labelled set of HTTP requests through the router with the
Cloudflare Clef-flash backend and reports how many attacks are blocked and how
many ordinary requests are wrongly blocked. The script uses only the Python
standard library.

## Files

- `dataset/dev.jsonl` and `dataset/holdout.jsonl`: 200 rows each, 90 `block`
  and 110 `allow`. Each row has `id`, `label`, `kind`, `request` (`method`,
  `path`, `query`, `headers`, `content_type`, `body`) and `note`. All data is
  synthetic: example.com and example.jp hosts, 192.0.2.x, 198.51.100.x and
  203.0.113.x addresses.
- `config.template.toml`: the router configuration. It uses the Clef backend,
  enforce mode, `block_threshold = 0.5`, `debug_headers = true`, and empty
  `deny_paths`, `fail_closed_paths` and `static_extensions`. An empty
  `static_extensions` means no row can skip the backend.
- `results/`: per-row results and router logs. Git-ignored.

## Backends

`--backend clef` (default) uses Clef-flash at `$0.038` per million input tokens
and reads the token from `CLOUDFLARE_AI_TOKEN`. `--backend jev` uses `jev-latest`
at `$0.0375` per million input tokens, reads the token from `TYPESAFE_API_KEY`,
and posts to `--jev-url` (default `https://api.typesafe.ai/v1/systemone`).
`--usd-per-mtok` overrides the price. Both backends use a 3000 ms timeout, so a
slow answer is not turned into a fail-open allow. Latency is still reported.
Results are written as `results/<UTC>-<backend>-<split>.jsonl`.

## Concurrency

`--concurrency N` (default 4) sends N rows at once. Each row carries
`X-Request-Id: <row id>`, and the router logs it as `request_id`, so every row
is joined to its decision event by id, not by order. The run aborts with a clear
error if any row has no decision event, or more than one.

The budget stays correct under concurrency. Before a row is sent, its estimated
cost is reserved: the average input tokens so far, or the largest request so
far if that is bigger. The reservation counts against the limit while the
request is in flight. When the decision event arrives, the reservation is
replaced by the real input tokens. A row is not sent if its reservation would
push the total past `--max-yen`. The reservation is an estimate, so a request
that costs more than every earlier one can still overshoot by that difference.

Results are written in dataset order, so the per-row files of two runs with
different concurrency can be compared directly.

## Offline run (free)

The offline mode points the router at the stub decider's Clef route. It costs
nothing and checks the whole flow: the request, the join with the decision log,
the report and the budget guard. Its numbers say nothing about Clef's quality.

```bash
cargo build --release --workspace
python3 -I eval/run.py --offline --split both
```

If nothing listens on port 9000, the script starts the stub itself. Use
`--backend jev` for the Jev path of the stub.

## Real run (paid)

```bash
export CLOUDFLARE_AI_TOKEN=...   # read from the environment only, never printed
python3 -I eval/run.py --clef-url "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/run/@cf/cloudflare/clef-flash" --split both --max-yen 30
```

Options:

- `--split dev|holdout|both` (default `both`)
- `--limit N`: at most N rows of each split
- `--max-yen X` (default 30): the budget in JPY for base spend plus this run
- `--spent-yen X` (default 0): JPY that earlier runs spent. Each run starts from
  it, so the 30 JPY budget is shared by all runs. The report prints the
  cumulative total.
- `--router PATH`: another router binary

## Budget guard

Before each request the script computes the cost so far from the
`input_tokens` the router logged, and adds the average input tokens per request
so far (1500 tokens before the first request). Prices use $0.038 per million
input tokens and 158 JPY per USD. If the total would exceed `--max-yen`, the run
stops and the report is marked partial. Output tokens are free for Clef-flash.

## Results

For each split the script writes `results/<UTC>-<split>.jsonl` with one line per
row: status, debug header, action, reason, scores, category, input tokens,
latency and whether the decision event matched the row. It prints a Markdown
report with:

- totals and the budget status
- a confusion matrix at block thresholds 0.5, 0.7 and 0.9. A row is predicted to
  be blocked when `attack >= t` or `ai_instruction >= 0.5`. The router's own 403
  decisions are shown too.
- recall per block kind and false positive rate per allow kind, at 0.5
- ai_instruction hits on allow rows
- category accuracy. Only kinds with one expected category are scored:
  sql_injection, xss, path_traversal, command_injection, file_inclusion, ssrf,
  scanner_probe and credential_attack. The others show `n/a`.
- latency p50 and p95, input tokens, cost in USD and JPY, and the misclassified ids

## Load test (offline only)

`eval/load.py` measures the router itself, not a model. It always starts the
stub decider with an extra delay (`STUB_DELAY_MS`), a local upstream, and a
release build of the router. It never calls a paid provider.

```bash
cargo build --release --workspace
python3 -I eval/load.py --concurrency 16 --requests 2000 --stub-delay-ms 20 --worker-threads 4
```

Options: `--concurrency` (client threads, each with its own connection),
`--requests`, `--stub-delay-ms`, `--max-concurrency` (the router's
`decision.max_concurrency`, default 64), `--worker-threads` (unset by default,
meaning one per CPU core). It prints throughput, latency p50/p95/p99, status
counts, and the decision events that failed, grouped by `decision_error`.
The client is Python, so at high concurrency the client itself can be the
bottleneck. Record the machine with each report.

## Rules

- Labels are never edited to match model output. A label that was wrong is
  corrected before a run and noted in the commit message, not after seeing
  scores. Git history shows every change to `dataset/`.
- The dev split is for looking at failures. The holdout split is for the final
  number. Do not tune thresholds or wording on holdout.
- Labels are not the only thing a run must not change: a row's request may be
  re-encoded to be valid HTTP, but only when the router never received it
  (for example a literal `<` in a query string, rejected before judging). Such a
  fix is recorded in the commit message.
- Each request is judged alone. Credential attacks (rapid logins with common
  passwords) and bursts cannot be seen from a single request, so they are
  expected to be missed.
