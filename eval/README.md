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

## Offline run (free)

The offline mode points the router at the stub decider's Clef route. It costs
nothing and checks the whole flow: the request, the join with the decision log,
the report and the budget guard. Its numbers say nothing about Clef's quality.

```bash
cargo build --release --workspace
python3 -I eval/run.py --offline --split both
```

If nothing listens on port 9000, the script starts the stub itself.

## Real run (paid)

```bash
export CLOUDFLARE_AI_TOKEN=...   # read from the environment only, never printed
python3 -I eval/run.py --clef-url "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/run/@cf/cloudflare/clef-flash" --split both --max-yen 30
```

Options:

- `--split dev|holdout|both` (default `both`)
- `--limit N`: at most N rows of each split
- `--max-yen X` (default 30): the budget in JPY
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

## Rules

- Labels are never edited to match model output. A label that was wrong is
  corrected before a run and noted in the commit message, not after seeing
  scores. Git history shows every change to `dataset/`.
- The dev split is for looking at failures. The holdout split is for the final
  number. Do not tune thresholds or wording on holdout.
- Each request is judged alone. Credential attacks (rapid logins with common
  passwords) and bursts cannot be seen from a single request, so they are
  expected to be missed.
