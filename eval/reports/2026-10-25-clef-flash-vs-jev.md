# Clef-flash vs Jev on the labelled dataset (2026-10-25)

Runs: `eval/run.py` against the real providers, dev and holdout splits (200 rows
each, 90 block / 110 allow), router with decision timeout 3000 ms. Labels were
committed in bb5b90f before any provider run; the only later dataset change is
the percent-encoding of `<` and `>` in dev-066 (payload and label unchanged).

`credential_attack` rows are excluded from the headline numbers: one login
request with a common password cannot be told apart from a legitimate login,
and the router redacts the password before the model sees it. They need a
rate-based control instead.

## Headline (block if attack >= t or ai_instruction >= 0.5)

| backend | split | t = 0.5 recall / FPR | t = 0.7 recall / FPR | t = 0.9 recall / FPR |
|---|---|---|---|---|
| clef-flash | dev | 0.988 / 0.227 | 0.965 / 0.127 | 0.635 / 0.000 |
| clef-flash | holdout | 0.988 / 0.191 | 0.916 / 0.109 | 0.699 / 0.000 |
| jev-latest | dev | 0.988 / 0.100 | 0.906 / 0.055 | 0.847 / 0.018 |
| jev-latest | holdout | 0.988 / 0.064 | 0.964 / 0.027 | 0.843 / 0.009 |

Threshold chosen on dev (highest recall with dev FPR <= 2%), then measured on
holdout:

| backend | t | dev recall / FPR | holdout recall / FPR |
|---|---|---|---|
| clef-flash | 0.88 | 0.694 / 0.018 | 0.723 / 0.000 |
| jev-latest | 0.87 | 0.871 / 0.018 | 0.892 / 0.009 |

## Where each model fails (t from the table above)

- Both: `scanner_probe` (requests for `/.env`, `/.git/config`, backup files)
  is the largest group of misses; these suit deterministic `deny_paths`.
- clef-flash: also misses most `ssrf` rows at t = 0.88; at t = 0.5 its false
  positives come from WordPress admin actions, file names with dots,
  analytics beacons, code pastes and base64 payloads.
- jev-latest: the remaining false positives come from the `ai_instruction`
  rule on ordinary text ("Ignore the first invoice", a question about a
  chatbot). With `instruction_threshold` 0.8 no allow row is hit and all 15
  prompt-injection rows are still blocked (measured on dev + holdout together,
  so this needs confirming on new data).

## Latency and cost (from a home connection in Japan, via the router)

| backend | p50 | p95 | input tokens per request | cost per 1M requests |
|---|---|---|---|---|
| clef-flash (Workers AI REST) | ~400 ms | 0.76–1.3 s | 869 | ~$33 |
| jev-latest | ~146 ms | ~180 ms | 1,030 | ~$39 |

The default `timeout_ms` (150) would turn most Clef-flash calls from this
location into fail-open allows. Total spend of the three paid runs: 4.55 JPY.

## Caveats

- The dataset is synthetic and small (about 85 scored attacks per split).
- Thresholds were picked on dev; only holdout numbers are out of sample.
