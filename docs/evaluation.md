# Evaluation

The router is measured in three ways: the decision models on a labelled dataset,
the built-in rules on the same dataset, and the router's load and concurrency
behaviour against a local stub backend. The full reports are in the repository's
[`eval/reports`](https://github.com/coo-quack/vigilant-heron/tree/develop/eval/reports)
directory. This page summarizes them and states their limits.

::: warning Limits of these numbers
The dataset is synthetic and small, with about 85 scored attacks and 110 allowed
requests per split. Thresholds were chosen on the dev split, so only the holdout
figures are out of sample. Credential-attack rows are excluded, because one login
request cannot be told apart from a legitimate login. None of this shows how a
model or a rule behaves on your traffic. Run a site in shadow mode first.
:::

## Decision models: Clef-flash and Jev

Report: [Clef-flash vs Jev on the labelled dataset](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/reports/2026-10-25-clef-flash-vs-jev.md)
(2026-10-25). Each model ran against the real provider on the dev and holdout
splits, with a decision timeout of 3000 ms.

The headline rule blocks a request when `attack` is at least the threshold, or
when `ai_instruction` is at least 0.5. Recall is the share of attacks blocked, and
FPR is the share of allowed requests blocked.

| Backend | Split | Threshold 0.7 recall / FPR | Threshold 0.9 recall / FPR |
|---|---|---|---|
| clef-flash | dev | 0.965 / 0.127 | 0.635 / 0.000 |
| clef-flash | holdout | 0.916 / 0.109 | 0.699 / 0.000 |
| jev-latest | dev | 0.906 / 0.055 | 0.847 / 0.018 |
| jev-latest | holdout | 0.964 / 0.027 | 0.843 / 0.009 |

With the threshold chosen on dev (the highest recall at a dev FPR of 2% or less),
the holdout results were:

| Backend | Threshold | Dev recall / FPR | Holdout recall / FPR |
|---|---|---|---|
| clef-flash | 0.88 | 0.694 / 0.018 | 0.723 / 0.000 |
| jev-latest | 0.87 | 0.871 / 0.018 | 0.892 / 0.009 |

The report's findings on where each model fails:

- Both models miss most `scanner_probe` requests, such as requests for `/.env`
  and `/.git/config`. Deterministic `deny_path` entries suit these better.
- clef-flash also misses most SSRF rows at the 0.88 threshold. At 0.5, its false
  positives come from WordPress admin actions, file names with dots, analytics
  beacons, code pastes and base64 payloads.
- jev-latest's remaining false positives come from the `ai_instruction` score on
  ordinary text. With `instruction_threshold` 0.8, no allowed row was blocked, and
  all 15 prompt-injection rows were still blocked on dev and holdout together.

The report measured latency and cost from a home connection in Japan through the
router: clef-flash had a p50 of about 400 ms and jev-latest about 146 ms. Its
paid runs cost 4.55 JPY in total.

## Built-in rules

Report: [Built-in rules: measurement on the labelled dataset](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/reports/2026-10-25-builtin-rules.md)
(2026-10-25). The 24 [built-in rules](/builtin-rules) ran on the same dev and
holdout splits through the router, and their results were combined with the saved
model scores.

- No allowed row was blocked by a rule, on either split.
- With Jev, the combination of rules and model had no false positives. The rules
  added recall in every split.
- With Clef, the combination blocked three dev allowed rows (dev-162, dev-175 and
  dev-180). The model alone blocked the same three, so the rules added none.
- The dataset has no deserialization rows, and it has no credential-attack rows
  that single requests could show. Those kinds stay at the model's level.

The rules were written from attack syntax, not from the dataset ids. The first
run on dev already had no allowed row hit by a rule, so no rule was changed after
that run. Holdout was run once, with the same rule file.

## Load and concurrency

Report: [Load test and parallel evaluation](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/reports/2026-10-25-load-and-concurrency.md)
(2026-10-25). The runs used a release build on a MacBook Air M2 with 8 logical
CPUs. The decision backend was the local stub with a 20 ms delay, so no paid
provider was called. The client is a Python program with one connection per
thread, so at high concurrency the client may be the bottleneck.

| Concurrency | Requests | Throughput | p50 | p95 | p99 | Status |
|---|---|---|---|---|---|---|
| 1 | 1000 | 40.9 req/s | 24.2 ms | 26.4 ms | 29.6 ms | 200 for all |
| 16 | 2000 | 567.9 req/s | 27.6 ms | 34.8 ms | 41.1 ms | 200 for all |
| 64 | 2000 | 2525.8 req/s | 23.3 ms | 27.7 ms | 67.0 ms | 200 for all |

Parallel evaluation gave the same per-row decisions at concurrency 1 and 8, for
both backends and both splits, and the same token totals. Latency was the only
field that differed.

The report also checks saturation. With `max_concurrency` set to 16 and no queue,
a call that found no free slot was counted as `backend_busy`, and the site's
`on_rate_limit allow` forwarded every request. Queueing within `queue_timeout` is
covered by the tests, not by this load run.

## What is not measured

- Traffic from your own sites, and the false positives that it would produce.
- Latency of the paid backends from your location, beyond the single Japan
  measurement above.
- Credential attacks, which need a rate-based control such as `limit_req`.
- Deserialization attacks. No built-in rule and no dataset row covers them.
