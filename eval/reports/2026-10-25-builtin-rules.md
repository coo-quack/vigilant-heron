# Built-in rules: measurement on the labelled dataset (2026-10-25)

This report covers the built-in signatures in `src/rules/builtin.conf` (24 rules,
ids `vh-<category>-<nnn>`) on `eval/dataset/dev.jsonl` and `holdout.jsonl`, and
their combination with the saved real-model results.

## Method

- Rules: each row goes through the release router with `backend http` pointing at
  the stub decider and built-in rules on (`eval/rules.py`). The row's `$rule_id`
  and `reason` come from the access log, joined by `X-Request-Id`. Every row got
  an access line (0 missing).
- Tuning: the rule set was written from attack syntax, not from the dataset ids.
  The first run on dev already had 0 allow rows hit by a rule, so no rule was
  changed afterwards. Holdout was run once for the out-of-sample figure, with the
  same rule file. No label was edited.
- Sensitivity check: 31 allow rows contain attack-like tokens (`select`, `union`,
  `<script`, `../`, `javascript:`, `--`, backticks and similar), mostly in the
  hard-negative kinds. None of them is hit, so the zero is not caused by the
  absence of such text.
- Combined pipeline: a row is blocked when a rule blocks it, OR the saved model
  score has `attack >= 0.87`, OR `ai_instruction >= 0.8`. These are the defaults
  of the router, not the 0.5 threshold of the earlier report. `credential_attack`
  rows are excluded. The model-only column uses the same saved scores and
  thresholds, so the two columns differ only by the rules.
- Saved results: Jev `eval/results/20261025T075722Z-jev-{dev,holdout}.jsonl`,
  Clef `eval/results/20261025T075350Z-clef-{dev,holdout}.jsonl`.

## Results

Summary: zero allow rows are hit by a rule on dev or holdout. Rules add recall on
top of the model in every split and for both backends, and the combination has
no false positive on the Jev results. With the Clef results, the combination
flags three dev allow rows (dev-162, dev-175, dev-180), and the model alone
flags the same three, so the rules add none there.

Recall and false positives are measured on this dataset only. The dataset has
no deserialization rule coverage (no built-in rule targets it) and no credential
attack coverage (single requests cannot show it), so those kinds stay at the
model's level.

## Raw output of `python3 -I eval/rules.py`

Rows file (git-ignored): eval/results/20261025T095630Z-rules-rows.jsonl

### dev

- rows: 200 (90 block, 110 allow); block rows decided by a rule: 36; allow rows hit by a rule: 0; rows without an access line: 0

| block kind | rows | rule blocks | rule ids |
|---|---:|---:|---|
| command_injection | 8 | 5 | vh-cmdi-001 x2, vh-cmdi-002 x1, vh-cmdi-003 x1, vh-traversal-002 x1 |
| credential_attack | 5 | 0 | - |
| deserialization | 3 | 0 | - |
| file_inclusion | 5 | 2 | vh-lfi-001 x1, vh-lfi-003 x1 |
| log4shell | 3 | 2 | vh-expr-001 x2 |
| path_traversal | 8 | 6 | vh-traversal-001 x5, vh-traversal-003 x1 |
| prompt_injection | 6 | 2 | vh-sqli-002 x1, vh-traversal-001 x1 |
| scanner_probe | 10 | 2 | vh-scanner-001 x2 |
| sql_injection | 17 | 7 | vh-sqli-001 x3, vh-sqli-002 x2, vh-sqli-004 x2 |
| ssrf | 7 | 3 | vh-ssrf-001 x1, vh-ssrf-002 x2 |
| template_injection | 4 | 1 | vh-expr-002 x1 |
| xss | 11 | 3 | vh-lfi-002 x1, vh-xss-001 x1, vh-xss-002 x1 |
| xxe | 3 | 3 | vh-ssrf-001 x1, vh-xxe-001 x2 |

| allow row | rule | reason |
|---|---|---|
| none | - | - |

### holdout

- rows: 200 (90 block, 110 allow); block rows decided by a rule: 28; allow rows hit by a rule: 0; rows without an access line: 0

| block kind | rows | rule blocks | rule ids |
|---|---:|---:|---|
| command_injection | 8 | 4 | vh-cmdi-001 x1, vh-cmdi-002 x1, vh-traversal-002 x2 |
| credential_attack | 7 | 0 | - |
| deserialization | 3 | 0 | - |
| file_inclusion | 5 | 2 | vh-lfi-001 x1, vh-traversal-001 x1 |
| log4shell | 3 | 2 | vh-expr-001 x2 |
| path_traversal | 7 | 4 | vh-traversal-001 x2, vh-traversal-002 x1, vh-traversal-003 x1 |
| prompt_injection | 9 | 1 | vh-sqli-003 x1 |
| scanner_probe | 10 | 2 | vh-scanner-001 x2 |
| sql_injection | 14 | 3 | vh-sqli-001 x2, vh-sqli-004 x1 |
| ssrf | 7 | 3 | vh-ssrf-001 x1, vh-ssrf-002 x1, vh-traversal-002 x1 |
| template_injection | 4 | 0 | - |
| xss | 10 | 4 | vh-xss-001 x1, vh-xss-002 x1, vh-xss-003 x2 |
| xxe | 3 | 3 | vh-lfi-001 x1, vh-xxe-001 x2 |

| allow row | rule | reason |
|---|---|---|
| none | - | - |

### Combined pipeline with jev (rule OR model score)

#### dev

| block kind | model only | rules + model |
|---|---:|---:|
| command_injection | 6/8 (75.0%) | 7/8 (87.5%) |
| deserialization | 2/3 (66.7%) | 2/3 (66.7%) |
| file_inclusion | 5/5 (100.0%) | 5/5 (100.0%) |
| log4shell | 3/3 (100.0%) | 3/3 (100.0%) |
| path_traversal | 8/8 (100.0%) | 8/8 (100.0%) |
| prompt_injection | 6/6 (100.0%) | 6/6 (100.0%) |
| scanner_probe | 6/10 (60.0%) | 6/10 (60.0%) |
| sql_injection | 17/17 (100.0%) | 17/17 (100.0%) |
| ssrf | 6/7 (85.7%) | 6/7 (85.7%) |
| template_injection | 3/4 (75.0%) | 4/4 (100.0%) |
| xss | 9/11 (81.8%) | 9/11 (81.8%) |
| xxe | 3/3 (100.0%) | 3/3 (100.0%) |
| all (excluding credential_attack) | 74/85 (87.1%) | 76/85 (89.4%) |

- allow rows: 110; false positives model only: 0/110 (0.0%); rules + model: 0/110 (0.0%)

#### holdout

| block kind | model only | rules + model |
|---|---:|---:|
| command_injection | 7/8 (87.5%) | 8/8 (100.0%) |
| deserialization | 3/3 (100.0%) | 3/3 (100.0%) |
| file_inclusion | 5/5 (100.0%) | 5/5 (100.0%) |
| log4shell | 2/3 (66.7%) | 2/3 (66.7%) |
| path_traversal | 7/7 (100.0%) | 7/7 (100.0%) |
| prompt_injection | 9/9 (100.0%) | 9/9 (100.0%) |
| scanner_probe | 6/10 (60.0%) | 8/10 (80.0%) |
| sql_injection | 14/14 (100.0%) | 14/14 (100.0%) |
| ssrf | 6/7 (85.7%) | 6/7 (85.7%) |
| template_injection | 3/4 (75.0%) | 3/4 (75.0%) |
| xss | 9/10 (90.0%) | 9/10 (90.0%) |
| xxe | 3/3 (100.0%) | 3/3 (100.0%) |
| all (excluding credential_attack) | 74/83 (89.2%) | 77/83 (92.8%) |

- allow rows: 110; false positives model only: 0/110 (0.0%); rules + model: 0/110 (0.0%)

### Combined pipeline with clef (rule OR model score)

#### dev

| block kind | model only | rules + model |
|---|---:|---:|
| command_injection | 5/8 (62.5%) | 7/8 (87.5%) |
| deserialization | 2/3 (66.7%) | 2/3 (66.7%) |
| file_inclusion | 5/5 (100.0%) | 5/5 (100.0%) |
| log4shell | 3/3 (100.0%) | 3/3 (100.0%) |
| path_traversal | 8/8 (100.0%) | 8/8 (100.0%) |
| prompt_injection | 6/6 (100.0%) | 6/6 (100.0%) |
| scanner_probe | 2/10 (20.0%) | 3/10 (30.0%) |
| sql_injection | 16/17 (94.1%) | 17/17 (100.0%) |
| ssrf | 2/7 (28.6%) | 4/7 (57.1%) |
| template_injection | 2/4 (50.0%) | 3/4 (75.0%) |
| xss | 8/11 (72.7%) | 8/11 (72.7%) |
| xxe | 3/3 (100.0%) | 3/3 (100.0%) |
| all (excluding credential_attack) | 62/85 (72.9%) | 69/85 (81.2%) |

- allow rows: 110; false positives model only: 3/110 (2.7%); rules + model: 3/110 (2.7%)
- allow rows flagged by the pipeline: dev-162, dev-175, dev-180

#### holdout

| block kind | model only | rules + model |
|---|---:|---:|
| command_injection | 7/8 (87.5%) | 7/8 (87.5%) |
| deserialization | 3/3 (100.0%) | 3/3 (100.0%) |
| file_inclusion | 5/5 (100.0%) | 5/5 (100.0%) |
| log4shell | 2/3 (66.7%) | 2/3 (66.7%) |
| path_traversal | 7/7 (100.0%) | 7/7 (100.0%) |
| prompt_injection | 5/9 (55.6%) | 5/9 (55.6%) |
| scanner_probe | 3/10 (30.0%) | 5/10 (50.0%) |
| sql_injection | 14/14 (100.0%) | 14/14 (100.0%) |
| ssrf | 2/7 (28.6%) | 3/7 (42.9%) |
| template_injection | 1/4 (25.0%) | 1/4 (25.0%) |
| xss | 9/10 (90.0%) | 10/10 (100.0%) |
| xxe | 3/3 (100.0%) | 3/3 (100.0%) |
| all (excluding credential_attack) | 61/83 (73.5%) | 65/83 (78.3%) |

- allow rows: 110; false positives model only: 0/110 (0.0%); rules + model: 0/110 (0.0%)


## Other measurements in the same run

- `eval/run.py --offline --backend jev --split both` at `--concurrency 1` and `8`:
  400 rows, 0 rows differ in any field except `latency_ms`. The harness config now
  sets `builtin_rules off;`. Without that line, the 36 dev and 28 holdout rule
  blocks would have no decision event, and the model numbers would change. The
  offline numbers say nothing about the model's quality; the stub stands in for it.
- Router load, `eval/load.py --concurrency 16 --requests 3000 --stub-delay-ms 20`:
  develop 572 req/s (p50 27.1 ms, p95 34.3 ms), this branch 597 req/s (p50 25.9 ms,
  p95 32.0 ms). Both runs had no transport errors. The difference is within noise.
- `eval/load.py --concurrency 64 --requests 2000 --stub-delay-ms 20` on this
  branch: 2484 req/s, p50 23.4 ms, p95 26.4 ms, p99 80.8 ms, 2000 status 200, no
  transport errors. Runs at concurrency 64 on this machine showed client-side
  `OSError` transport errors in both the develop build and this branch (up to
  about 5000 of 5000 requests in some runs). The cause was not diagnosed, so the
  concurrency-64 throughput numbers are not used for the comparison.
- Cost of the rules: the normalized query, body and header values are computed at
  most once per request. The per-request work with 24 built-in rules and no user
  rules is measured above as parity at concurrency 16.
