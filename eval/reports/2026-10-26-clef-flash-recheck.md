# Clef-flash recheck on the current code (2026-10-26)

Run: `eval/run.py --clef-url ... --split both --max-yen 30` against the real
Clef-flash endpoint, dev and holdout (200 rows each, 90 block / 110 allow), on
develop 2c76471, router decision timeout 3000 ms, `builtin_rules off`. The run
cost 2.08 JPY; with the earlier runs the total is 6.63 JPY of the 30 JPY budget.
Labels did not change since the 2026-10-25 runs.

## Why this run

The security changes after 2026-10-25 touched the path between the router and
the backend: query and header redaction before the event is sent, a `client_busy`
outcome, and an unchanged built-in rule set. Clef-flash was measured again on the
current code to check that the numbers still hold, and to measure latency through
the router, which the earlier runs only partly covered.

`credential_attack` rows are excluded from every number below, as before. A single
login request cannot be told apart from a legitimate one.

## Headline (block if attack >= t or ai_instruction >= 0.5)

| split | t = 0.5 recall / FPR | t = 0.7 recall / FPR | t = 0.9 recall / FPR |
|---|---|---|---|
| dev | 0.988 / 0.227 | 0.965 / 0.127 | 0.635 / 0.000 |
| holdout | 0.988 / 0.191 | 0.916 / 0.109 | 0.699 / 0.000 |

These match the 2026-10-25 Clef-flash runs exactly. Dev FPR at 0.5 is 25 of 110
allowed rows, holdout 21 of 110.

## Threshold chosen on dev

The rule from the 2026-10-25 report is the highest recall with dev FPR at most
2%. It selects 0.88:

| split | t = 0.88 recall / FPR |
|---|---|
| dev (chosen on this split) | 0.694 / 0.018 (2 of 110) |
| holdout (out of sample) | 0.723 / 0.000 |

The two dev false positives at 0.88 are dev-162 (`analytics` beacon, a scroll
depth event) and dev-180 (`hard_negative_code`, a unit test that asserts path
normalization). Holdout has none.

## Latency through the router

Router-side decision latency over all 400 calls: p50 374 ms on dev and 377 ms on
holdout; p95 675 ms on dev and 870 ms on holdout (nearest rank).

Share of calls slower than a given decision timeout. A call slower than the
timeout is a decision error, and `on_decision_error` decides it. The default
`timeout` is 300 ms (`docs/configuration.md`).

| timeout | calls slower than it |
|---|---|
| 150 ms | 100% (400 of 400) |
| 300 ms (default) | 82% (329 of 400) |
| 500 ms | 17.5% (70 of 400) |
| 1000 ms | 3.3% (13 of 400) |
| 1500 ms | 2.0% (8 of 400) |

One holdout row, hold-109, timed out at 3000 ms and was allowed with reason
`decision_error_allowed`. It is counted in the 1000 ms and 1500 ms rows. It was
judged in 333 ms in the 2026-10-25 run, so this is a slow call, not a different
result. The 2026-10-25 report gives the default as 150 ms; the current default is
300 ms.

## Combined pipeline with built-in rules (Clef)

`eval/rules.py` on the release router, with the stub decider. A rule block OR a
model score at or above 0.87 (attack) or 0.8 (ai_instruction) counts as a block.
This is the threshold pair that `rules.py` uses, not the 0.88 chosen above.
`credential_attack` is excluded.

| split | block kind | model only | rules + model |
|---|---|---:|---:|
| dev | all kinds | 62/85 (72.9%) | 69/85 (81.2%) |
| dev | scanner_probe | 2/10 | 3/10 |
| dev | ssrf | 2/7 | 4/7 |
| dev | template_injection | 2/4 | 3/4 |
| holdout | all kinds | 61/83 (73.5%) | 65/83 (78.3%) |
| holdout | scanner_probe | 3/10 | 5/10 |
| holdout | ssrf | 2/7 | 3/7 |
| holdout | prompt_injection | 5/9 | 5/9 |

False positives: dev 3 of 110 (2.7%) with the model alone and with rules + model
(dev-162, dev-175, dev-180; dev-175 is a parameterized-query snippet pasted to
`/paste`, scored 0.875). Holdout 0 of 110 in both. No allowed row was decided
by a built-in rule on either split. The rules add recall, and they add no false
positive.

The holdout result for hold-109 is "model did not block": the row has no scores,
so the pipeline counts it as allowed by the model, as the router did.

## Where Clef-flash fails

At t = 0.5 the false positives come from these allowed kinds (dev / holdout):

| allow kind | dev | holdout |
|---|---:|---:|
| hard_negative_code | 6/6 | 5/6 |
| wp_admin | 4/8 | 5/8 |
| filename_dots | 3/8 | 4/8 |
| hard_negative_base64 | 3/7 | 3/7 |
| analytics | 2/6 | 2/6 |
| hard_negative_text | 4/8 | 1/8 |
| search, japanese_form, login | 1 each on dev | 1 on holdout (search) |

Misses at 0.5 are few: one `xss` row on dev and one `prompt_injection` row on
holdout. At t = 0.88, `scanner_probe` recall is 1/10 on dev and 3/10 on holdout,
and `ssrf` recall is 2/7 on both splits. Scanner probes such as `/.env` and
`/.git/config` are a better fit for `deny_path` than for the model.

## Using Clef-flash

These follow from the numbers above. They are not a tested configuration.

- Set `timeout` to about 1000 ms when calling Clef-flash from a network like this
  one. At 1000 ms, 3.3% of calls still exceed it, and those follow
  `on_decision_error`. At the default 300 ms, about 82% of calls would fail and
  be allowed without the model.
- `block_threshold` around 0.88 keeps false positives near zero on this data, but
  recall falls to about 72% (holdout 0.723, dev 0.694). Lower thresholds block
  WordPress admin actions, code pastes, base64 payloads and dotted file names.
- Start in shadow mode. Read the `would_have` lines for your own traffic before
  enforcing. Consider skip rules for authenticated admin paths only after the
  shadow logs show what those paths send.
- Built-in rules and `deny_path` cover part of what Clef misses, mainly scanner
  probes. Keep them on.

## Caveats

- The dataset is synthetic. Each split has about 85 scored attacks, so one row
  moves recall by about 1.2 points.
- One network location. Latency is measured at the router, and the same location
  produced all the numbers.
- Thresholds were chosen on dev. Only the holdout figures are out of sample. The
  built-in rules were tuned on dev only.
- The run used a 3000 ms timeout, so the latency above 3000 ms is not measured.
  The timeout table is computed from the observed latencies only.
