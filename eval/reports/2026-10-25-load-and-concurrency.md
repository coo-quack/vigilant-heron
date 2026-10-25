# Load test and parallel evaluation (2026-10-25)

Machine: MacBook Air M2 (Mac14,2), macOS 27.0 (Darwin 27.0.0, arm64), 8 logical CPUs.
Router: release build of vigilant-heron on the same machine; decision backend is the
local stub decider with a 20 ms delay (`STUB_DELAY_MS=20`). No paid provider was called.
Router config: `worker_threads` unset (tokio default, 8 worker threads); `max_connections` 1024;
`decision.max_concurrency` 64 (default); `decision.timeout_ms` 300 (default).
The client is Python (threads, one connection each), so at 64 threads the client may be the bottleneck.

## Load runs

### Load run: concurrency 1, 1000 requests

- Machine: Darwin 27.0.0 (arm64), 8 logical CPUs, model Mac14,2
- Stub decision delay: 20 ms; router decision.max_concurrency: 64; decision.timeout_ms: 300
- Router worker_threads: unset (tokio default, one per CPU core); max_connections: 1024 (default)
- Duration: 24.45 s; throughput: 40.9 req/s
- Latency ms: p50 24.2, p95 26.4, p99 29.6, mean 24.4
- Status counts: {200: 1000}
- Client transport errors: 0 []
- Decision events logged: 1000; decisions that failed, by decision_error: none

### Load run: concurrency 16, 2000 requests

- Machine: Darwin 27.0.0 (arm64), 8 logical CPUs, model Mac14,2
- Stub decision delay: 20 ms; router decision.max_concurrency: 64; decision.timeout_ms: 300
- Router worker_threads: unset (tokio default, one per CPU core); max_connections: 1024 (default)
- Duration: 3.52 s; throughput: 567.9 req/s
- Latency ms: p50 27.6, p95 34.8, p99 41.1, mean 28.1
- Status counts: {200: 2000}
- Client transport errors: 0 []
- Decision events logged: 2000; decisions that failed, by decision_error: none

### Load run: concurrency 64, 2000 requests

- Machine: Darwin 27.0.0 (arm64), 8 logical CPUs, model Mac14,2
- Stub decision delay: 20 ms; router decision.max_concurrency: 64; decision.timeout_ms: 300
- Router worker_threads: unset (tokio default, one per CPU core); max_connections: 1024 (default)
- Duration: 0.79 s; throughput: 2525.8 req/s
- Latency ms: p50 23.3, p95 27.7, p99 67.0, mean 24.8
- Status counts: {200: 2000}
- Client transport errors: 0 []
- Decision events logged: 2000; decisions that failed, by decision_error: none

## Parallel evaluation: offline, concurrency 1 vs 8

Both backends, both splits, against the stub. Per-row decisions (every field except
latency_ms) and token totals are identical between concurrency 1 and 8.

| backend | split | rows | identical per-row decisions | input tokens (c=1 / c=8) |
|---|---|---|---|---|
| clef | dev | 200 | yes | 144570 / 144570 |
| clef | holdout | 200 | yes | 144836 / 144836 |
| jev | dev | 200 | yes | 144570 / 144570 |
| jev | holdout | 200 | yes | 144836 / 144836 |

Budget guard under concurrency (`--offline --split dev --max-yen 0.02`): cumulative spend
0.0169 JPY at concurrency 1 (4 rows) and 0.0084 JPY at concurrency 8 (2 rows), both under the limit.
At concurrency 8 fewer rows are sent: each in-flight row reserves the larger of the average and
the largest request so far, so the guard is conservative early in a run.
