#!/usr/bin/env python3
"""Measure the built-in rules on the labelled dataset, and the combined pipeline.

Run with `python3 -I eval/rules.py`. The script uses only the standard library.

It starts the stub decider if nothing listens on port 9000, a local upstream
and a release build of vigilant-heron with `backend http` pointed at the stub.
Each row of eval/dataset/dev.jsonl and holdout.jsonl is sent once. The row's
`$rule_id` and `reason` are read back from the access log, joined by the
X-Request-Id header.

The report has three parts:

1. Rule blocks per block kind and per split, with the rule ids.
2. Every allow row that a rule decided, with the rule id. The target is none.
3. The combined pipeline (rule block OR model score at or above the thresholds)
   against the saved real-model results, with recall and false positive rate.
   credential_attack rows are excluded from this part.

Labels are never changed. The rule set is tuned on dev only; holdout is reported
once, as the out-of-sample result.
"""

import argparse
import collections
import concurrent.futures
import datetime
import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "eval" / "dataset"
RESULTS_DIR = ROOT / "eval" / "results"
ROUTER_BIN = ROOT / "target" / "release" / "vigilant-heron"
STUB_BIN = ROOT / "target" / "release" / "stub-decider"
STUB_PORT = 9000
SITE_HOST = "eval.example.com"
REQUEST_ID_HEADER = "X-Request-Id"
MODEL_BLOCK_THRESHOLD = 0.87
MODEL_INSTRUCTION_THRESHOLD = 0.8
EXCLUDED_KINDS = {"credential_attack"}
DEFAULT_MODEL_RESULTS = {
    "jev": "20261025T075722Z-jev",
    "clef": "20261025T075350Z-clef",
}


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Answers every request with 200 `ok`, so an allowed row shows up as 200."""

    def respond(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = respond

    def log_message(self, fmt, *args):
        return


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_for_port(port, process=None, seconds=15):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if port_open(port):
            return
        if process is not None and process.poll() is not None:
            raise SystemExit(f"process exited early with status {process.returncode}")
        time.sleep(0.05)
    raise SystemExit(f"nothing listened on port {port} within {seconds} seconds")


def load_rows():
    rows = []
    for name in ("dev", "holdout"):
        with (DATASET_DIR / f"{name}.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    row["split"] = name
                    rows.append(row)
    return rows


def send_row(port, row):
    request = row["request"]
    target = request["path"] + (f"?{request['query']}" if request["query"] else "")
    headers = {"Host": SITE_HOST, REQUEST_ID_HEADER: row["id"]}
    headers.update(request["headers"])
    body = None
    if request["body"] is not None:
        body = request["body"].encode("utf-8")
        headers["Content-Length"] = str(len(body))
    if request["content_type"]:
        headers["Content-Type"] = request["content_type"]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    try:
        connection.request(request["method"], target, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def write_config(path, router_port, upstream_port, access_log):
    text = f"""listen 127.0.0.1:{router_port};
request_id_header x-request-id;
access_log "{access_log}" json;
client_max_body_size 10485760;
decision {{
    backend http;
    url "http://127.0.0.1:{STUB_PORT}/decide";
    timeout 3000ms;
    inspect_body 8192;
}}
default_status 421;

site {SITE_HOST} {{
    upstream "http://127.0.0.1:{upstream_port}";
    mode enforce;
    action block;
    block_threshold 0.5;
    instruction_threshold 0.5;
    # Nothing is skipped as static, so every row reaches the rules and the stub.
    static_extensions zzz-no-row-uses-this;
    debug_headers on;
}}
"""
    path.write_text(text, encoding="utf-8")


def read_log(path, ids, seconds=30):
    """Waits until the access log has a line for every id, and returns the last line per id."""
    deadline = time.time() + seconds
    while True:
        found = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                request_id = record.get("request_id")
                if request_id:
                    found[request_id] = record
        if ids.issubset(found) or time.time() > deadline:
            return found
        time.sleep(0.1)


def run_rules(rows, concurrency):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    access_log = RESULTS_DIR / f"{stamp}-rules-access.jsonl"
    config = RESULTS_DIR / f"{stamp}-rules-config.conf"
    router_port = free_port()
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    write_config(config, router_port, upstream.server_address[1], access_log)

    stub = None
    if not port_open(STUB_PORT):
        if not STUB_BIN.exists():
            raise SystemExit("stub-decider is not built: run cargo build --release --workspace")
        stub = subprocess.Popen([str(STUB_BIN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for_port(STUB_PORT, stub)
    router = subprocess.Popen(
        [str(ROUTER_BIN), "--config", str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_port(router_port, router)
        statuses = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(send_row, router_port, row): row["id"] for row in rows}
            for future in concurrent.futures.as_completed(futures):
                statuses[futures[future]] = future.result()
        log = read_log(access_log, {row["id"] for row in rows})
    finally:
        router.terminate()
        router.wait(timeout=10)
        if stub is not None:
            stub.terminate()
            stub.wait(timeout=10)
        upstream.shutdown()
    results = []
    for row in rows:
        record = log.get(row["id"], {})
        results.append(
            {
                "id": row["id"],
                "split": row["split"],
                "label": row["label"],
                "kind": row["kind"],
                "status": statuses.get(row["id"]),
                "action": record.get("action", ""),
                "reason": record.get("reason", ""),
                "rule_id": record.get("rule_id", ""),
                "missing_log": row["id"] not in log,
            }
        )
    out = RESULTS_DIR / f"{stamp}-rules-rows.jsonl"
    out.write_text("".join(json.dumps(item) + "\n" for item in results), encoding="utf-8")
    return results, out


def rule_blocked(item):
    return item["reason"] == "rule" and item["action"] == "block"


def rule_report(results, splits):
    lines = []
    for split in splits:
        rows = [item for item in results if item["split"] == split]
        blocks = [item for item in rows if item["label"] == "block"]
        allows = [item for item in rows if item["label"] == "allow"]
        blocked_by_rule = [item for item in blocks if rule_blocked(item)]
        allow_hits = [item for item in allows if rule_blocked(item) or item["reason"] == "skip_rule"]
        missing = [item["id"] for item in rows if item["missing_log"] or item["status"] is None]
        lines.append(f"### {split}")
        lines.append("")
        lines.append(
            f"- rows: {len(rows)} ({len(blocks)} block, {len(allows)} allow); "
            f"block rows decided by a rule: {len(blocked_by_rule)}; "
            f"allow rows hit by a rule: {len(allow_hits)}; rows without an access line: {len(missing)}"
        )
        lines.append("")
        lines.append("| block kind | rows | rule blocks | rule ids |")
        lines.append("|---|---:|---:|---|")
        by_kind = collections.defaultdict(list)
        for item in blocks:
            by_kind[item["kind"]].append(item)
        for kind in sorted(by_kind):
            kind_rows = by_kind[kind]
            hits = [item for item in kind_rows if rule_blocked(item)]
            ids = collections.Counter(item["rule_id"] for item in hits)
            summary = ", ".join(f"{rule} x{count}" for rule, count in sorted(ids.items())) or "-"
            lines.append(f"| {kind} | {len(kind_rows)} | {len(hits)} | {summary} |")
        lines.append("")
        lines.append("| allow row | rule | reason |")
        lines.append("|---|---|---|")
        for item in allow_hits:
            lines.append(f"| {item['id']} | {item['rule_id'] or '-'} | {item['reason']} |")
        if not allow_hits:
            lines.append("| none | - | - |")
        lines.append("")
    return "\n".join(lines)


def load_model_results(name):
    scores = {}
    for split in ("dev", "holdout"):
        path = RESULTS_DIR / f"{name}-{split}.jsonl"
        if not path.exists():
            raise SystemExit(f"missing model results: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                scores[record["id"]] = record
    return scores


def pipeline_metrics(rule_results, model_scores, split):
    rows = [
        item
        for item in rule_results
        if item["split"] == split and item["kind"] not in EXCLUDED_KINDS
    ]
    per_kind = collections.defaultdict(lambda: [0, 0])
    model_per_kind = collections.defaultdict(lambda: [0, 0])
    allow_total = 0
    allow_flagged = 0
    allow_model_flagged = 0
    flagged_ids = []
    missing = 0
    unscored_ids = []
    for item in rows:
        score = model_scores.get(item["id"])
        if score is None:
            missing += 1
            continue
        if score.get("attack") is None or score.get("ai_instruction") is None:
            # The router allowed the row without scores (decision error), so the model did not block it.
            unscored_ids.append(item["id"])
            model_block = False
        else:
            model_block = (
                float(score["attack"]) >= MODEL_BLOCK_THRESHOLD
                or float(score["ai_instruction"]) >= MODEL_INSTRUCTION_THRESHOLD
            )
        rule_block = rule_blocked(item)
        if item["label"] == "block":
            per_kind[item["kind"]][1] += 1
            model_per_kind[item["kind"]][1] += 1
            if rule_block or model_block:
                per_kind[item["kind"]][0] += 1
            if model_block:
                model_per_kind[item["kind"]][0] += 1
        else:
            allow_total += 1
            if rule_block or model_block:
                allow_flagged += 1
                flagged_ids.append(item["id"])
            if model_block:
                allow_model_flagged += 1
    return {
        "per_kind": per_kind,
        "model_per_kind": model_per_kind,
        "allow_total": allow_total,
        "allow_flagged": allow_flagged,
        "allow_model_flagged": allow_model_flagged,
        "flagged_ids": flagged_ids,
        "missing": missing,
        "unscored_ids": unscored_ids,
    }


def ratio(hit, total):
    return f"{hit}/{total} ({100.0 * hit / total:.1f}%)" if total else "n/a"


def pipeline_report(rule_results, backend, model_scores):
    lines = [f"### Combined pipeline with {backend} (rule OR model score)", ""]
    for split in ("dev", "holdout"):
        metrics = pipeline_metrics(rule_results, model_scores, split)
        lines.append(f"#### {split}")
        lines.append("")
        lines.append("| block kind | model only | rules + model |")
        lines.append("|---|---:|---:|")
        total_hits = total_model = total_rows = 0
        for kind in sorted(metrics["per_kind"]):
            hit, rows = metrics["per_kind"][kind]
            model_hit = metrics["model_per_kind"][kind][0]
            total_hits += hit
            total_model += model_hit
            total_rows += rows
            lines.append(f"| {kind} | {ratio(model_hit, rows)} | {ratio(hit, rows)} |")
        lines.append(f"| all (excluding credential_attack) | {ratio(total_model, total_rows)} | {ratio(total_hits, total_rows)} |")
        lines.append("")
        lines.append(
            f"- allow rows: {metrics['allow_total']}; false positives model only: "
            f"{ratio(metrics['allow_model_flagged'], metrics['allow_total'])}; "
            f"rules + model: {ratio(metrics['allow_flagged'], metrics['allow_total'])}"
        )
        if metrics["flagged_ids"]:
            lines.append(f"- allow rows flagged by the pipeline: {', '.join(metrics['flagged_ids'])}")
        if metrics["missing"]:
            lines.append(f"- rows without model results: {metrics['missing']}")
        if metrics["unscored_ids"]:
            lines.append(
                "- rows without model scores (decision error; counted as not blocked by the model): "
                + ", ".join(metrics["unscored_ids"])
            )
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--concurrency", type=int, default=8, help="rows in flight at the same time")
    parser.add_argument("--rows", type=pathlib.Path, help="reuse a rows file from an earlier run instead of sending")
    parser.add_argument(
        "--model-results",
        default=",".join(DEFAULT_MODEL_RESULTS.values()),
        help="comma-separated result prefixes for jev and clef, in that order",
    )
    args = parser.parse_args()

    if args.rows:
        results = [json.loads(line) for line in args.rows.read_text(encoding="utf-8").splitlines() if line.strip()]
        rows_file = args.rows
    else:
        if not ROUTER_BIN.exists():
            raise SystemExit("release router is not built: run cargo build --release --workspace")
        results, rows_file = run_rules(load_rows(), args.concurrency)

    print("## Built-in rules on the dataset")
    print()
    print(f"Rows file: {rows_file}")
    print()
    print(rule_report(results, ["dev", "holdout"]))
    prefixes = args.model_results.split(",")
    for backend, prefix in zip(("jev", "clef"), prefixes):
        model_scores = load_model_results(prefix)
        print(pipeline_report(results, backend, model_scores))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
