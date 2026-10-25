#!/usr/bin/env python3
"""Measure the router with Cloudflare Clef-flash on the labelled dataset.

Run with `python3 -I eval/run.py`. The script uses only the standard library.

It starts a local upstream and a release build of vigilant-heron, sends the
rows of eval/dataset/*.jsonl one by one, joins each row with its decision log
event, and prints a Markdown report. Labels are never changed by this script.
"""

import argparse
import datetime
import http.client
import http.server
import json
import os
import pathlib
import socket
import statistics
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "eval" / "dataset"
RESULTS_DIR = ROOT / "eval" / "results"
TEMPLATE = ROOT / "eval" / "config.template.toml"
ROUTER_BIN = ROOT / "target" / "release" / "vigilant-heron"
STUB_BIN = ROOT / "target" / "release" / "stub-decider"

SITE_HOST = "eval.example.com"
OFFLINE_TOKEN = "test-token"
STUB_PORT = 9000
JEV_DEFAULT_URL = "https://api.typesafe.ai/v1/systemone"
JPY_PER_USD = 158
# Per backend: the token variable, the model, the price per million input tokens
# (Clef-flash $0.038, Jev $0.0375), and the stub endpoint used with --offline.
BACKENDS = {
    "clef": {
        "token_env": "CLOUDFLARE_AI_TOKEN",
        "model": "clef-flash",
        "usd_per_mtok": 0.038,
        "offline_url": "http://127.0.0.1:9000/client/v4/accounts/test/ai/run/@cf/cloudflare/clef-flash",
    },
    "jev": {
        "token_env": "TYPESAFE_API_KEY",
        "model": "jev-latest",
        "usd_per_mtok": 0.0375,
        "offline_url": "http://127.0.0.1:9000/v1/systemone",
    },
}
# Used for the budget check before the first request, when no average exists yet.
FIRST_REQUEST_TOKEN_ESTIMATE = 1500
THRESHOLDS = (0.5, 0.7, 0.9)
PRIMARY_THRESHOLD = 0.5
INSTRUCTION_THRESHOLD = 0.5
# Expected Clef category for block kinds that map to one category. Other kinds
# are reported as not applicable.
CATEGORY_FOR_KIND = {
    "sql_injection": "sql_injection",
    "xss": "xss",
    "path_traversal": "path_traversal",
    "command_injection": "command_injection",
    "file_inclusion": "file_inclusion",
    "ssrf": "ssrf",
    "scanner_probe": "scanner_probe",
    "credential_attack": "credential_attack",
}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_port(port, process=None, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"process exited early with code {process.returncode}")
        if port_open(port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open within {seconds} seconds")


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Answers every method with 200 `ok`, so an allowed row shows up as 200."""

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


def start_upstream(port):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), UpstreamHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def load_rows(split):
    rows = []
    for name in ("dev", "holdout") if split == "both" else (split,):
        path = DATASET_DIR / f"{name}.jsonl"
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    row = json.loads(line)
                    row["split"] = name
                    rows.append(row)
    return rows


def splits_to_run(split):
    return ["dev", "holdout"] if split == "both" else [split]


def send_row(port, row):
    request = row["request"]
    target = request["path"] + (f"?{request['query']}" if request["query"] else "")
    headers = {"Host": SITE_HOST}
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
        return response.status, response.getheader("x-vigilant-heron")
    finally:
        connection.close()


class DecisionLog:
    """Reads the router's JSON log and returns decision events in order."""

    def __init__(self, path):
        self.path = path
        self.offset = 0

    def next_event(self, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.path.open("rb") as handle:
                handle.seek(self.offset)
                data = handle.read()
            lines = data.split(b"\n")
            for line in lines[:-1]:
                self.offset += len(line) + 1
                if not line.strip():
                    continue
                entry = json.loads(line)
                if entry.get("target") == "vigilant_heron::decision":
                    return entry.get("fields", {})
            time.sleep(0.05)
        return None


def yen(tokens, usd_per_mtok):
    return tokens * usd_per_mtok / 1_000_000 * JPY_PER_USD


def run_split(split, rows, router_port, log, max_yen, result_handle, state):
    """Sends the rows of one split. `state` is shared across splits for the budget.

    `state["base_yen"]` is what earlier runs spent; the budget covers base plus this run.
    """
    results = []
    for row in rows:
        average = state["tokens"] / state["done"] if state["done"] else FIRST_REQUEST_TOKEN_ESTIMATE
        spent_yen = state["base_yen"] + yen(state["tokens"], state["price"])
        next_yen = yen(average, state["price"])
        if spent_yen + next_yen > max_yen:
            state["stopped"] = True
            break
        status, debug = send_row(router_port, row)
        event = log.next_event()
        join_ok = bool(event) and event.get("method") == row["request"]["method"] and event.get("path") == row["request"]["path"]
        tokens = event.get("input_tokens") if event else None
        if isinstance(tokens, int):
            state["tokens"] += tokens
        state["done"] += 1
        record = {
            "id": row["id"],
            "split": split,
            "label": row["label"],
            "kind": row["kind"],
            "status": status,
            "blocked": status == 403,
            "debug": debug,
            "action": event.get("action") if event else None,
            "reason": event.get("reason") if event else None,
            "attack": event.get("attack") if event else None,
            "ai_instruction": event.get("ai_instruction") if event else None,
            "category": event.get("category") if event else None,
            "input_tokens": tokens if isinstance(tokens, int) else None,
            "latency_ms": event.get("latency_ms") if event else None,
            "join_ok": join_ok,
        }
        results.append(record)
        result_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        result_handle.flush()
    return results


def predicted_block(record, threshold):
    if record["attack"] is None or record["ai_instruction"] is None:
        return False
    return record["attack"] >= threshold or record["ai_instruction"] >= INSTRUCTION_THRESHOLD


def percentile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return None
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def report(split, rows_total, results, stopped, errors_missing_tokens, usd_per_mtok):
    lines = [f"## Split: {split}", ""]
    scored = [r for r in results if r["attack"] is not None]
    blocks = [r for r in results if r["label"] == "block"]
    allows = [r for r in results if r["label"] == "allow"]
    lines.append(f"- Rows in split: {rows_total}; sent: {len(results)}; scored: {len(scored)}")
    lines.append(f"- Stopped by the budget guard: {'yes, partial run' if stopped else 'no'}")
    lines.append(f"- Labels: {len(blocks)} block, {len(allows)} allow")
    lines.append(f"- Join mismatches (decision event not matching the row): {sum(not r['join_ok'] for r in results)}")
    unjudged = [r["id"] for r in results if r["attack"] is None]
    lines.append(f"- Rows with no decision event (never judged, e.g. rejected by the HTTP parser): {len(unjudged)} {unjudged}")
    lines.append(f"- Rows whose response had no input_tokens: {errors_missing_tokens}")
    lines.append("")

    lines.append("### Confusion matrix (predicted block = attack >= t or ai_instruction >= 0.5)")
    lines.append("")
    lines.append("| threshold t | TP | FN | FP | TN | recall | false positive rate |")
    lines.append("|---|---|---|---|---|---|---|")
    for threshold in THRESHOLDS:
        tp = sum(predicted_block(r, threshold) for r in blocks)
        fn = len(blocks) - tp
        fp = sum(predicted_block(r, threshold) for r in allows)
        tn = len(allows) - fp
        recall = tp / len(blocks) if blocks else 0.0
        fpr = fp / len(allows) if allows else 0.0
        lines.append(f"| {threshold} | {tp} | {fn} | {fp} | {tn} | {recall:.3f} | {fpr:.3f} |")
    router_tp = sum(r["blocked"] for r in blocks)
    router_fp = sum(r["blocked"] for r in allows)
    lines.append(f"| router (403 at its configured thresholds) | {router_tp} | {len(blocks) - router_tp} | {router_fp} | {len(allows) - router_fp} | {router_tp / len(blocks) if blocks else 0:.3f} | {router_fp / len(allows) if allows else 0:.3f} |")
    lines.append("")

    lines.append("### Recall per block kind (t = 0.5)")
    lines.append("")
    lines.append("| kind | rows | detected | recall | category correct |")
    lines.append("|---|---|---|---|---|")
    for kind in sorted({r["kind"] for r in blocks}):
        group = [r for r in blocks if r["kind"] == kind]
        detected = sum(predicted_block(r, PRIMARY_THRESHOLD) for r in group)
        expected = CATEGORY_FOR_KIND.get(kind)
        if expected is None:
            category = "n/a"
        else:
            category = f"{sum(r['category'] == expected for r in group)}/{len(group)}"
        lines.append(f"| {kind} | {len(group)} | {detected} | {detected / len(group):.3f} | {category} |")
    lines.append("")

    lines.append("### False positive rate per allow kind (t = 0.5)")
    lines.append("")
    lines.append("| kind | rows | false positives | rate |")
    lines.append("|---|---|---|---|")
    for kind in sorted({r["kind"] for r in allows}):
        group = [r for r in allows if r["kind"] == kind]
        false_positives = sum(predicted_block(r, PRIMARY_THRESHOLD) for r in group)
        lines.append(f"| {kind} | {len(group)} | {false_positives} | {false_positives / len(group):.3f} |")
    lines.append("")

    ai_hits = [r["id"] for r in allows if r["ai_instruction"] is not None and r["ai_instruction"] >= INSTRUCTION_THRESHOLD]
    lines.append(f"- ai_instruction >= 0.5 on allow rows: {len(ai_hits)} {ai_hits}")
    category_rows = [r for r in blocks if CATEGORY_FOR_KIND.get(r["kind"]) is not None]
    correct = sum(r["category"] == CATEGORY_FOR_KIND[r["kind"]] for r in category_rows)
    lines.append(f"- Category accuracy on block rows with one expected category: {correct}/{len(category_rows)}")
    latencies = [r["latency_ms"] for r in results if isinstance(r["latency_ms"], int)]
    lines.append(f"- Latency ms: p50 {percentile(latencies, 0.5)}, p95 {percentile(latencies, 0.95)}")
    tokens = sum(r["input_tokens"] or 0 for r in results)
    usd = tokens * usd_per_mtok / 1_000_000
    lines.append(f"- Input tokens: {tokens}; cost: ${usd:.6f} = {usd * JPY_PER_USD:.4f} JPY")
    false_negatives = [r["id"] for r in blocks if not predicted_block(r, PRIMARY_THRESHOLD)]
    false_positives = [r["id"] for r in allows if predicted_block(r, PRIMARY_THRESHOLD)]
    lines.append(f"- Misclassified at t = 0.5: false negatives {false_negatives}; false positives {false_positives}")
    lines.append("")
    return "\n".join(lines)


def start_stub_if_needed():
    if port_open(STUB_PORT):
        return None
    if not STUB_BIN.exists():
        raise SystemExit("stub-decider is not built: run cargo build --release -p stub-decider")
    process = subprocess.Popen([str(STUB_BIN)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for_port(STUB_PORT, process)
    return process


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backend", choices=sorted(BACKENDS), default="clef")
    parser.add_argument("--split", choices=["dev", "holdout", "both"], default="both")
    parser.add_argument("--offline", action="store_true", help="use the stub decider instead of the provider")
    parser.add_argument("--clef-url", help="full clef-flash endpoint URL (Clef, without --offline)")
    parser.add_argument("--jev-url", default=JEV_DEFAULT_URL, help="System One endpoint for Jev")
    parser.add_argument("--usd-per-mtok", type=float, help="input price per million tokens (default per backend)")
    parser.add_argument("--max-yen", type=float, default=30.0, help="budget in JPY for base spend plus this run")
    parser.add_argument("--spent-yen", type=float, default=0.0, help="JPY already spent by earlier runs")
    parser.add_argument("--limit", type=int, help="send at most N rows of each split")
    parser.add_argument("--router", type=pathlib.Path, default=ROUTER_BIN)
    args = parser.parse_args()

    backend = BACKENDS[args.backend]
    price = args.usd_per_mtok if args.usd_per_mtok is not None else backend["usd_per_mtok"]
    if args.offline:
        decision_url = backend["offline_url"]
        token = OFFLINE_TOKEN
    else:
        if args.backend == "clef":
            if not args.clef_url:
                raise SystemExit("--clef-url is required for --backend clef unless --offline is given")
            decision_url = args.clef_url
        else:
            decision_url = args.jev_url
        token = os.environ.get(backend["token_env"], "")
        if not token.strip():
            raise SystemExit(f"{backend['token_env']} must be set; the token is read from the environment only")
    if not args.router.exists():
        raise SystemExit(f"router binary not found: {args.router}; run cargo build --release")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    processes = []
    upstream = None
    result_files = {}
    try:
        if args.offline:
            stub = start_stub_if_needed()
            if stub is not None:
                processes.append(stub)

        upstream_port = free_port()
        upstream = start_upstream(upstream_port)
        router_port = free_port()
        config_path = RESULTS_DIR / f"{stamp}-{args.backend}-config.toml"
        config_text = TEMPLATE.read_text(encoding="utf-8")
        for placeholder, value in {
            "@LISTEN@": f"127.0.0.1:{router_port}",
            "@UPSTREAM@": f"http://127.0.0.1:{upstream_port}",
            "@BACKEND@": args.backend,
            "@MODEL@": backend["model"],
            "@DECISION_URL@": decision_url,
            "@TOKEN_ENV@": backend["token_env"],
        }.items():
            config_text = config_text.replace(placeholder, value)
        config_path.write_text(config_text, encoding="utf-8")
        log_path = RESULTS_DIR / f"{stamp}-{args.backend}-router.log"
        log_path.touch()
        env = dict(os.environ)
        env[backend["token_env"]] = token
        with log_path.open("ab") as log_file:
            router = subprocess.Popen(
                [str(args.router), "--config", str(config_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
            )
        processes.append(router)
        wait_for_port(router_port, router)

        log = DecisionLog(log_path)
        state = {"tokens": 0, "done": 0, "stopped": False, "price": price, "base_yen": args.spent_yen}
        markdown = []
        for split in splits_to_run(args.split):
            rows = load_rows(split)
            if args.limit is not None:
                rows = rows[: args.limit]
            result_path = RESULTS_DIR / f"{stamp}-{args.backend}-{split}.jsonl"
            result_files[split] = result_path
            with result_path.open("w", encoding="utf-8") as handle:
                results = run_split(split, rows, router_port, log, args.max_yen, handle, state)
            missing = sum(1 for r in results if r["input_tokens"] is None)
            markdown.append(report(split, len(rows), results, state["stopped"], missing, price))
            if state["stopped"]:
                break
        run_yen = yen(state["tokens"], price)
        total_yen = args.spent_yen + run_yen
        markdown.append(
            "## Budget\n\n"
            f"- Backend: {args.backend} ({backend['model']}), price ${price} per million input tokens\n"
            f"- Input tokens billed in this run: {state['tokens']}; {run_yen:.4f} JPY\n"
            f"- Spent before this run: {args.spent_yen:.4f} JPY\n"
            f"- Cumulative spend: {total_yen:.4f} JPY (limit {args.max_yen} JPY)\n"
        )
        print("\n".join(markdown))
        for split, path in result_files.items():
            print(f"Per-row results ({split}): {path}")
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
