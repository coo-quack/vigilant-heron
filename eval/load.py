#!/usr/bin/env python3
"""Load test for the router against the local upstream and the stub decider.

Run with `python3 -I eval/load.py`. It uses only the standard library and never
calls a paid provider: it always starts the stub decider with `STUB_DELAY_MS`.

It reports throughput, latency percentiles, status counts, and how many
decisions failed, grouped by the `decision_error` value in the router's log.
"""

import argparse
import datetime
import http.client
import json
import os
import pathlib
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "eval" / "results"
ROUTER_BIN = ROOT / "target" / "release" / "vigilant-heron"
STUB_BIN = ROOT / "target" / "release" / "stub-decider"
STUB_PORT = 9000
SITE_HOST = "load.example.com"
CONFIG_TEXT = """listen = "@LISTEN@"
log_format = "json"
request_id_header = "x-request-id"
@WORKER_THREADS@

[decision]
backend = "http"
url = "http://127.0.0.1:9000/decide"
timeout_ms = 300
max_concurrency = @MAX_CONCURRENCY@
inspect_body_bytes = 8192
max_body_bytes = 10485760

[default]
status = 421

[[sites]]
hosts = ["load.example.com"]
upstream = "http://127.0.0.1:@UPSTREAM@"
mode = "enforce"
action = "block"
block_threshold = 0.87
instruction_threshold = 0.8
"""


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


def start_upstream(port):
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def respond(self):
            body = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_HEAD = do_POST = respond

        def log_message(self, fmt, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def percentile(values, fraction):
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def run_load(port, concurrency, requests):
    """Sends `requests` GET requests from `concurrency` threads, each on its own connection."""
    lock = threading.Lock()
    next_index = [0]
    latencies = []
    statuses = {}
    errors = []

    def worker():
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        while True:
            with lock:
                index = next_index[0]
                if index >= requests:
                    break
                next_index[0] += 1
            started = time.perf_counter()
            try:
                connection.request(
                    "GET",
                    f"/articles/{index % 500}",
                    headers={"Host": SITE_HOST, "X-Request-Id": f"load-{index}"},
                )
                response = connection.getresponse()
                response.read()
                status = response.status
            except (OSError, http.client.HTTPException) as error:
                errors.append(type(error).__name__)
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                status = None
            elapsed_ms = (time.perf_counter() - started) * 1000
            with lock:
                latencies.append(elapsed_ms)
                statuses[status] = statuses.get(status, 0) + 1
        connection.close()

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    duration = time.perf_counter() - started
    return duration, latencies, statuses, errors


def decision_errors(log_path):
    counts = {}
    decisions = 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("target") != "vigilant_heron::decision":
            continue
        decisions += 1
        cause = entry.get("fields", {}).get("decision_error")
        if cause is not None:
            counts[cause] = counts.get(cause, 0) + 1
    return decisions, counts


def machine_description():
    model = ""
    try:
        model = subprocess.run(
            ["sysctl", "-n", "hw.model"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        pass
    return f"{platform.system()} {platform.release()} ({platform.machine()}), {os.cpu_count()} logical CPUs, model {model or 'unknown'}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--stub-delay-ms", type=int, default=20)
    parser.add_argument("--max-concurrency", type=int, default=64, help="decision.max_concurrency of the router")
    parser.add_argument("--worker-threads", type=int, help="runtime worker_threads (default: absent, one per CPU core)")
    parser.add_argument("--router", type=pathlib.Path, default=ROUTER_BIN)
    args = parser.parse_args()
    if args.concurrency < 1 or args.requests < 1:
        raise SystemExit("--concurrency and --requests must be at least 1")
    if not args.router.exists() or not STUB_BIN.exists():
        raise SystemExit("build the release binaries first: cargo build --release --workspace")
    if port_open(STUB_PORT):
        raise SystemExit("port 9000 is in use; stop the other stub so this run controls the delay")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    processes = []
    upstream = None
    try:
        stub_env = dict(os.environ, STUB_DELAY_MS=str(args.stub_delay_ms))
        stub = subprocess.Popen([str(STUB_BIN)], env=stub_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(stub)
        wait_for_port(STUB_PORT, stub)

        upstream_port = free_port()
        upstream = start_upstream(upstream_port)
        router_port = free_port()
        config_path = RESULTS_DIR / f"{stamp}-load-config.toml"
        config_path.write_text(
            CONFIG_TEXT.replace("@LISTEN@", f"127.0.0.1:{router_port}")
            .replace("@UPSTREAM@", str(upstream_port))
            .replace("@MAX_CONCURRENCY@", str(args.max_concurrency))
            .replace(
                "@WORKER_THREADS@",
                f"worker_threads = {args.worker_threads}" if args.worker_threads else "",
            ),
            encoding="utf-8",
        )
        log_path = RESULTS_DIR / f"{stamp}-load-router.log"
        with log_path.open("wb") as log_file:
            router = subprocess.Popen(
                [str(args.router), "--config", str(config_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
        processes.append(router)
        wait_for_port(router_port, router)

        duration, latencies, statuses, errors = run_load(router_port, args.concurrency, args.requests)
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

    decisions, failures = decision_errors(log_path)
    done = len(latencies)
    lines = [
        f"## Load run: concurrency {args.concurrency}, {args.requests} requests",
        "",
        f"- Machine: {machine_description()}",
        f"- Stub decision delay: {args.stub_delay_ms} ms; router decision.max_concurrency: {args.max_concurrency}; decision.timeout_ms: 300",
        f"- Router worker_threads: {args.worker_threads if args.worker_threads else 'unset (tokio default, one per CPU core)'}; max_connections: 1024 (default)",
        f"- Duration: {duration:.2f} s; throughput: {done / duration:.1f} req/s",
        f"- Latency ms: p50 {percentile(latencies, 0.5):.1f}, p95 {percentile(latencies, 0.95):.1f}, p99 {percentile(latencies, 0.99):.1f}, mean {statistics.fmean(latencies):.1f}",
        f"- Status counts: {dict(sorted(statuses.items(), key=lambda item: str(item[0])))}",
        f"- Client transport errors: {len(errors)} {sorted(set(errors))}",
        f"- Decision events logged: {decisions}; decisions that failed, by decision_error: {failures or 'none'}",
        "",
    ]
    print("\n".join(lines))
    print(f"Router log: {log_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
