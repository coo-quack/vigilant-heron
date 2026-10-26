# Command line

The `vigilant-heron` command checks a configuration, runs the router, runs it in
the background, and sends signals to a router that is already running. The options
follow nginx's, so `-t`, `-T` and `-s` do what they do in nginx.

## Options

| Option | What it does |
|---|---|
| `-h`, `--help` | Print the usage and exit 0. |
| `-v`, `--version` | Print `vigilant-heron version <version>` and exit 0. |
| `-c <path>`, `--config <path>`, `--config=<path>` | Use this configuration file. |
| `-t` | Check the configuration and exit. Nothing is bound or started. |
| `-T` | Check the configuration, print it with every `include` expanded, and exit. |
| `-s <signal>` | Send a signal to the running router. See [Signal the running router with -s](#signal-the-running-router-with-s). |
| `start` | Check the configuration, then run the router in the background. See [Run in the background](#run-in-the-background-start-stop-restart). |
| `stop` | Stop the background router and wait until it has exited. |
| `restart` | Check the configuration, then stop and start the background router. |
| `test-request <file>` | Report what the router would do with one raw HTTP request, without calling the decision backend. See [Check a request with test-request](#check-a-request-with-test-request). |
| `--client <address>` | The client address that `test-request` uses for the access list. The default is `127.0.0.1`. |

An unknown option, a missing value, or an invalid `-s` word prints the reason and
the usage to stderr, and exits 1. `-h` and `-v` win over the other options. `-s`
cannot be combined with `-t`, `-T`, `start`, `stop` or `restart`. Only one of
`start`, `stop` and `restart` may be given. The words `start`, `stop` and
`restart` may come before or after `-c`.

With no option, the router runs in the foreground. The configuration file is
chosen in this order:

1. `-c` or `--config`.
2. The `VIGILANT_HERON_CONFIG` environment variable.
3. `/etc/vigilant-heron/vigilant-heron.conf`.

## Run in the background: start, stop, restart

Use these three commands to run the router on a host that you manage yourself.
Under Docker or systemd, run the router in the foreground instead, and let the
container runtime or systemd watch the process.

- **`start`** checks the configuration first, as `-t` does. An invalid file prints
  the error and starts nothing. If the pid file names a running router, `start`
  prints `already running (pid N)` and exits 1. Otherwise it starts a new router
  in its own process group, with its standard input and output not kept. It waits
  up to 10 seconds for the router to write its pid file, then prints
  `started (pid N)` and exits 0. If the router exits while it starts, `start` exits
  1 and prints the router's startup message. A stale pid file does not stop
  `start`: a pid file counts as running only while a router holds its lock (see
  [One router per pid file](#one-router-per-pid-file)), so a file that names a
  process but has no lock is stale.
- **`stop`** sends the graceful shutdown that `-s quit` sends, then waits until the
  router has exited. It prints `stopped (pid N)`. The wait is the
  [worker_shutdown_timeout](/configuration#worker-shutdown-timeout) plus 5 seconds,
  or 35 seconds (30 seconds plus 5) when that directive is not set. If the router is still running after
  the wait, `stop` exits 1 and says so. It does not kill the process. With no pid
  file, or with a stale one, `stop` prints `not running` and exits 0, as
  `systemctl stop` does. A pid file is stale when no router holds its lock, even
  if the process it names is alive, and `stop` does not signal that process.
- **`restart`** checks the configuration first. An invalid file exits 1, and the
  running router keeps its pid and keeps serving. Otherwise it stops the running
  router, if there is one, and starts a new one.

```console
$ vigilant-heron start -c vigilant-heron.conf
vigilant-heron: warning: error_log writes to a standard stream, which a background router does not keep; set error_log to a file
started (pid 48211)
$ vigilant-heron stop -c vigilant-heron.conf
stopped (pid 48211)
```

A router started with `start` is not restarted if it crashes. Nothing watches it.
Use systemd for that, as [Installation](/install#run-as-a-service-with-systemd) shows.

### One router per pid file

A running router holds an exclusive lock on a file next to its pid file, named
`<pid file>.lock`, until it exits. It takes the lock before it binds its
listen address, so a second router with the same `pid` path does not start. It
exits 1 with this message and does not change the pid file or bind:

```console
$ vigilant-heron -c second.conf
vigilant-heron: another router is using the pid file /run/vigilant-heron.pid
```

The lock file is an empty file. The router never deletes it, so it stays after
the router exits. The lock is what makes a pid file trusted as a running router.
If the lock file cannot be created, or another user owns it inside a shared
directory, the router logs a warning and runs without the lock. Then `-s`, `start`,
`stop` and `restart` treat it as not running, and `start` may start a second
router with the same pid file.

### Standard streams and logs

A background router keeps no standard input or output. If `error_log` or
`access_log` writes to `stdout` or `stderr`, those messages are lost, and `start`
prints a warning. Set both to files for a background router:

```nginx
error_log /var/log/vigilant-heron/error.log warn;
access_log /var/log/vigilant-heron/access.log json;
```

### Reload or restart?

For a change to the configuration, use `-s reload`. It reads the file again and
keeps every connection open, as [Configuration](/configuration#reload-and-log-reopen)
describes. Use `restart` only for a setting that is read at startup. Those are
`listen`, `pid`, `worker_threads`, `worker_shutdown_timeout`, `max_connections`,
and the connection timers and header limits: `client_header_timeout`,
`keepalive_timeout`, `keepalive_requests`, `send_timeout`,
`large_client_header_buffers`, `lingering_close`, `lingering_time` and
`lingering_timeout`. A reload that changes one of them logs a warning, and the
change applies at the next restart.

`restart` stops the old router gracefully, as `stop` does, so requests in flight
finish before the new router starts. A new binary also needs a restart, because a
reload does not load a new program.

## Check the configuration with -t

```console
$ TYPESAFE_API_KEY=... vigilant-heron -t -c vigilant-heron.conf
configuration file vigilant-heron.conf test is successful
$ echo $?
0
```

A failure prints the file and line of the error, then `test failed`, and exits 1.
The check reads the includes, rules, block pages and token variables. A token
variable that is not set fails the check.

## Print the configuration with -T

`-T` runs the same check. If the check passes, it prints the configuration to
stdout. Each include is replaced by the file it names, under a header line, as
`nginx -T` does:

```console
$ TYPESAFE_API_KEY=... vigilant-heron -T -c vigilant-heron.conf > effective.conf
configuration file vigilant-heron.conf test is successful
```

```nginx
# configuration file /etc/vigilant-heron/vigilant-heron.conf:
listen 0.0.0.0:8080;
# include rules.d/*.conf;
# configuration file /etc/vigilant-heron/rules.d/local.conf:
rule local-001 {
    ...
}
```

The output is the file text as written, so comments stay. The line that holds an
include is kept as a comment, and the included files follow it under their own
headers. Token values never appear, because the configuration names only the
variables. An include must be
written alone on one line, ending in `;`, so that `-T` can replace it. Otherwise
`-T` reports an include error at its line.

## Check a request with test-request

`test-request` shows what the router would do with one sample request, before you
deploy a rule or a configuration change. It reads the configuration the same way
`-t` does, and reports the decision. Nothing is bound or forwarded, and neither the
upstream nor the decision backend is contacted.

Because the configuration is checked as `-t` checks it, the variable named by
`api_token_env` must be set. Any value works, since the backend is not called.

```console
$ vigilant-heron -c examples/vigilant-heron.conf test-request examples/requests/sqli-get.http
request: GET "/products?id=1%20UNION%20SELECT%20password%20FROM%20users" (Host: "www.example.com", client: 127.0.0.1)
site: example.com (shadow off)
limits: not simulated (counts depend on earlier requests); limit_req zones: none; limit_conn zones: none
access list: allowed
deny_path: no match
rules: vh-sqli-001 matched (block): UNION SELECT in a query string
result: blocked with 403 by rule vh-sqli-001
$ echo $?
0
```

The request file holds the request line, the header lines, a blank line and an
optional body, as sent on the wire. Lines end in LF or CRLF. A POST looks like this:

```http
POST /api/comments HTTP/1.1
Host: www.example.com
Content-Type: application/json
Content-Length: 31

{"text":"Nice product, thanks"}
```

The example files are in `examples/requests/`. Use `-` to read the request from
standard input:

```console
$ printf 'GET /healthz HTTP/1.1\nHost: www.example.com\n\n' | vigilant-heron -c vigilant-heron.conf test-request -
```

For a request that no rule decides, the report says that it would be sent to the
decision backend, and names the backend. The verdict is not known without calling the
backend, so the report gives the thresholds that would block it:

```console
$ vigilant-heron -c examples/vigilant-heron.conf test-request examples/requests/normal-post.http
...
rules: no block or skip rule matched
static asset skip: does not apply
result: would be sent to the decision backend (jev, model jev-latest); the verdict is not known without calling it
otherwise the request would be forwarded to http://upstream:80/; a verdict of attack 0.87 or more, or ai_instruction 0.8 or more, would be blocked with 403
if the backend fails, the request would be allowed by on_decision_error
```

The checks run in the order the server runs them, and the same code makes the
decisions:

1. The Host picks the site. An invalid Host is refused with 400, and a Host that
   matches no site gets `default_status`.
2. The access list, for the client address given by `--client`.
3. `client_max_body_size`, for a body that is too large.
4. `deny_path`, then block rules, then skip rules, then the static asset skip.

In a shadow site, the report says what would have happened, and that the request
would be forwarded. The limits (`limit_req` and `limit_conn`) depend on the requests
that came before, so `test-request` lists the zones that would apply and does not
count anything. The `realip` settings are not applied: the client address is the one
given by `--client`, or `127.0.0.1`.

The command exits 0 whenever the report is printed, whatever the verdict. A file that
cannot be read, a request that is not valid HTTP/1.1, or an invalid configuration
prints the reason to stderr and exits 1. `test-request` cannot be combined with `-t`,
`-T`, `-s`, `start`, `stop` or `restart`.

## Signal the running router with -s

`-s` sends a signal to the router that is running with the same configuration.

| Word | Signal | What the router does |
|---|---|---|
| `reload` | `SIGHUP` | Reads the configuration again, as [reload](/configuration#reload-and-log-reopen) describes. |
| `reopen` | `SIGUSR1` | Reopens the log files, so logrotate can move them away. |
| `stop` | `SIGTERM` | Shuts down gracefully. |
| `quit` | `SIGQUIT` | Shuts down gracefully. |

In this version `stop` and `quit` both wait for requests in flight, as
[worker_shutdown_timeout](/configuration#worker-shutdown-timeout) describes. There
is no fast shutdown yet.

The pid comes from the file named by the [`pid`](/configuration#pid) directive,
which defaults to `/run/vigilant-heron.pid`. The router writes that file once it
is listening, and removes it on exit. `-s` reads `pid` from the configuration it
is given, so pass the same `-c` as the running router.

`-s` sends a signal only while a router holds the lock of the pid file (see
[One router per pid file](#one-router-per-pid-file)). A pid file without the lock is
stale: `-s` fails and sends nothing, even when the process it names is alive,
because a crashed router's pid can belong to an unrelated process now.

```console
$ vigilant-heron -s reload -c vigilant-heron.conf
$ vigilant-heron -s reopen -c vigilant-heron.conf
$ vigilant-heron -s quit -c vigilant-heron.conf
```

`-s` prints nothing and exits 0 when the signal is sent. It does not wait for the
router to finish the work the signal asks for.

### When -s fails

| Message | Cause |
|---|---|
| `cannot read the pid file <path>` | The router is not running with this configuration, or it has exited without removing the file. |
| `does not hold a process id` | The file was edited by hand or is damaged. A positive decimal process id is required. |
| `is not trusted` | The file sits in a shared directory such as `/tmp` and another user owns it, so its contents are ignored. Put the pid file in a directory that only the router's user can write. |
| `the pid file <path> is stale: no router holds its lock` | The router has stopped, or it crashed and left the file. Nothing was signalled. Delete the file if no router runs. |
| `no process <n> is running: the pid file <path> is stale` | The router has stopped, or the file was left by a crash. Delete the file. |

Each of these exits 1.

### Docker

The image runs as `nonroot` on distroless, which cannot write to `/run`. Put a
`pid` in a path the user can write, in the configuration mounted into the
container:

```nginx
pid /tmp/vigilant-heron.pid;
```

The binary is `/usr/local/bin/vigilant-heron` in the image. Run the signal words
with `docker exec`:

```bash
docker exec <container> /usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
```

If the pid file cannot be written at startup, the router logs a warning and runs
anyway, so `-s` reports the missing file instead of the router refusing to start.
The same holds for the lock file: if it cannot be created or is not trusted, the
router logs a warning and runs without the lock, as described in
[One router per pid file](#one-router-per-pid-file).


## Run from source

With the toolchain installed, run the router without installing it. The example
configuration uses the default backend, Jev, so its token variable must be set:

```bash
TYPESAFE_API_KEY=... cargo run --release -- --config examples/vigilant-heron.conf
```

The binary is `target/release/vigilant-heron` after `cargo build --release --locked`.
