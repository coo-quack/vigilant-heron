# Command line

The `vigilant-heron` command checks a configuration, runs the router, and sends
signals to a router that is already running. The options follow nginx's, so
`-t`, `-T` and `-s` do what they do in nginx.

## Options

| Option | What it does |
|---|---|
| `-h`, `--help` | Print the usage and exit 0. |
| `-v`, `--version` | Print `vigilant-heron version <version>` and exit 0. |
| `-c <path>`, `--config <path>`, `--config=<path>` | Use this configuration file. |
| `-t` | Check the configuration and exit. Nothing is bound or started. |
| `-T` | Check the configuration, print it with every `include` expanded, and exit. |
| `-s <signal>` | Send a signal to the running router. See below. |

An unknown option, a missing value, or an invalid `-s` word prints the reason and
the usage to stderr, and exits 1. `-h` and `-v` win over the other options. `-s`
cannot be combined with `-t` or `-T`.

With no option, the router starts. The configuration file is chosen in this order:

1. `-c` or `--config`.
2. The `VIGILANT_HERON_CONFIG` environment variable.
3. `/etc/vigilant-heron/vigilant-heron.conf`.

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

## Signal the running router with -s

`-s` sends a signal to the router that is running with the same configuration.

| Word | Signal | What the router does |
|---|---|---|
| `reload` | `SIGHUP` | Reads the configuration again, as [reload](/configuration#reload-and-log-reopen) describes. |
| `reopen` | `SIGUSR1` | Reopens the log files, so logrotate can move them away. |
| `stop` | `SIGTERM` | Shuts down gracefully. |
| `quit` | `SIGQUIT` | Shuts down gracefully. |

In this version `stop` and `quit` both wait for requests in flight, as
[worker_shutdown_timeout](/configuration#worker_shutdown_timeout) describes. There
is no fast shutdown yet.

The pid comes from the file named by the [`pid`](/configuration#pid) directive,
which defaults to `/run/vigilant-heron.pid`. The router writes that file once it
is listening, and removes it on exit. `-s` reads `pid` from the configuration it
is given, so pass the same `-c` as the running router.

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
| `does not hold a process id` | The file was edited by hand or is damaged. |
| `no process <n> is running: the pid file <path> is stale` | The router has stopped, or the file was left by a crash. Delete the file. |

Each of these exits 1.

### Docker

The image runs as `nonroot`, which cannot write to `/run`. Set a `pid` in a path
the user can write, in the configuration mounted into the container:

```nginx
pid /tmp/vigilant-heron.pid;
```

Then the signal words work inside the container too:

```bash
docker exec <container> vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
```

If the router cannot write the pid file at startup, it logs a warning and runs
anyway, so `-s` reports the missing file instead of the router refusing to start.

## Run from source

With the toolchain installed, run the router without installing it. The example
configuration uses the default backend, Jev, so its token variable must be set:

```bash
TYPESAFE_API_KEY=... cargo run --release -- --config examples/vigilant-heron.conf
```

The binary is `target/release/vigilant-heron` after `cargo build --release --locked`.
