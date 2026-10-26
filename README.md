# vigilant-heron

[![CI](https://github.com/coo-quack/vigilant-heron/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/coo-quack/vigilant-heron/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

vigilant-heron is a reverse-proxy router. It sits between your edge (nginx or Cloudflare) and your site, and it checks each web request before the request reaches the site. Obvious attacks are blocked by fixed rules. Anything less obvious is sent to a decision model, which returns scores for the request. The router then blocks, redirects, or forwards the request.

Use it when you want a second screen in front of an application, with its own logs, its own limits, and a choice of model.

> **Status:** early development. It has not been validated on real traffic. Run every new site in shadow mode first.

```
client ──► nginx / Cloudflare ──► vigilant-heron ──► your site (upstream)
                                      │
                                      └──► decision model (Jev, Clef, Strands Decider, or your own)
```

## Install

Build from source. You need the Rust toolchain that `rust-toolchain.toml` names. `rustup` installs it on the first build:

```bash
git clone https://github.com/coo-quack/vigilant-heron.git
cd vigilant-heron
cargo build --release --locked
./target/release/vigilant-heron --version
```

To put the binary on your `PATH`, run `cargo install --locked --path .` in the clone.

**Docker.** No image is published yet, so build it from the Dockerfile:

```bash
docker build -t vigilant-heron .
docker run --rm vigilant-heron --version
```

The container runs as `nonroot`, so its configuration must set `listen 0.0.0.0:8080;` and a writable pid file, for example `pid /tmp/vigilant-heron.pid;`. See [Installation](docs/install.md) for the full Docker example, Docker Compose, nginx and Cloudflare in front, and systemd.

## Quick start

1. **Write a configuration file.** Save this as `vigilant-heron.conf`. It listens on port 8080, uses the Jev decision model, and forwards `example.com` to a local app on port 3000. Shadow mode records what the router would block, but blocks nothing.

   ```nginx
   listen 127.0.0.1:8080;              # the address the router listens on

   decision {
       backend jev;                    # the decision model; reads its key from TYPESAFE_API_KEY
   }

   site example.com {
       upstream http://127.0.0.1:3000; # where allowed requests go
       mode shadow;                    # record decisions, block nothing
   }
   ```

2. **Check the file.** `-t` reads and validates the file, then exits. It starts nothing.

   ```console
   $ TYPESAFE_API_KEY=... vigilant-heron -t -c vigilant-heron.conf
   configuration file vigilant-heron.conf test is successful
   ```

3. **Run the router.** Keep it running in its own terminal or service.

   ```bash
   TYPESAFE_API_KEY=... vigilant-heron -c vigilant-heron.conf
   ```

4. **Point nginx at the router.** nginx stays in front, terminates TLS, and passes the real client address and WebSocket headers to the router:

   ```nginx
   upstream vigilant_heron {
       server 127.0.0.1:8080;          # the router's listen address
       keepalive 16;
   }

   server {
       listen 443 ssl;
       server_name example.com;

       location / {
           proxy_pass http://vigilant_heron;
           proxy_http_version 1.1;                                # WebSocket upgrades need HTTP/1.1
           proxy_set_header Host $host;                           # sites are matched on this header
           proxy_set_header X-Real-IP $remote_addr;               # the client address, read by real_ip_from
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection $connection_upgrade;
       }
   }

   map $http_upgrade $connection_upgrade {
       default upgrade;
       ''      close;
   }
   ```

   Add these lines to the router's configuration too, so it trusts only nginx's address for the client address:

   ```nginx
   real_ip_from 127.0.0.1;             # trust X-Real-IP only from nginx
   real_ip_header X-Real-IP;
   ```

5. **Watch the log in shadow mode.** Each request gets one JSON line on stdout. A line with `"would_have":"block"` is a request the router would have blocked. Read a day of these before you move on.

6. **Switch to enforce.** When the blocked requests are the ones you expect, change `mode shadow;` to `mode enforce;` and run `vigilant-heron -s reload -c vigilant-heron.conf`. The reload applies the new file without a restart. For Cloudflare or a Docker setup, see [Getting started](docs/getting-started.md).

## CLI

| Option | What it does |
|---|---|
| `-h`, `--help` | Show the usage and exit. |
| `-v`, `--version` | Show the version and exit. |
| `-c <path>`, `--config <path>` | Use this configuration file. |
| `-t` | Check the configuration and exit. |
| `-T` | Check the configuration and print it, with every `include` expanded. |
| `-s reload\|reopen\|stop\|quit` | Signal the running router. `reload` re-reads the file without dropping connections, `reopen` reopens the log files, `stop` and `quit` shut down gracefully. |
| `start` | Check the file, then run the router in the background. It prints `started (pid N)`. |
| `stop` | Stop the background router gracefully and wait until it has exited. |
| `restart` | Check the file, then stop and start the background router. Use it for settings read at startup, such as `listen`. |

The router finds its configuration in this order: `-c`, then the `VIGILANT_HERON_CONFIG` environment variable, then `/etc/vigilant-heron/vigilant-heron.conf`. `-s`, `stop` and `restart` find the running router through the `pid` directive. Under Docker or systemd, run the router in the foreground and let the container or service manager run it. See [Command line](docs/cli.md) for the details. In Docker, send a signal with `docker exec vigilant-heron /usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf`.

## What happens to each request

1. **Limits.** A client that sends too many requests is refused with its status code (`limit_req`, `limit_conn`).
2. **Host check.** A `Host` header with characters that cannot be a host name gets 400.
3. **Access list.** A denied client address gets 403.
4. **Fixed rules.** Built-in and user rules block known attack patterns without asking the model. Skip rules let known-safe requests through. A fixed rule decides the request, and the model cannot change that decision.
5. **Static files.** Plain requests for images, CSS and JavaScript go straight to the site. The router does not ask the model about them.

Built-in virtual patches for specific CVEs are off by default. Turn one on for a site with `enable_rule`. See [Built-in rules](docs/builtin-rules.md) and [From CVE advisories to rules](docs/cve-rules.md).
6. **Model.** The router sends a redacted copy of the request to the model. Cookies and authorization headers are removed, and the body is cut to its first 8 KiB by default. The model returns two scores. A score at or above its threshold blocks the request with 403, or redirects it.
7. **Model failure.** If the model does not answer in time, or answers badly, `on_decision_error` decides. The default is to let the request through. You can set it to block instead.
8. **Forward.** The request goes to the upstream, and the router writes one access line.

In shadow mode, steps 1 to 6 still run and are logged, but every request is forwarded.

## Documentation

The full reference is in [`docs/`](docs/).

- [Getting started](docs/getting-started.md): a minimal configuration, a test attack, shadow mode, enforce mode
- [Installation](docs/install.md): Docker, building from source, nginx or Cloudflare in front, updates
- [Command line](docs/cli.md): every option, `-T`, and `-s` signals
- [Troubleshooting](docs/troubleshooting.md): common symptoms and their fixes
- [Configuration](docs/configuration.md): every directive, with its default and context
- [How it works](docs/how-it-works.md): the request path in detail, shadow mode, failure behavior
- [Decision backends](docs/decision-backends.md): Jev, Clef, Strands Decider, and the JSON protocol for your own model
- [Rules](docs/rules.md) and [built-in rules](docs/builtin-rules.md): access list, rule syntax, the built-in signatures
- [Limits](docs/limits.md) and [timeouts](docs/timeouts.md): request-rate and connection limits, timers
- [Logging](docs/logging.md): access and error logs, log formats, variables
- [Security](docs/security.md): what leaves the router, and what the router can and cannot stop
- [Evaluation](docs/evaluation.md): measurements of the models and the built-in rules
- [Changelog](docs/changelog.md)

## Security

Read [SECURITY.md](SECURITY.md) before you enable a decision model. It explains what is sent to the model, and how the router limits the effect of a model that is wrong. To report a vulnerability, follow the steps in that file.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the toolchain, the checks that CI runs, and the branch workflow.

## License

[MIT](LICENSE)
