# Getting started

vigilant-heron runs in front of your sites, behind nginx or Cloudflare. It needs
a configuration file, a decision backend, and a token for that backend when the
backend requires one.

::: warning Status
The project is in early development. Run every new site in `shadow` mode first,
and read the access log before you switch it to `enforce`.
:::

## Install

### Docker image

The image is published for `linux/amd64` and `linux/arm64`. While the repository
is private, the image is also private, so log in to `ghcr.io` first.

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
  ghcr.io/coo-quack/vigilant-heron:latest
```

Replace `latest` with a release from the
[GitHub Releases](https://github.com/coo-quack/vigilant-heron/releases) page to
pin a version. To build the image yourself:

```bash
docker build --target runtime -t vigilant-heron .
```

### Build from source

The toolchain is pinned in `rust-toolchain.toml`. With `rustup` installed, a
release build is:

```bash
cargo build --release --locked
./target/release/vigilant-heron --help
```

The binary is `target/release/vigilant-heron`.

## A minimal configuration

The smallest configuration that runs has a `listen` address, a `decision` block
and one `site`. This one forwards to an upstream and uses the Jev defaults, so
`TYPESAFE_API_KEY` has to be set.

```nginx
listen 0.0.0.0:8080;

decision {
    backend jev;
    timeout 300ms;
}

site example.com {
    upstream http://app:8080;
    mode shadow;
}
```

`backend jev` is the default, so it can be left out. The `url`, `model` and
`api_token_env` defaults are listed in [Configuration](/configuration#decision-block).

Run the router with the configuration file:

```bash
TYPESAFE_API_KEY=... vigilant-heron --config vigilant-heron.conf
```

The config path can also come from `VIGILANT_HERON_CONFIG`. Without either, the
binary reads `/etc/vigilant-heron/vigilant-heron.conf`. All the options are listed
in [Command line](/cli).

## Check the configuration with -t

`-t` checks the configuration the way `nginx -t` does. It reads the includes,
rules, block pages and token variables, validates everything, and exits without
binding the listen address.

```console
$ TYPESAFE_API_KEY=... vigilant-heron -t --config vigilant-heron.conf
configuration file vigilant-heron.conf test is successful
$ echo $?
0
```

On failure the error names the file and line, the last line says the test
failed, and the exit code is 1. A misspelled directive inside `decision` gives:

```console
$ TYPESAFE_API_KEY=... vigilant-heron -t --config broken.conf
vigilant-heron: broken.conf:5: unknown directive "timout" in decision
configuration file broken.conf test failed
$ echo $?
1
```

A missing token variable fails the same way, so `-t` also needs the token in
the environment that the router will run in.

Run `-t` in CI or before every reload.

## Run behind nginx

Usually nginx terminates TLS and forwards to the router. Three things must be
right for the screening to see the real client and the upgrade requests:

- nginx must send the client address in a header, and the router must trust
  only nginx as the peer (`real_ip_from`).
- WebSocket upgrades need the `Upgrade` and `Connection` headers, and HTTP/1.1
  to the router.
- nginx should pass the `Host` header unchanged, because sites match on it.

```nginx
upstream vigilant_heron {
    server 127.0.0.1:8080;
    keepalive 16;
}

server {
    listen 443 ssl;
    server_name example.com;

    location / {
        proxy_pass http://vigilant_heron;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
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

The router side of that setup:

```nginx
real_ip_from 127.0.0.1;
real_ip_header X-Real-IP;
real_ip_recursive off;
```

`real_ip_from` names the peers whose `X-Real-IP` header is believed. Without a
trusted peer, the client is the TCP peer, which behind nginx is always nginx
itself. The access list, the limits and the logs all use the address that the
realip settings choose.

Behind Cloudflare, use the `CF-Connecting-IP` header and list the Cloudflare
ranges in `real_ip_from`:

```nginx
real_ip_from 173.245.48.0/20;   # one line per Cloudflare range you trust
real_ip_header CF-Connecting-IP;
```

Keep the list current. A range that is missing from `real_ip_from` means the
client address is Cloudflare's, and the access list and the limits see that
address instead.

## Shadow mode first

Set `mode shadow;` on a site before you enforce anything on it. In shadow mode
every request is forwarded, rules and limits included, and the access log and
the optional debug header record what would have happened in `would_have`.

```nginx
site example.com {
    upstream http://app:8080;
    mode shadow;
    debug_headers on;
}
```

Read the log for a day or more. Check three things:

1. Requests that would be blocked are the ones you expected to block.
2. No ordinary user, script or health check appears in `would_have=block`.
3. `decision_error` and `reason` show whether the backend is reachable and fast
   enough for the `timeout` you chose.

When the numbers look right, change `mode shadow;` to `mode enforce;` and
reload with `SIGHUP` (see [Configuration](/configuration#reload-and-log-reopen)).

## Next steps

- [How it works](/how-it-works) explains the order in which a request is judged.
- [Configuration](/configuration) lists every directive with its default.
- [Decision backends](/decision-backends) covers the choice of model and the thresholds.
