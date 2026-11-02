# Installation

You can run vigilant-heron as a binary (downloaded from a GitHub Release, or built from source) or as the published Docker image, and all of them use the same configuration file.

## Requirements

- **Operating system:** The release binaries are for Linux on x86_64 or aarch64 with glibc 2.39 or newer (Ubuntu 24.04, Debian 13, or later). On macOS or an older Linux, build from source. The `-s` signal command and the background commands need a Unix system.
- **Rust toolchain** only to build from source, and **Docker** only for the image. The toolchain version is pinned in `rust-toolchain.toml` as 1.99.1. `rustup` installs it on the first `cargo` call.
- **An API key** for the decision model. The default model, Jev, reads its key from the `TYPESAFE_API_KEY` environment variable. The router refuses to start when that variable is unset or blank. See [Decision backends](/decision-backends) for other models.
- **Outbound HTTPS** from the router to the model's API (`api.typesafe.ai` by default).
- **Network access** from the router to each `upstream` address.

## Download a release binary

Each release on the [Releases page](https://github.com/coo-quack/vigilant-heron/releases) has an archive per architecture and a `SHA256SUMS` file.

```bash
ARCH=$(uname -m)   # x86_64 or aarch64
BASE=https://github.com/coo-quack/vigilant-heron/releases/latest/download
curl -fsSLO "$BASE/vigilant-heron-$ARCH-unknown-linux-gnu.tar.gz"
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "vigilant-heron-$ARCH-unknown-linux-gnu.tar.gz"
sudo install -m 755 "vigilant-heron-$ARCH-unknown-linux-gnu/vigilant-heron" /usr/local/bin/
vigilant-heron --version
```

Each archive holds the binary, `LICENSE`, `README.md`, the `packaging/` folder with the service files and `install.sh`, and the sample configuration `examples/vigilant-heron.conf`. To install a particular version, replace `latest/download` with `download/v0.1.0`, for example.

## Build from source

Get the code and build a release binary. `--locked` makes the build use the versions in `Cargo.lock`:

```bash
git clone https://github.com/coo-quack/vigilant-heron.git
cd vigilant-heron
cargo build --release --locked
./target/release/vigilant-heron --version
```

To install the binary into `~/.cargo/bin`, so that `vigilant-heron` is on your `PATH`, run this in the clone:

```bash
cargo install --locked --path .
```

## Docker image

The image is published at `ghcr.io/coo-quack/vigilant-heron` for `linux/amd64` and `linux/arm64`. Each version has its own tag, such as `0.1.0`, and `latest` follows the newest version:

```bash
docker pull ghcr.io/coo-quack/vigilant-heron:latest
```

In production, use a version tag such as `:0.1.0`, so the image changes only when you change the tag.

To build the image from a clone instead, run `docker build -t vigilant-heron .`, and use `vigilant-heron` in place of `ghcr.io/coo-quack/vigilant-heron:latest` in the commands below.

The image runs as the `nonroot` user on distroless, and its binary is `/usr/local/bin/vigilant-heron`. The configuration must set two things for the container:

- `listen 0.0.0.0:8080;`, so that the published port reaches the router.
- `pid /tmp/vigilant-heron.pid;`, because the `nonroot` user cannot write to `/run`.

1. **Write a configuration file.** Here is a complete example:

   ```nginx
   listen 0.0.0.0:8080;               # 0.0.0.0 so that the published port reaches the router
   pid /tmp/vigilant-heron.pid;       # the nonroot user cannot write to /run

   decision {
       backend jev;
   }

   site example.com {
       upstream http://app:8080;      # the address of your app, as the container sees it
       mode shadow;
   }
   ```

2. **Check the file.** `-t` runs the check and exits. Pass the key from your shell with `-e TYPESAFE_API_KEY`, so the value does not appear in the command:

   ```bash
   docker run --rm \
     -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
     -e TYPESAFE_API_KEY \
     ghcr.io/coo-quack/vigilant-heron:latest \
     -t -c /etc/vigilant-heron/vigilant-heron.conf
   ```

3. **Run the router.** The container is named `vigilant-heron`, and port 8080 is published on the host:

   ```bash
   docker run -d --name vigilant-heron -p 8080:8080 \
     -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
     -e TYPESAFE_API_KEY \
     ghcr.io/coo-quack/vigilant-heron:latest
   ```

   Without `-c`, the image starts with `/etc/vigilant-heron/vigilant-heron.conf`, so the mount above is all it needs.

### Docker Compose

Save this as `compose.yaml` next to `vigilant-heron.conf`:

```yaml
services:
  vigilant-heron:
    image: ghcr.io/coo-quack/vigilant-heron:latest
    ports:
      - "8080:8080"
    volumes:
      - ./vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro
    environment:
      TYPESAFE_API_KEY: ${TYPESAFE_API_KEY}
    restart: unless-stopped
```

Start it with `TYPESAFE_API_KEY=... docker compose up -d`. Compose reads `${TYPESAFE_API_KEY}` from your shell or from a `.env` file beside `compose.yaml`. Do not commit that `.env` file.

To send a signal to the router in the container, use `docker exec`, as [Command line](/cli#docker) shows.

## Configuration file location and -c and -t

The router reads its configuration from the first of these that is set:

1. The file given with `-c <path>` (or `--config <path>`).
2. The path in the `VIGILANT_HERON_CONFIG` environment variable.
3. `/etc/vigilant-heron/vigilant-heron.conf`.

Check a file before you run it. `-t` validates the file, its includes, its rules, its block pages and its token variables, and then exits:

```console
$ TYPESAFE_API_KEY=... vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
configuration file /etc/vigilant-heron/vigilant-heron.conf test is successful
```

A failed check names the file and line of the error and exits 1. The other options are listed in [Command line](/cli).

## Putting it behind nginx or Cloudflare

vigilant-heron does not terminate TLS. Put nginx or Cloudflare in front of it. The edge sends the real client address in a header, and the router trusts that header only from the edge.

### nginx in front

Forward requests to the router, and keep the `Host` header, which sites are matched on:

```nginx
upstream vigilant_heron {
    server 127.0.0.1:8080;                 # the router's listen address
    keepalive 16;
}

server {
    listen 443 ssl;
    server_name example.com;

    location / {
        proxy_pass http://vigilant_heron;
        proxy_http_version 1.1;            # WebSocket upgrades need HTTP/1.1
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

On the router, name nginx as the only trusted peer, so the client address comes from `X-Real-IP`:

```nginx
real_ip_from 127.0.0.1;                    # trust X-Real-IP only from nginx
real_ip_header X-Real-IP;
real_ip_recursive off;
```

Without `real_ip_from`, the router sees nginx as the client. Then the access list, the limits and the logs all see one address.

### Cloudflare in front

Cloudflare sends the client address in `CF-Connecting-IP`. List the Cloudflare address ranges you trust in `real_ip_from`, one line per range:

```nginx
real_ip_from 173.245.48.0/20;              # one line per Cloudflare range you trust
real_ip_header CF-Connecting-IP;
```

Cloudflare publishes its ranges and changes them now and then. A range that is missing from `real_ip_from` makes requests from it look like they come from Cloudflare.

### WordPress behind nginx

This layout puts the router in the request path of a PHP site, such as WordPress on PHP-FPM. The outer nginx serves static files itself and sends only PHP requests to the router. The router forwards each allowed request to a second nginx server on the same host, and that server runs PHP.

The outer nginx server sends PHP requests to the router with the original URI:

```nginx
server {
    listen 443 ssl;                        # add your TLS certificate and key here
    server_name example.com;
    root /var/www/example;
    index index.php;                       # a request for / is answered by index.php
    client_max_body_size 64m;              # the same limit as the router and the inner server

    # Paths that are never served. This is a minimum, not a full list.
    # Dotfiles are denied, except those under /.well-known/. Scripts there are denied too,
    # so that a script is never served as source.
    location ^~ /.well-known/ {
        location ~* \.(php|phtml)$ {
            deny all;
        }
        try_files $uri =404;
    }

    location ~ /\. {
        deny all;
    }

    # wp-config.php and its backups, such as wp-config.php.bak or wp-config.php~.
    location ~* /wp-config[^/]*$ {
        deny all;
    }

    location ~* \.(log|sql|bak)$ {
        deny all;
    }

    # Many sites do not use XML-RPC, and xmlrpc.php is a common target for password guessing.
    # Remove this block if your site uses XML-RPC clients.
    location = /xmlrpc.php {
        deny all;
    }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        try_files $uri =404;               # a missing script is a 404 here, not a router request
        proxy_pass http://php_router$request_uri;
        proxy_next_upstream error;         # not "error timeout": see the backup server below
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

The upstream goes in the `http` block:

```nginx
upstream php_router {
    server 127.0.0.1:8090;                                # the router
    server 127.0.0.1:8091 backup;                         # the inner server, used while the router is down
    keepalive 16;
}
```

The inner server runs PHP. It is the router's upstream:

```nginx
server {
    listen 127.0.0.1:8091;
    server_name example.com;
    root /var/www/example;
    index index.php;
    client_max_body_size 64m;
    set_real_ip_from 127.0.0.1;            # the router and the outer nginx both connect from here
    real_ip_header X-Real-IP;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param HTTPS on;
        fastcgi_param REQUEST_SCHEME https;
        fastcgi_param SERVER_PORT 443;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }
}
```

The inner server trusts `X-Real-IP` from `127.0.0.1`, so any process on the same host can set the client address that the inner server reports. Keep the inner server on the loopback address, as above.

The router reads its own settings from its configuration file:

```nginx
listen 127.0.0.1:8090;                     # the upstream above names this address
real_ip_from 127.0.0.1;                    # trust X-Real-IP only from the outer nginx
real_ip_header X-Real-IP;
real_ip_recursive off;

decision {
    backend jev;                           # reads TYPESAFE_API_KEY, as in the example above
}

site example.com {
    upstream http://127.0.0.1:8091;        # the inner server
    client_max_body_size 64m;              # the router's default is 1m
    static_extensions;                     # no static skip: see "Missing files" below
}
```

Each part has a reason:

**Why there is an inner server.** PHP-FPM speaks FastCGI, not HTTP, and the router can forward only to an `http://` upstream. The inner nginx server accepts HTTP from the router and passes PHP requests to PHP-FPM over FastCGI.

**HTTPS and the client address.** The outer nginx terminates TLS, so the inner server receives plain HTTP. `HTTPS on` and `SERVER_PORT 443` tell PHP that the visitor used HTTPS. Without them, WordPress can build `http://` links or redirect in a loop. `set_real_ip_from` with `real_ip_header X-Real-IP` makes the inner server take the visitor's address from the header that the outer nginx sets. Without it, WordPress and security plugins see every visitor as `127.0.0.1`.

**Request size.** The router's `client_max_body_size` defaults to `1m`, so an upload above 1 MB gets 413 from the router. Set the same limit on the outer nginx, the router and the inner server. Otherwise the one with the smallest limit refuses the upload first.

**The URI and the index redirect.** `index index.php;` makes nginx answer a request for `/` with `/index.php`. nginx makes this an internal redirect, so the request then matches `location ~ \.php$`. The default index is `index.html`, so without this line a request for `/` would not reach PHP.

**Static files.** A request for a file that exists, such as `/style.css`, matches only `location /`, which has no `proxy_pass`. nginx serves the file itself, so the router never sees it.

**Missing files.** A file that does not exist, such as `/missing.js`, falls back to `/index.php` and reaches the router. The router's static skip would let such a request skip the backend, because it trusts the file extension. Every request that reaches the router here runs PHP, so the router site sets `static_extensions;` with no extension, which turns the static skip off.

**Permalinks.** The fallback `/index.php?$args` lets a path such as `/about/` reach WordPress, which then finds the page. The outer nginx still sends the original URI to the router through `$request_uri`, so the router sees `/about/`, not `/index.php`.

**The backup server.** nginx sends a request to the `backup` server only when it cannot get an answer from the router because of an error: the router cannot be reached, or the connection fails while nginx sends the request or reads the response header. The outer PHP location sets `proxy_next_upstream error;` instead of the default `error timeout`. With the default, a GET that the router does not answer within `proxy_read_timeout` (60 seconds by default) would be sent again to the backup, past the router. With `error`, such a request gets 504 instead, and the router stays in use for the next request, so a slow request cannot be used to get past the router. The trade-off is availability: if the router accepts connections but stops answering, visitors get 504 until you switch back (see below). While a request goes to the backup, the router does not check it, and `fail_closed_path` does not apply. nginx does not send a POST to another server after it was sent to the router, and a 403 or 429 from the router is a response, not an error, so nginx does not retry it.

**Failure settings.** `on_decision_error` and `on_rate_limit` both default to `allow`, so when the backend fails, the router forwards the request. Set `block` to refuse it instead. See [`on_decision_error`](/configuration#on-decision-error) and [`on_rate_limit`](/configuration#on-rate-limit).

**Client address.** This example assumes that nginx faces the visitors directly. If Cloudflare or another proxy is in front of the outer nginx, first set the visitor's address on the outer nginx with the [nginx realip module](https://nginx.org/en/docs/http/ngx_http_realip_module.html): `set_real_ip_from` lists the proxy's addresses, and `real_ip_header` names the header that carries the visitor's address, such as `real_ip_header CF-Connecting-IP;` for Cloudflare. Otherwise `$remote_addr` is the proxy's address, and the router and WordPress see the proxy as the visitor.

**Switching back.** To take the router out of the request path, point the upstream at the inner server only:

```nginx
upstream php_router {
    server 127.0.0.1:8091;
    keepalive 16;
}
```

Then check the file with `nginx -t`, and reload with `nginx -s reload`. The [nginx command-line switches](https://nginx.org/en/docs/switches.html) describe both: `-t` tests the configuration file, and `reload` applies it to the running server. nginx also checks the new configuration before it applies it, and keeps the old one if the check fails.

### Try shadow mode beside a live site with an nginx mirror

To measure the router on real traffic without putting it in the response path, let nginx send it a copy of each request with the [`mirror`](https://nginx.org/en/docs/http/ngx_http_mirror_module.html) module. nginx serves the site as before and discards the router's answers. The router forwards its copy to a sink that answers 204, so a POST does not run twice.

```nginx
# In the site's server block.
mirror /__vh_mirror;
mirror_request_body on;

location = /__vh_mirror {
    internal;
    proxy_pass http://127.0.0.1:8090$request_uri;   # the router; the original URI
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # Remove any header that only the origin may see, such as a secret your CDN adds.
    # proxy_set_header X-Origin-Secret "";
    proxy_connect_timeout 200ms;
    proxy_send_timeout 2s;
    proxy_read_timeout 2s;
    access_log off;
}

# The sink that the router forwards to.
server {
    listen 127.0.0.1:8091;
    access_log off;
    location / { return 204; }
}
```

On the router, the site is in shadow mode, forwards to the sink, and trusts `X-Real-IP` from nginx only:

```nginx
real_ip_from 127.0.0.1;
real_ip_header X-Real-IP;

site example.com {
    upstream http://127.0.0.1:8091;
    mode shadow;
}
```

The short timeouts bound how long nginx waits on a slow or stopped router.

Two things change what the router sees:

- **Requests that nginx answers before the mirror runs are not copied**, such as a `return` in a `location`. The router's counts then cover only the requests nginx passes on.
- **An internal redirect after the mirror has run copies the request again.** The `index` directive is one: nginx turns `/` into `/index.php` and runs the mirror a second time, so every request for `/` is logged and judged twice. Two lines with the same time, client, method and path show it. For PHP, pass `/` to PHP without the redirect:

  ```nginx
  location = / {
      include snippets/fastcgi-php.conf;   # fastcgi_index makes the script /index.php
      fastcgi_pass unix:/run/php/php-fpm.sock;
  }
  ```

The status in the router's log is the sink's 204, not the site's. To stop the trial, remove the `mirror` lines and reload nginx.

## Run as a service with systemd

To run the router as a service, run it in the foreground under systemd, not with `start`. systemd then restarts it when it crashes, reloads it on `systemctl reload`, and stops it gracefully.

The release archive holds a script that sets up the service. Check the archive first, as the Download section shows. Then, as root, extract it into a directory that only root can read or write, and run the script from there:

```bash
sudo install -d -m 700 /root/vh-install
sudo tar -xzf "vigilant-heron-$ARCH-unknown-linux-gnu.tar.gz" -C /root/vh-install
sudo sh /root/vh-install/vigilant-heron-$ARCH-unknown-linux-gnu/packaging/install.sh
```

The script installs these:

- `/usr/local/bin/vigilant-heron`, the binary.
- `/etc/systemd/system/vigilant-heron.service`, the unit shown below.
- `/etc/logrotate.d/vigilant-heron`, the log rotation described below.
- `/etc/vigilant-heron/vigilant-heron.conf`, a copy of `examples/vigilant-heron.conf`, and `/etc/vigilant-heron/env`, a token file with a commented template. Only root can read the token file.
- `/var/log/vigilant-heron`, the directory for the log files.
- The system user and group `vigilant-heron`, when they do not exist.

The script stops before it writes anything when one of the paths it writes is a symbolic link.

The script copies the sample configuration and the token template only when those files are missing. Running it again replaces the binary, the unit and the logrotate file, and keeps the configuration and the token file. After a re-run that replaces the binary, restart the service with `sudo systemctl restart vigilant-heron`, so that it runs the new program.

The script does not start the service. It prints the next steps. Two of them are easy to miss:

- Add `pid /run/vigilant-heron/vigilant-heron.pid;` to the configuration. The unit creates `/run/vigilant-heron`, and the router writes its pid file there.
- Add `access_log /var/log/vigilant-heron/access.json json;` to the configuration. The guide's tools, `shadow-report` and `suggest-skip-rules`, read the json format, and only that format has `user_agent` and `request_id`.

The unit that the script installs is shown here, and the repository has the same file at `packaging/systemd/vigilant-heron.service`:

```ini
[Unit]
Description=vigilant-heron router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vigilant-heron
# Creates /run/vigilant-heron, the directory of the pid file that the configuration names.
RuntimeDirectory=vigilant-heron
# KEY=value lines with the API tokens. systemd reads this file as root, so only root can read it.
EnvironmentFile=/etc/vigilant-heron/env
ExecStart=/usr/local/bin/vigilant-heron -c /etc/vigilant-heron/vigilant-heron.conf
ExecReload=/usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
# SIGTERM already stops the router gracefully; this makes it explicit.
KillSignal=SIGTERM
Restart=on-failure
# Hardening. The router writes only to its runtime directory and its log directory.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log/vigilant-heron
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
UMask=0027

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vigilant-heron
sudo systemctl reload vigilant-heron    # after a configuration change
systemctl status vigilant-heron
```

A reload keeps connections open. Use `sudo systemctl restart vigilant-heron` only for a setting that is read at startup, or after you install a new binary. Check the file before you reload with `vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf`.

The unit runs the router with systemd's hardening options, so it can write only to its runtime directory and to `/var/log/vigilant-heron`.

The logrotate file rotates each `/var/log/vigilant-heron/*.log` file daily, as the `vigilant-heron` user, and keeps 14 rotated files. After each rotation it sends SIGUSR1, so the router opens its log files again.

## Updating

- **Release binary:** download the new archive as in [Download a release binary](#download-a-release-binary), check the configuration with the new binary before you install it (`./vigilant-heron-$ARCH-unknown-linux-gnu/vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf`), install it, then restart the router; a reload does not load a new program.

- **From source:** pull the new code, build it, and check the configuration:

  ```bash
  git pull
  cargo build --release --locked
  ./target/release/vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
  ```

  Restart the router after you update the binary. A reload reads the configuration again, but it does not load a new program. Settings such as `listen` and `worker_threads` also take effect only at startup, as [Configuration](/configuration#reload-and-log-reopen) lists.

- **Docker:** pull the new image, and replace the container:

  ```bash
  docker pull ghcr.io/coo-quack/vigilant-heron:latest
  docker rm -f vigilant-heron
  docker run -d --name vigilant-heron -p 8080:8080 \
    -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
    -e TYPESAFE_API_KEY \
    ghcr.io/coo-quack/vigilant-heron:latest
  ```

Read the [Changelog](/changelog) before you update.

## Uninstall

- **Installed with `cargo install`:** run `cargo uninstall vigilant-heron`.
- **Release binary:** delete `/usr/local/bin/vigilant-heron`.
- **Built from source:** delete the clone and the binary you copied.
- **Docker:** remove the container and the image:

  ```bash
  docker rm -f vigilant-heron
  docker image rm ghcr.io/coo-quack/vigilant-heron:latest
  ```

- **systemd:** run `sudo systemctl disable --now vigilant-heron`, then delete `/etc/systemd/system/vigilant-heron.service` and `/etc/logrotate.d/vigilant-heron`. Delete `/etc/vigilant-heron` and `/var/log/vigilant-heron` only when you no longer need the configuration and the logs. Then remove the user and the group with `sudo userdel vigilant-heron` and `sudo groupdel vigilant-heron`.

Apart from the files that `install.sh` copies and the system user and group it creates, the router installs nothing on the system. The pid file is removed when the router exits. If the router stopped without removing it, delete the file named by your `pid` directive. Your configuration file and logs stay where you put them.
