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

Each archive holds the binary, `LICENSE` and `README.md`. To install a particular version, replace `latest/download` with `download/v0.1.0`, for example.

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

## Run as a service with systemd

To run the router as a service, run it in the foreground under systemd, not with `start`. systemd then restarts it when it crashes, reloads it on `systemctl reload`, and stops it gracefully. This unit assumes a system user `vigilant-heron`, a binary in `/usr/local/bin`, and the configuration in `/etc/vigilant-heron`. The configuration must set the pid file in the runtime directory:

```nginx
pid /run/vigilant-heron/vigilant-heron.pid;
```


```ini
# /etc/systemd/system/vigilant-heron.service
[Unit]
Description=vigilant-heron router
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vigilant-heron
# systemd creates /run/vigilant-heron and gives it to the service user.
# The configuration names a pid file in that directory: pid /run/vigilant-heron/vigilant-heron.pid;
RuntimeDirectory=vigilant-heron
# A file of KEY=value lines, readable only by root and the service: TYPESAFE_API_KEY=...
EnvironmentFile=/etc/vigilant-heron/env
ExecStart=/usr/local/bin/vigilant-heron -c /etc/vigilant-heron/vigilant-heron.conf
ExecReload=/usr/local/bin/vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
# SIGTERM already stops the router gracefully; this makes it explicit.
KillSignal=SIGTERM
Restart=on-failure

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

- **systemd:** run `sudo systemctl disable --now vigilant-heron`, then delete the unit file.

The router installs nothing else on the system. The pid file is removed when the router exits. If the router stopped without removing it, delete the file named by your `pid` directive. Your configuration file and logs stay where you put them.
