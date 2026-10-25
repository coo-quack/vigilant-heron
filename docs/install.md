# Installation

You can run vigilant-heron from its Docker image or from a binary you build yourself. The Docker image is the quickest way to start. Both need the same configuration file.

## Requirements

- **Operating system:** Linux or macOS. The `-s` signal command needs a Unix system.
- **Docker** (for the image), or the Rust toolchain (for a build). The toolchain version is pinned in `rust-toolchain.toml` as 1.99.1. `rustup` installs it on the first `cargo` call.
- **An API key** for the decision model. The default model, Jev, reads its key from the `TYPESAFE_API_KEY` environment variable. The router refuses to start when that variable is unset or blank. See [Decision backends](/decision-backends) for other models.
- **Outbound HTTPS** from the router to the model's API (`api.typesafe.ai` by default).
- **Network access** from the router to each `upstream` address.

The repository is private, so the image and the source are visible only to members of the organization. Log in to `ghcr.io` with an account that can read the repository before you pull the image.

## Docker image

The image is published as `ghcr.io/coo-quack/vigilant-heron:<version>` for `linux/amd64` and `linux/arm64`. Replace `<version>` with a release number from the [GitHub Releases](https://github.com/coo-quack/vigilant-heron/releases) page.

1. **Write a configuration file.** Inside the container, the router must listen on `0.0.0.0`, and it must write its pid file to `/tmp`, because the image runs as `nonroot` and cannot write to `/run`:

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
     ghcr.io/coo-quack/vigilant-heron:<version> \
     -t -c /etc/vigilant-heron/vigilant-heron.conf
   ```

3. **Run the router.** The container is named `vigilant-heron`, and port 8080 is published on the host:

   ```bash
   docker run -d --name vigilant-heron -p 8080:8080 \
     -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
     -e TYPESAFE_API_KEY \
     ghcr.io/coo-quack/vigilant-heron:<version>
   ```

   Without `-c`, the image starts with `/etc/vigilant-heron/vigilant-heron.conf`, so the mount above is all it needs.

### Docker Compose

Save this as `compose.yaml` next to `vigilant-heron.conf`:

```yaml
services:
  vigilant-heron:
    image: ghcr.io/coo-quack/vigilant-heron:<version>
    ports:
      - "8080:8080"
    volumes:
      - ./vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro
    environment:
      TYPESAFE_API_KEY: ${TYPESAFE_API_KEY}
    restart: unless-stopped
```

Start it with `TYPESAFE_API_KEY=... docker compose up -d`. Compose reads `${TYPESAFE_API_KEY}` from your shell or from a `.env` file beside `compose.yaml`. Do not commit that `.env` file.

### Build the image yourself

```bash
docker build --target runtime -t vigilant-heron .
```

## Build from source

```bash
git clone https://github.com/coo-quack/vigilant-heron.git
cd vigilant-heron
cargo build --release --locked
./target/release/vigilant-heron --version
```

`--locked` makes the build use the versions in `Cargo.lock`. The binary is `target/release/vigilant-heron`. Copy it to a directory on your `PATH`, such as `/usr/local/bin`.

To install the binary into `~/.cargo/bin` without cloning first:

```bash
cargo install --git https://github.com/coo-quack/vigilant-heron --locked
```

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

## Updating

- **Docker:** check the new version's configuration with `-t` first, using the same `docker run --rm ... -t` command as above. Then replace the container:

  ```bash
  docker pull ghcr.io/coo-quack/vigilant-heron:<new-version>
  docker rm -f vigilant-heron
  docker run -d --name vigilant-heron -p 8080:8080 \
    -v "$PWD/vigilant-heron.conf:/etc/vigilant-heron/vigilant-heron.conf:ro" \
    -e TYPESAFE_API_KEY \
    ghcr.io/coo-quack/vigilant-heron:<new-version>
  ```

- **From source:** pull the new code, build it, and check the configuration:

  ```bash
  git pull
  cargo build --release --locked
  ./target/release/vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
  ```

Read the [Changelog](/changelog) before you update. A reload (`-s reload`) reads the configuration again, but it does not load a new binary. Restart the router after you update the binary. Settings such as `listen` and `worker_threads` take effect only at startup, as [Configuration](/configuration#reload-and-log-reopen) lists.

To update a `cargo install` copy, run the same command with `--force`:

```bash
cargo install --git https://github.com/coo-quack/vigilant-heron --locked --force
```

## Uninstall

- **Docker:**

  ```bash
  docker rm -f vigilant-heron
  docker image rm ghcr.io/coo-quack/vigilant-heron:<version>
  ```

- **From source:** delete the clone and the binary you copied. For a `cargo install` copy, run `cargo uninstall vigilant-heron`.

The router installs nothing else on the system. The pid file is removed when the router exits. If the router stopped without removing it, delete the file named by your `pid` directive. Your configuration file and logs stay where you put them.
