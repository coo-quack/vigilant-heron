# Getting Started

This page takes you from nothing to a blocked request in about ten minutes. You will write one small configuration file, check it, run the router, and send it a test attack.

::: warning Status
vigilant-heron is in early development. Run every new site in shadow mode first, and read the log before you enforce anything.
:::

## 1. Install

Install the router with the [Docker image or a binary you build](/install). The steps below assume the `vigilant-heron` command is on your `PATH`. With Docker, run the same commands inside the container, as the [Installation](/install#docker-image) page shows.

## 2. Write a minimal configuration

Save this as `vigilant-heron.conf`. It listens on port 8080 and forwards requests for `example.com` to an app on port 3000.

```nginx
listen 127.0.0.1:8080;              # the address the router listens on
pid /tmp/vigilant-heron.pid;        # where the router writes its process id

decision {
    backend jev;                    # the decision model; it reads its key from TYPESAFE_API_KEY
}

site example.com {
    upstream http://127.0.0.1:3000; # where allowed requests go
    mode shadow;                    # record decisions, block nothing
}
```

- `upstream` is your application. It can be any HTTP server, and it does not need to run yet.
- `mode shadow` means the router forwards every request and only records what it would have blocked.

## 3. Check the file

`-t` reads the file, validates it, and exits. It does not start the server.

```console
$ TYPESAFE_API_KEY=... vigilant-heron -t -c vigilant-heron.conf
configuration file vigilant-heron.conf test is successful
```

A mistake prints the file and line, for example `vigilant-heron.conf:6: unknown directive "upstrem"`, and exits 1. Fix the line and run the check again.

## 4. Run the router

```bash
TYPESAFE_API_KEY=... vigilant-heron -c vigilant-heron.conf
```

The router keeps running in the foreground. Leave it in its own terminal. It prints one JSON line for each request.

## 5. Send a test attack

In a second terminal, send a request whose query string contains a SQL injection:

```bash
curl -i "http://127.0.0.1:8080/?id=1%20UNION%20SELECT%20password%20FROM%20users" \
  -H "Host: example.com"
```

Shadow mode forwards this request, so you see whatever the upstream returns. If nothing listens on port 3000, you get `502 Bad Gateway`. That is expected, and the log line still records the decision.

Look at the router's terminal. The log line for the request contains these fields, among others:

```json
{"status":"502","action":"allow","reason":"rule","rule_id":"vh-sqli-001","would_have":"block",...}
```

- `rule_id` is the built-in rule that matched. `vh-sqli-001` matches `UNION SELECT` in a query string.
- `would_have` is `block`. In enforce mode, the router would have answered with 403.
- `action` is `allow`, because shadow mode forwarded the request.

## 6. Switch to enforce mode

When the shadow log shows the blocks you expect, change `mode shadow;` to `mode enforce;` in the file. Then reload the configuration with the `-s` command. This sends the router a signal, so it reads the file again without a restart:

```bash
vigilant-heron -s reload -c vigilant-heron.conf
```

Send the test attack again:

```bash
curl -i "http://127.0.0.1:8080/?id=1%20UNION%20SELECT%20password%20FROM%20users" \
  -H "Host: example.com"
```

The response is now `403 Forbidden`, and the upstream never sees the request.

## Next steps

- [Installation](/install) covers Docker Compose, nginx and Cloudflare in front, and updates.
- [Command line](/cli) lists every option, including `-T` and the signal words for `-s`.
- [How it works](/how-it-works) explains the order in which the router judges a request.
- [Configuration](/configuration) lists every directive with its default.
- [Decision backends](/decision-backends) covers the choice of model and the thresholds.
- [Troubleshooting](/troubleshooting) helps when a request is blocked, or when the router does not start.
