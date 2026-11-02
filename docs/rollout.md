# From shadow mode to enforce

This guide takes a site from a first install to blocking real traffic. It has seven phases, and each ends with a checklist. Move on only when every item is true.

Run each site in `mode shadow;` until the log shows what the router would block, then change to `mode enforce;`. In shadow mode the router forwards a request whatever its verdict. A few refusals, such as an invalid `Host`, apply in both modes. See [How it works](/how-it-works#shadow-mode).

## 1. Before you start

On a Linux server, install the release with the packaged `install.sh`. It also installs the systemd unit and the logrotate file, and it sets the log directory's permissions that phase 3 checks. [Run as a service with systemd](/install#run-as-a-service-with-systemd) describes the script's steps.

### What the site serves and who uses it

1. List what the site serves: static files (images, CSS, JavaScript), scripts, forms and uploads.
2. List the legitimate clients: visitors, the owner and admins, webhooks and partner services, crawlers, and the site itself when it calls its own public URL. The site's own calls show the server's public address in the log. Make sure no limit or deny rule on that address stops them.

### What sits in front and how the client address arrives

3. Note what runs in front of the router: a CDN (a content delivery network, a service that stands in front of your site), nginx, or both.
4. Set `real_ip_from` to every proxy in front of the router, and `real_ip_header` to the header it sends. See [Installation](/install#putting-it-behind-nginx-or-cloudflare). The router believes the header only from a listed peer, so a client cannot choose its address by sending it.

### Which backend, and how fast it answers

5. Choose a decision backend. This is the model that judges each request. [Decision backends](/decision-backends) lists the choices.
6. Measure the backend's latency from the server that will run the router, not from your workstation. The p99 is the time that 99 in 100 answers beat. Two figures from one rollout, both measured from the router's server: one backend had a median of about 130 ms and a maximum under 200 ms, and the other had a p99 of about 1.8 s. With a p99 of 1.8 s, at least 1 request in 100 takes longer than the 1000 ms `timeout` in step 7, so those requests fall back to `on_decision_error`.
7. Set `timeout` from your measurements. The default is 2000 ms; [`timeout`](/configuration#timeout) describes it. Every judged request waits for the backend, up to `timeout`, even when the answer is slow:

   ```nginx
   decision {
       backend jev;
       timeout 1000ms;
   }
   ```

8. Know what a failed decision does. If no answer arrives in time, the default `on_decision_error allow` forwards the request without a verdict.

### What it costs

9. Estimate the input tokens per call. In one rollout an ordinary request was about 1,000. Replace the estimate with `input_tokens` from your log.
10. Count the calls per day: the requests that reach the backend after the skip rules and the static skip. The static skip is the router's shortcut for a plain `GET` or `HEAD` of a static file, such as a `.css` or `.png`, which is forwarded without asking the backend. Multiply the calls by the tokens per call, then by your provider's price per input token. For example, 20,000 calls at about 1,000 tokens each is 20 million input tokens a day.

### How good the backend is on your traffic

11. Run the labelled evaluation with your backend, as [Evaluation](/evaluation) describes. When the shadow log shows a request near the threshold, add it as a row. The format is in [`eval/README.md`](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/README.md).

Until `TYPESAFE_API_KEY` is set, `-t` and `test-request --url` still pass. They print a warning and carry on, but the router does not start without the key. [Check a URL with test-request](/cli#check-a-url-with-test-request) shows the output.

**Before you move on:**

- [ ] The site's files, scripts, uploads and legitimate clients are written down.
- [ ] `real_ip_from` names every proxy in front of the router.
- [ ] Latency was measured from the router's server, and `timeout` is set from it.
- [ ] The cost per day is estimated, and the labelled evaluation was run.

## 2. Shadow beside the site

Nginx copies each request to the router with its `mirror` module, and the router's answer is discarded. The [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror) page gives the nginx mirror and the sink, a local server that answers 204 so each copy ends there. Set those up and reload nginx. Then configure the router to listen on the mirror's target and send the site to the sink in shadow mode. Keep the `decision` block from phase 1:

```nginx
listen 127.0.0.1:8090;                  # the mirror in nginx sends its copies here
real_ip_from 127.0.0.1;                 # trust X-Real-IP only from nginx
real_ip_header X-Real-IP;

site example.com {
    upstream http://127.0.0.1:8091;     # the sink
    mode shadow;
}
```

Reload the router, and send one ordinary request. Its line should appear in the router's access log.

The mirror does not change responses. But when it copies bodies (`mirror_request_body on`, the default), nginx reads the whole request body before it passes the request on, which can delay large uploads.

Three more things change what the router sees:

- **Requests that nginx answers itself may not be copied.** In one trial, a `return`, a 403 from a `deny` rule and nginx's own 404 for missing files did not reach the router. Compare the nginx log with the router's log to see what the router does not see on your setup.
- **An internal redirect, which nginx handles again under another path, copies the request again.** The `index` directive is one: `/` becomes `/index.php`, and the mirror runs twice. Two log lines with the same time, client, method and path show it. The fix for PHP is in [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).
- **A secret header that the CDN adds is copied too.** The router drops a header whose name looks like a credential, such as `x-csrf-token` or `x-functions-key`, before it calls the backend. Strip any other secret header in the mirror block.

Watch the trial for several days, including the owner's admin work, scheduled jobs, backups and crawler peaks. Schedule the stop with a systemd timer or a similar scheduler. It removes the mirror lines and the sink, then reloads nginx.

**Before you move on:**

- [ ] The router's log shows requests from the site, with no double lines on `/`.
- [ ] A secret header that the CDN adds is dropped by name or stripped in nginx.
- [ ] The trial covers several days, and the stop is scheduled.

## 3. Reading the shadow log

Each request gets one JSON line, and every value is a string. A `would_have` block therefore appears as `"would_have":"block"`, with no space after the colon. [Logging](/logging#the-built-in-formats) describes the fields.

`shadow-report` gives most of these figures in one plain-text summary. Run it on the rotated log and the current log together, as [Summarize a shadow log](/cli#summarize-a-shadow-log) describes:

```console
$ vigilant-heron shadow-report /var/log/vigilant-heron/access.json.1 /var/log/vigilant-heron/access.json
```

The report prints paths from the log, which can carry tokens, so read it before you paste any part of it.

Look at these things:

1. **Counts by `reason` and `decision_error`.** A large count in one reason shows where most traffic goes.
2. **Every `would_have=block` line.** Find them with `grep -c '"would_have":"block"' access.json`, then read the last few lines with `tail`. The report lists only the first 50 blocked or redirected lines, in log order.
3. **Decision errors per hour.** Timeouts in an hour with little load point to the provider, not to the site.
4. **`client_busy` bursts per minute and per client.** `client_busy` is the router's refusal when one client already has its share of backend calls in flight. One browser that loads many assets at once can cause it. Phases 4 and 5 show the fixes.
5. **The p99 of `latency_ms`**, compared with your `timeout`.
6. **`input_tokens`**, to replace the estimate from phase 1.

Tell your own traffic from attacks by what the requests do, not by IP address. Your browsers send recognizable User-Agent values, and an admin workflow has a recognizable order: a login, an edit, then an upload. IP addresses change, and a cloud provider's address shows no partner, since anyone can rent one. The built-in `json` format has a `user_agent` key, so the JSON log shows the User-Agent beside each request. Keep that log, because `suggest-skip-rules` reads the JSON format.

By default the log keeps only `query_shape`, such as `id=<num>&s=<text>`, never the values. The `$path` field is different: the router logs the path as the client sent it, so a token in a path, such as a password-reset link, appears in the log. Keep the logs private. The log directory should be `750` and owned by the router's user and the `adm` group, and the files `640`, as the `packaging/` install script and logrotate file set them:

```console
$ sudo install -d -m 750 -o vigilant-heron -g adm /var/log/vigilant-heron
$ ls -ld /var/log/vigilant-heron    # expect drwxr-x---
$ ls -l /var/log/vigilant-heron     # expect -rw-r----- for each log file
```

To review a block, find the web server's own log line for the same second, client and path. To see what a blocked request carried, add `$block_query` to a `log_format` of your own. The value is redacted like the event sent to the backend, but a query can still carry personal data, so the built-in formats leave it out; [`$block_query`](/logging#block-query) has an example.

**Before you move on:**

- [ ] The counts by `reason` and `decision_error` are reviewed, and each `would_have=block` line has been read.
- [ ] `client_busy` bursts and decision errors per hour are explained.
- [ ] The p99 of `latency_ms` and the `input_tokens` are recorded.
- [ ] The log directory is `750`, and its files are `640`.

## 4. Writing skip rules

A skip rule forwards a request without calling the backend. Write each one narrow:

1. Limit the method to `GET` and `HEAD`.
2. Match one exact path.
3. Make the query regex allow only the shape you expect, such as digits or a handle name.
4. Never skip a `POST` that carries credentials.

```nginx
rule skip-product-page {
    description "product page with a numeric id";
    action skip;
    site example.com;
    method GET HEAD;
    path = /products;
    query ~ "^id=[0-9]+$";
}
```

The `site` line limits the rule to `example.com`. A rule without a `site` line applies to every site, so add one unless you mean that.

For a WordPress site, start from [`examples/rules.d/wordpress.conf`](https://github.com/coo-quack/vigilant-heron/blob/develop/examples/rules.d/wordpress.conf), whose [four rules](/rules#wordpress-rules) apply to every site until you add a `site` line to each. Copy the file, narrow each rule to the request shapes your site sends, and test each one as below.

Put the rule in a file under `rules.d/`, include that file, and check the configuration with `vigilant-heron -t`. It reports the file and line of any error. `-t` and [`test-request`](/cli#check-a-request-with-test-request), which reports what the router would do with a saved request, print a warning when `TYPESAFE_API_KEY` is not set, and do not fail. The router itself does not start without the variable, so set it before you start the router. See [Rules](/rules#write-your-own-rule).

Keep these facts in mind. A skip rule never overrides a block rule, because the built-in block rules run first. A skipped request is not seen by the model at all, headers and cookies included.

Test each rule before you reload. Run `test-request` on a request the rule must skip, and check that its `rules:` line reads `matched (skip)` with the rule's description. Then run it on near misses: a quote in the value, a `<script>` tag, an extra parameter, an encoded newline, a `POST`, and a longer path. A near miss that reports `matched (skip)` means the rule is too wide. In the access log, the same decision appears as `reason` `skip_rule`.

```console
$ vigilant-heron -c /etc/vigilant-heron/vigilant-heron.conf test-request near-miss-extra.http
```

To test a URL without writing a file, use `test-request --url`, as [Check a URL with test-request](/cli#check-a-url-with-test-request) shows.

`suggest-skip-rules` lists candidates from the JSON log. Its thresholds are strict, so on a small site it may print nothing. It changes no file, so review each candidate before you copy it. See [Learn skip rules from the access log](/cli#learn-skip-rules-from-the-access-log).

Cache-busting queries on static files, such as `?ver=1.2.3`, need `static_query_params`:

```nginx
site example.com {
    upstream http://127.0.0.1:8081;
    static_query_params ver;
}
```

The better fix is to let the web server serve static files, as phase 5 shows.

**Before you move on:**

- [ ] Each rule has a method, an exact path and a narrow query regex, and no skip rule matches a credential-carrying `POST`.
- [ ] `test-request` was run on the matching request and on each near miss.
- [ ] Each `suggest-skip-rules` candidate was reviewed, and the file passes `vigilant-heron -t`.

## 5. Putting the router in the request path

In this phase the site's scripts go through the router, and visitors receive its answers. Each step keeps a way back in place before it changes live traffic.

1. **Set up the inner server and check it directly.** The inner server is a second, local server block. It runs the scripts from the same root as the public site, and it takes the client address from `X-Real-IP`, which the outer nginx sends and the router forwards unchanged. Other processes on the same host can reach `127.0.0.1:8081` without the router, so keep it on the loopback address:

   ```nginx
   # inner server: runs the scripts, reached through the router or the fallback
   server {
       listen 127.0.0.1:8081;
       root /var/www/example.com;
       index index.php;
       set_real_ip_from 127.0.0.1;      # the outer nginx is local
       real_ip_header X-Real-IP;

       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           fastcgi_param HTTPS on;      # the visitor used HTTPS
           fastcgi_pass unix:/run/php/php-fpm.sock;   # your PHP-FPM setup
       }
       location / { try_files $uri $uri/ /index.php?$args; }
   }
   ```

   Send a request straight to it: `curl -i -H 'Host: example.com' http://127.0.0.1:8081/index.php`. A script must answer before you go on.

2. **Prepare the switch back, and test it once.** Keep the two upstream blocks in separate files. Nginx includes whichever one the symlink `upstream.conf` points to, so only one is active, and the name `vigilant_heron` is never defined twice:

   ```nginx
   # /etc/nginx/vh/direct.conf: the switch back, with no router
   upstream vigilant_heron {
       server 127.0.0.1:8081;
   }
   ```

   ```nginx
   # /etc/nginx/vh/router.conf: the router, with the inner server as the fallback
   upstream vigilant_heron {
       server 127.0.0.1:8080;
       server 127.0.0.1:8081 backup;
   }
   ```

   In the `http` block, add `include /etc/nginx/vh/upstream.conf;`. Then add the outer server block. It serves static files itself, sends scripts to the router, and takes the visitor's address from the CDN header if a CDN is in front. It uses WordPress-style permalinks: a missing file falls back to `/index.php`, so a pretty URL such as `/2026/11/post-name/` runs as a script. For a site with plain files and no fallback, use `try_files $uri $uri/ =404;`.

   ```nginx
   server {
       listen 443 ssl;
       server_name example.com;
       root /var/www/example.com;
       index index.php;
       ssl_certificate /etc/ssl/example.com/fullchain.pem;     # or your existing TLS lines
       ssl_certificate_key /etc/ssl/example.com/privkey.pem;

       # Behind a CDN only: the visitor's address comes from the CDN header, from the CDN's ranges only.
       # Without this, every visitor looks like the CDN, and client_busy refuses them all.
       set_real_ip_from 173.245.48.0/20;   # one line per CDN range; use the CDN's published list
       real_ip_header CF-Connecting-IP;    # or your CDN's header

       location ~ /\.(?!well-known) { deny all; }   # hidden files, before the other locations

       location ~ \.php$ {                 # scripts go through the router
           try_files $uri =404;            # a missing script is a 404 here, not a model call
           proxy_pass http://vigilant_heron$request_uri;   # the original URI, also after the permalink fallback
           proxy_next_upstream error;      # not "error timeout", see step 4
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-Proto https;
       }

       location / {                        # static files, and permalinks that fall back to a script
           try_files $uri $uri/ /index.php?$args;
       }
   }
   ```

   Point the symlink at the switch back, reload nginx, and check that the site answers. Traffic now goes straight to the inner server:

   ```console
   $ sudo ln -sfn /etc/nginx/vh/direct.conf /etc/nginx/vh/upstream.conf && sudo nginx -t && sudo nginx -s reload
   ```

3. **Put the router in the path, in shadow mode.** First remove the mirror lines and the sink from phase 2, and cancel the stop timer. Otherwise each request is judged twice, and the timer would stop the router that is now in the path. Then point the symlink at the router:

   ```console
   $ sudo ln -sfn /etc/nginx/vh/router.conf /etc/nginx/vh/upstream.conf && sudo nginx -t && sudo nginx -s reload
   ```

   The router trusts the address nginx sends, and forwards the site to the inner server. Keep the decision block from phase 1:

   ```nginx
   # the router's configuration
   listen 127.0.0.1:8080;
   real_ip_from 127.0.0.1;             # trust X-Real-IP only from the outer nginx
   real_ip_header X-Real-IP;
   client_max_body_size 1m;            # the same as nginx's limit; phase 6 raises both

   site example.com {
       upstream http://127.0.0.1:8081; # the inner server
       mode shadow;
       static_extensions;              # only for permalink sites: see below
   }
   ```

   Reload the router. Check that a page and a login load, and that each has a line in the router's log. Compare `latency_ms` with nginx's request time to measure the latency the router adds.

   On a permalink site, a missing `/x.css` falls back to `/index.php` and reaches the router as a script request. The static skip, the router's shortcut from phase 1, would forward it without a verdict. An empty `static_extensions;` turns the static skip off, so keep that line on such a site.

4. **Stop the router, and check the fallback.** Stop the router with `sudo systemctl stop vigilant-heron`, or, for a background router, `vigilant-heron stop -c /etc/vigilant-heron/vigilant-heron.conf`. Send a request to the site, and expect the page from the inner server. Then start the router again.

   While requests go to the backup, nothing is judged. The router never sees them, so its rules, limits and `fail_closed_path` (a path prefix that is blocked whenever the decision fails) do not apply. With `proxy_next_upstream error;`, a router that accepts connections but does not answer gives 504 instead of being bypassed. The nginx default, `error timeout`, would send a slow request past the router. When the router is up but not answering, the switch back is the way out.

**Before you move on:**

- [ ] The inner server answers a script directly, and the switch back was tested once.
- [ ] Behind a CDN, nginx takes the visitor's address from the CDN header.
- [ ] The router ran in shadow mode in the path, and you measured the latency it adds.
- [ ] With the router stopped, the site still answers through the inner server.

## 6. Switching to enforce

The way back is rehearsed before enforce, while the router is still in shadow mode.

1. **Raise the upload limit in both places, then test uploads.** Choose the largest upload the site must accept, for example `10m`. Set `client_max_body_size` to that in nginx's server block and in the router's configuration, and reload both. A file within the limit must upload, and a file over it must get 413.
2. **Rehearse the way back.** Point the symlink at `direct.conf`, reload nginx, and check that the site answers. The router's log gets no new line for that request, because the router is out of the path. Then point the symlink back at `router.conf`, reload, and check that the site answers and that the router's log has a new line:

   ```console
   $ sudo ln -sfn /etc/nginx/vh/direct.conf /etc/nginx/vh/upstream.conf && sudo nginx -t && sudo nginx -s reload
   $ sudo ln -sfn /etc/nginx/vh/router.conf /etc/nginx/vh/upstream.conf && sudo nginx -t && sudo nginx -s reload
   ```

3. **Switch to enforce.** Only after step 2 passes, change `mode shadow;` to `mode enforce;`, check the file, and reload. Before the reload, `test-request --url` reports what the router would do with a known attack, without calling the backend; [Check a URL with test-request](/cli#check-a-url-with-test-request) shows the report. A reload applies the new file to new requests, and requests already in flight finish with the configuration they started with:

   ```console
   $ vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
   $ vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
   ```

   With the systemd unit from [Installation](/install#run-as-a-service-with-systemd), run `sudo systemctl reload vigilant-heron` instead.

4. **Check right after the reload.** Send a known attack, such as a query with `UNION SELECT`. The answer should be `403 Forbidden`:

   ```console
   $ curl -i "https://example.com/?id=1%20UNION%20SELECT%20password%20FROM%20users"
   ```

   Have the owner log in, save a post, upload a file within the limit, and use the admin screens. Check the log for any block or 429 from these actions. A 429 is the `client_busy` refusal, which `on_client_busy` sends by default. A visitor who reports a block can quote its request id: the blocked response carries it in an `X-Request-ID` header, and the JSON log has it as `request_id`. To log an id that a proxy already sets, name that header in [`request_id_header`](/configuration#request-id-header).

5. **Know the two ways back after enforce.** Set `mode shadow;` and reload, which keeps the router in the path and recording. Or point the symlink at `direct.conf` and reload nginx, which takes the router out of the path.

6. **Review regularly.** Look at every block and 429, at allowed requests whose `attack` score was close to `block_threshold` (the score at which the router blocks, 0.87 by default), at decision errors per hour, and at the cost per day. Change a rule only after `test-request` has checked it.

**Before you move on:**

- [ ] Uploads within the limit work, and a file over it gets 413.
- [ ] The way back was rehearsed in shadow mode, and the log confirmed it.
- [ ] The `403` test attack was seen, and the owner's actions gave no unexpected block or 429.
- [ ] The review schedule is set.

## 7. Principles for running it safely

- **Layers.** Put a CDN or an edge web application firewall (WAF, a filter of attack patterns) first, then the web server's deny rules, the router's rules and the model. The model only adds blocks, and no model answer can turn a rule block into an allow.
- **What the backend receives.** The router removes credential headers, redacts sensitive fields, and sends only the first `inspect_body` bytes of a body. A file upload's content is replaced by `[REDACTED]` by default (`redact_file_parts`), so the metadata in a photo, such as its location, is not sent; the part's headers, including the file name and content type, still are. A personal field that is not sensitive by name, such as a location typed into a form, must be listed in `redact_field` in the `decision` block, for example `redact_field gps_position;`.
- **Defaults that favor availability.** A failed decision forwards the request, and a client over its share is refused, as phase 1 explains. For the few paths where a missed attack costs more than a refused visitor, such as a login page, set `fail_closed_path`. A request on those paths is blocked whenever the decision fails:

  ```nginx
  site example.com {
      upstream http://127.0.0.1:8081;
      fail_closed_path /login /admin;
  }
  ```

  Forwarding failed decisions means that an attacker who makes the backend unavailable can get requests past the model. Limit each client too, with `limit_req` (a limit on how fast a client may send requests) and `limit_conn` (a limit on how many requests a client may have open at once). See [Security](/security#failure-behavior).
- **Configuration under version control.** Keep the router's configuration in the same version control as the server setup. Pin the release binary, and check it against `SHA256SUMS` before you install it, as [Installation](/install#download-a-release-binary) shows.

**Before you move on:**

- [ ] The layers are in place, and the model is only one of them.
- [ ] Fields that carry personal data are listed in `redact_field`, and an upload was checked against the log.
- [ ] `fail_closed_path` covers the login and admin paths, and `limit_req` and `limit_conn` limit each client.
- [ ] The configuration and the pinned binary are under version control.
