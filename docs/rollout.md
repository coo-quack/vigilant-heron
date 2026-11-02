# From shadow mode to enforce

This guide takes a site from a first install to blocking real traffic. It has seven phases. Each phase ends with a checklist, and you move on only when every item on it is true.

Run each site in `mode shadow;` until the log shows what the router would block, and change to `mode enforce;` only after that. In shadow mode the router forwards a request whatever its verdict. A few refusals, such as an invalid `Host`, apply in both modes. See [How it works](/how-it-works#shadow-mode).

## 1. Before you start

Answer these questions before you change any setting.

### What the site serves and who uses it

1. List what the site serves: static files (images, CSS, JavaScript), scripts that run on the server, and forms and uploads.
2. List the clients that are legitimate:
   - visitors;
   - the owner and admins, who log in, edit and upload;
   - webhooks and partner services that call the site;
   - the site itself, when it calls its own public URL;
   - crawlers.

   The site's own calls to its public URL show the server's public address in the log. Count them as legitimate, and check that no limit or deny rule on that address stops them.

### What sits in front and how the client address arrives

3. Note what runs in front of the router: a CDN, nginx, or both.
4. Set `real_ip_from` to the addresses of every proxy in front of the router, and `real_ip_header` to the header that they send. See [Installation](/install#putting-it-behind-nginx-or-cloudflare). The router believes the header only from a listed peer, so a client that is not a trusted proxy cannot choose its own address by sending the header.

### Which backend, and how fast it answers

5. Choose a decision backend. This is the model that judges each request, and [Decision backends](/decision-backends) lists the choices.
6. Measure the backend's latency from the server that will run the router, not from your workstation. The p99 is the time that 99 in 100 answers beat; the slowest 1 in 100 take longer. In one rollout, two backends differed about tenfold when measured from the same server: one had a median of about 130 ms and a maximum under 200 ms, and the other had a p99 of about 1.8 s. The order was the reverse of the providers' published figures, so measure before you choose.
7. Set `timeout` to a few times the slowest answer you measured:

   ```nginx
   decision {
       backend jev;
       timeout 1000ms;                 # a few times the slowest measured answer
   }
   ```

8. Know what a slow backend does to the site. Every judged request waits for the backend, up to `timeout`, even when the answer is slow. If no answer arrives in time, the default `on_decision_error allow` forwards the request without a verdict.

### What it costs

9. Estimate the input tokens per call. In one rollout an ordinary request was about 1,000. Replace the estimate with your own `input_tokens` once the log has them.
10. Count the calls per day: the requests that reach the backend after the skip rules and the static skip. The static skip is the router's shortcut for a plain `GET` or `HEAD` of a static file, such as a `.css` or `.png`, which is forwarded without asking the backend. Multiply the calls by the tokens per call, then by your provider's price per input token. For example, 20,000 calls at about 1,000 tokens each is 20 million input tokens a day.

### How good the backend is on your kind of traffic

11. Run the labelled evaluation with your backend, as [Evaluation](/evaluation) describes. When the shadow log shows a request near the threshold, add it to the dataset as a row. The format is in [`eval/README.md`](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/README.md).

**Before you move on:**

- [ ] The site's files, scripts, uploads and legitimate clients are written down.
- [ ] `real_ip_from` names every proxy in front of the router.
- [ ] The backend's latency was measured from the router's server, and `timeout` is set from it.
- [ ] The cost per day is estimated, and the labelled evaluation was run.

## 2. Shadow beside the site

In this phase nginx copies each request to the router with its `mirror` module. The mirror has zero risk to responses: nginx serves the site as before and discards the router's answers. In one trial, requests that nginx answered itself did not reach the router through the mirror: a `return`, a 403 from a `deny` rule, and that trial's own 404 for missing files. Your setup may differ. Compare the nginx log with the router's log to see which requests the router does not see. See [Try shadow mode beside a live site with an nginx mirror](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).

1. Add the `mirror` lines and the sink server from that section to nginx, and reload nginx.
2. In the router's configuration, listen on the mirror's target address, and send the site to the sink in shadow mode. The sink is a local server that answers 204, so each copy ends there. Keep the `decision` block from phase 1, and reload the router:

   ```nginx
   listen 127.0.0.1:8090;              # the mirror in nginx sends its copies here

   site example.com {
       upstream http://127.0.0.1:8091; # the sink
       mode shadow;
   }
   ```
3. Send one ordinary request to the site. Check that the router's access log has a line for it, with the client address and the path.

Three things change what the router sees:

- **Requests that nginx answers itself may not be copied.** In one trial, a `return`, a `deny` refusal and nginx's own 404 for missing files did not reach the router. The router's log then under-counts scanners that nginx turns away. Compare the nginx log with the router's log to see the difference on your setup.
- **An internal redirect copies the request again.** The `index` directive is one: `/` becomes `/index.php`, and the mirror runs twice. Two log lines with the same time, client, method and path show it. The fix for PHP is in [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).
- **A secret header that the CDN adds is copied too.** The router drops a header whose name looks like a credential, such as `x-csrf-token`, `x-session-id` or `x-functions-key`, before it calls the backend. Strip any other secret header in the mirror block, as [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror) shows.

Watch the trial for several days that include the owner's admin work, scheduled jobs, backups and crawler peaks. Schedule the stop, with a systemd timer or a similar scheduler, to remove the mirror lines and reload nginx, so the trial does not run on unnoticed.

**Before you move on:**

- [ ] The mirror and the sink are in place, and the router's log shows requests from the site.
- [ ] The log has no double lines on `/`, and you know which requests nginx answers before the mirror runs.
- [ ] A secret header that the CDN adds is dropped by name or stripped in nginx.
- [ ] The trial covers several days, and the stop is scheduled.

## 3. Reading the shadow log

Each request gets one JSON line, with each value written as a string. So the field reads `"would_have":"block"`, with no space after the colon. [Logging](/logging#the-built-in-formats) describes the fields.

Look at these things:

1. **Counts by `reason` and `decision_error`.** A large count in one reason shows where most of the traffic goes.
2. **Every `would_have=block` line.** Find them with `grep`:

   ```console
   $ grep -c '"would_have":"block"' access.json
   $ grep '"would_have":"block"' access.json | tail -n 20
   ```

3. **Decision errors per hour.** Timeouts in an hour with little load point to the provider, not to the site.
4. **`client_busy` bursts per minute and per client.** One browser that loads many assets at once can cause them. The fixes are in phases 4 and 5.
5. **The p99 of `latency_ms`**, compared with your `timeout`.
6. **`input_tokens`**, to replace the estimate from phase 1.

Tell your own traffic from attacks by what the requests do, not by IP address. To see the User-Agent, add a second log beside the JSON log. Keep the JSON log, because `suggest-skip-rules` reads only that format. Both lines go in the router's configuration, at the top level, where `log_format` and `access_log` are written:

```nginx
# the router's configuration, at the top level
log_format review escape=json "$time_iso8601 $client_ip $site $method $path $query_shape $status $reason $decision_error $would_have $http_user_agent";

access_log /var/log/vigilant-heron/access.json json;   # for suggest-skip-rules
access_log /var/log/vigilant-heron/review.log review;  # adds the User-Agent
```

Your own browsers send recognizable User-Agent values, and an admin workflow has a recognizable order: a login, an edit, then an upload. IP addresses change, and a cloud provider's address shows no partner, since anyone can rent one.

By default the log keeps only `query_shape`, such as `id=<num>&s=<text>`, and never the values. The `$path` field is different: the router logs the path as the client sent it. So a token in a path, such as a password-reset link, appears in the log. Keep the log files readable only by root and the operators. To review a block, find the web server's own log line for the same second, client and path.

**Before you move on:**

- [ ] The counts by `reason` and `decision_error` are reviewed.
- [ ] Each `would_have=block` line is reviewed, with its User-Agent.
- [ ] The decision errors per hour are compared with the load.
- [ ] The `client_busy` bursts are found and explained.
- [ ] The p99 of `latency_ms` and the `input_tokens` are recorded.

## 4. Writing skip rules

A skip rule forwards a request without calling the backend. It saves calls and time. Write each one narrow:

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

Put the rule in a file under `rules.d/`, include that file, and check the configuration with `vigilant-heron -t`. `-t` reports the file and line of any error. `-t` and `test-request` read the configuration the way the router does, so `TYPESAFE_API_KEY` must be set to any value. See [Rules](/rules#write-your-own-rule).

Keep these facts in mind:

- A skip rule never overrides a block rule. The built-in block rules still run first.
- A skipped request is not seen by the model at all, headers and cookies included.

Test each rule before you reload. Run `test-request` on a request that the rule must skip. Its `rules:` line then reads `matched (skip)` with the rule's description. Then run it on near misses: a quote in the value, a `<script>` tag, an extra parameter, an encoded newline, a `POST`, and a longer path. A near miss is a request the rule must not skip. If `test-request` reports `matched (skip)` for one, the rule is too wide. In the access log, the same decision appears as `reason` `skip_rule`.

```console
$ vigilant-heron -c vigilant-heron.conf test-request near-miss-extra.http
```

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

- [ ] Each rule has a method, an exact path and a narrow query regex.
- [ ] No skip rule matches a `POST` that carries credentials.
- [ ] `test-request` was run on the matching request and on each near miss.
- [ ] Each candidate from `suggest-skip-rules` was reviewed before it was copied, and the file passes `vigilant-heron -t`.

## 5. Putting the router in the request path

Until now the router only watched a copy of the traffic. In this phase the site's scripts go through it, and visitors receive its answers. Each step keeps a way back in place before it changes live traffic.

1. **Set up the inner server and check it directly.** The inner server is a second, local server block that runs the scripts. It has the same `root` as the public site, and it takes the client address from `X-Real-IP`, which the outer nginx sends and the router forwards unchanged:

   ```nginx
   # inner server: runs the scripts, reached through the router or the fallback
   server {
       listen 127.0.0.1:8081;
       root /var/www/example.com;       # the same root as the public site
       index index.php;
       set_real_ip_from 127.0.0.1;      # the outer nginx is local
       real_ip_header X-Real-IP;

       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           fastcgi_param HTTPS on;      # the visitor used HTTPS
           fastcgi_pass unix:/run/php/php-fpm.sock;   # your PHP-FPM setup
       }
       location / { try_files $uri $uri/ =404; }
   }
   ```

   Before you go on, send a request straight to the inner server, bypassing the router, and check that a script answers: `curl -i -H 'Host: example.com' http://127.0.0.1:8081/index.php`.

2. **Prepare the switch back.** Save an outer upstream that names only the inner server, next to the live one, and write down where it is. Do not use it yet:

   ```nginx
   # the switch back: copy this over the upstream block of step 3, then reload nginx
   upstream vigilant_heron {
       server 127.0.0.1:8081;
   }
   ```

3. **Put the router in the path with `mode shadow;`.** Nginx keeps its deny rules and serves static files itself, and it sends only scripts to the router. Behind a CDN, nginx must also take the visitor's address from the CDN's header. Without that, every visitor looks like the CDN, and `client_busy` refuses them all. Use the CDN's published ranges, one line each:

   ```nginx
   # outer nginx, in front of the router
   upstream vigilant_heron {
       server 127.0.0.1:8080;          # the router
       server 127.0.0.1:8081 backup;   # the inner server, used only when the router cannot be reached
   }

   server {
       listen 443 ssl;
       server_name example.com;
       root /var/www/example.com;
       index index.php;

       set_real_ip_from 173.245.48.0/20;   # behind a CDN only: one line per CDN range
       real_ip_header CF-Connecting-IP;    # behind a CDN only: or your CDN's header

       location ~ /\.(?!well-known) { deny all; }   # hidden files, before the other locations

       location ~ \.php$ {                 # scripts go through the router
           proxy_pass http://vigilant_heron;
           proxy_next_upstream error;      # not "error timeout", see step 4
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-Proto https;
       }

       location / {                        # static files, served by nginx
           try_files $uri $uri/ =404;
       }
   }
   ```

   The full layout, with keep-alive and WebSocket headers, is in [Installation](/install#putting-it-behind-nginx-or-cloudflare). The router trusts the address that nginx sends, and it forwards the site to the inner server:

   ```nginx
   # the router's configuration (keep the decision block from phase 1)
   listen 127.0.0.1:8080;
   real_ip_from 127.0.0.1;             # trust X-Real-IP only from the outer nginx
   real_ip_header X-Real-IP;
   client_max_body_size 1m;            # the same as nginx's limit; phase 6 raises both

   site example.com {
       upstream http://127.0.0.1:8081; # the inner server
       mode shadow;
   }
   ```

   Check the file with `-t`, then reload the router and nginx. Compare `latency_ms` in the log with nginx's request time to measure the latency the router adds.

   Permalink sites need one more setting. WordPress, for example, falls back to `/index.php` for a missing file, so a request for a missing `/x.css` reaches the router as a script request. The static skip, the router's shortcut from phase 1, would then forward it without a verdict. On such a site, add `static_extensions;` with no extensions to the site block. An empty list turns the static skip off.

4. **Stop the router, and check the fallback.** Stop the router with `sudo systemctl stop vigilant-heron`, or with `vigilant-heron stop -c` for a background router. Send a request to the site, and expect the page from the inner server. Then start the router again.

   While requests go to the backup, nothing is judged. The router never sees them, so its rules, limits and `fail_closed_path` (a path prefix that is blocked whenever the decision fails) do not apply. The fallback is for a router that cannot be reached. With `proxy_next_upstream error;`, a router that accepts connections but does not answer gives 504 instead of being bypassed. The nginx default, `error timeout`, would send a slow request past the router, so slowness could be used to get around it. When the router is up but not answering, the switch back from step 2 is the way out.

**Before you move on:**

- [ ] The inner server answers a script directly, with the client address and the scheme from the outer nginx.
- [ ] The switch back is saved in a file, and you know where it is.
- [ ] Behind a CDN, nginx takes the visitor's address from the CDN header.
- [ ] The router ran in the path in shadow mode, and you measured the latency it adds.
- [ ] With the router stopped, the site still answers through the inner server.
- [ ] On a permalink site, `static_extensions;` is set.

## 6. Switching to enforce

1. **Raise the upload limit in both places, then test uploads.** Choose the largest upload the site must accept, for example `10m`. Set `client_max_body_size` to that in nginx's server block and in the router's configuration, and reload both. Upload a file within the limit, which must work, and a file over it, which must get 413.
2. **Rehearse the way back.** Change `mode shadow;` to `mode enforce;`, reload the router, then change it back to `mode shadow;` and reload again. Check the log: requests are forwarded again, and the ones that would be blocked show `would_have`. Only then set `mode enforce;` for real.
3. **Switch to enforce.** Change `mode shadow;` to `mode enforce;`, check the file, and reload. A reload applies the new file to new requests, and requests already in flight finish with the configuration they started with:

   ```console
   $ vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
   $ vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
   ```

   With the systemd unit from [Installation](/install#run-as-a-service-with-systemd), run `sudo systemctl reload vigilant-heron` instead.

4. **Check right after the reload.**
   - Send a known attack, such as a query with `UNION SELECT`. The answer should be `403 Forbidden`:

     ```console
     $ curl -i "https://example.com/?id=1%20UNION%20SELECT%20password%20FROM%20users"
     ```

   - Have the owner log in, save a post, upload a file within the limit, and use the admin screens.
   - Check the log for any block or 429 from these actions. A 429 is the `client_busy` refusal, which `on_client_busy` sends by default.

5. **Know the two ways back.** `mode shadow;` and reload keeps the router in the path and recording. The switch back from phase 5 takes the router out of the path.

6. **Review regularly.** Look at every block and 429, at allowed requests whose `attack` score was close to `block_threshold`, at decision errors per hour, and at the cost per day. Change a rule only after `test-request` has checked it.

**Before you move on:**

- [ ] Uploads within the limit work, and a file over it gets 413.
- [ ] The way back was rehearsed, and the log confirmed it.
- [ ] The `403` test attack was seen, and the owner's actions gave no unexpected block or 429.
- [ ] The way back is written down, and you know which one you would use.
- [ ] The review schedule is set: blocks, 429s, near-threshold allows, decision errors and cost.

## 7. Principles for running it safely

- **Layers.** Put a CDN or an edge web application firewall (WAF, a filter of attack patterns) first, then the web server's deny rules, the router's rules and the model. The model only adds blocks. No model answer can turn a rule block into an allow.
- **What the backend receives.** The router removes credential headers, redacts sensitive fields, and sends only the first `inspect_body` bytes of a body. Uploads can still carry personal data, such as a location in a photo's metadata. Name such fields with `redact_field` in the `decision` block, for example `redact_field gps_position;`. For a body within `inspect_body`, the whole content of a part with that field name is replaced by `[REDACTED]`. An upload under that name is therefore sent without its file bytes or metadata.
- **Defaults that favor availability.** A failed decision forwards the request, and a client over its share is refused, as phase 1 explains. For the few paths where a missed attack costs more than a refused visitor, such as a login page, set `fail_closed_path`. A request on those paths is blocked whenever the decision fails, whatever the other settings say:

  ```nginx
  site example.com {
      upstream http://127.0.0.1:8081;
      fail_closed_path /login /admin;
  }
  ```

  The cost of forwarding failed decisions is that an attacker who makes the backend unavailable can get requests past the model. Limit each client with `limit_req` and `limit_conn` too. See [Security](/security#failure-behavior).
- **Configuration under version control.** Keep the router's configuration in the same version control as the server setup. Pin the release binary, and check it against `SHA256SUMS` before you install it, as [Installation](/install#download-a-release-binary) shows.

**Before you move on:**

- [ ] The layers are in place, and the model is only one of them.
- [ ] Fields that carry personal data are listed in `redact_field`, and an upload was checked against the log.
- [ ] `fail_closed_path` covers the login and admin paths.
- [ ] `limit_req` and `limit_conn` limit each client.
- [ ] The configuration and the pinned binary are under version control.
