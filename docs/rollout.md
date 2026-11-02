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

   Expect the site's own calls to its public URL to show the server's own public address in the log. Count them as a legitimate client, and check that no limit or deny rule on that address stops the site's own work.

### What sits in front and how the client address arrives

3. Note what runs in front of the router: a CDN, nginx, or both.
4. Set `real_ip_from` to the addresses of every proxy in front of the router, and `real_ip_header` to the header that they send. See [Installation](/install#putting-it-behind-nginx-or-cloudflare). The router believes the header only from a listed peer, so a client that is not a trusted proxy cannot choose its own address by sending the header.

### Which backend, and how fast it answers

5. Choose a backend. [Decision backends](/decision-backends) lists them.
6. Measure the backend's latency from the server that will run the router, not from your workstation. In one rollout, two backends differed about tenfold when measured from the same server: one answered in about 130 ms, and the other had a p99 near 1.8 s. The order was the reverse of the providers' published figures, so measure before you choose.
7. Set `timeout` to a few times the slowest answer you measured:

   ```nginx
   decision {
       backend jev;
       timeout 1000ms;                 # a few times the slowest measured answer
   }
   ```

8. Know what a slow backend does to the site. With the default `on_decision_error allow`, a request whose answer does not arrive within `timeout` is forwarded without a verdict. A request whose answer never comes waits the whole `timeout` before it is forwarded.

### What it costs

9. Estimate the input tokens per call. In one rollout an ordinary request was about 1,000 input tokens. Replace this estimate with your own `input_tokens` values once the shadow log has them.
10. Count the calls per day: the requests that reach the backend after the skip rules and the static skip have taken their share. Multiply the calls by the tokens per call, then by your provider's price per input token. For example, 20,000 calls a day at about 1,000 tokens each is 20 million input tokens a day.

### How good the backend is on your kind of traffic

11. Run the labelled evaluation with your backend, as [Evaluation](/evaluation) describes. When the shadow log shows a request near the threshold, add it to the dataset as a row. The format is in [`eval/README.md`](https://github.com/coo-quack/vigilant-heron/blob/develop/eval/README.md).

**Before you move on:**

- [ ] The site's static files, scripts, uploads and legitimate clients are written down.
- [ ] `real_ip_from` names every proxy in front of the router.
- [ ] The backend's latency was measured from the router's server, and `timeout` is set from it.
- [ ] The cost per day is estimated.
- [ ] The labelled evaluation was run with the backend you chose.

## 2. Shadow beside the site

In this phase nginx copies each request to the router with its `mirror` module. nginx serves the site as before and discards the router's answers. See [Try shadow mode beside a live site with an nginx mirror](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).

1. Add the `mirror` lines and the sink server from that section to nginx, and reload nginx.
2. In the router's configuration, set the site to `mode shadow;` with `upstream http://127.0.0.1:8091;`, the sink. Reload the router.
3. Send one ordinary request to the site. Check that the router's access log has a line for it, with the client address and the path.

Three things change what the router sees:

- **Requests that nginx answers before the mirror runs are not copied.** Examples are a `return` in a `location` and a request that an access `deny` refuses. The log under-counts scanners that nginx turns away.
- **An internal redirect copies the request again.** The `index` directive is one: `/` becomes `/index.php`, and the mirror runs twice. Two log lines with the same time, client, method and path show it. The fix for PHP is in [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror).
- **A secret header that the CDN adds is copied too.** The router drops a header whose name looks like a credential, such as `x-csrf-token`, `x-session-id` or `x-functions-key`, before it calls the backend. Strip any other secret header in the mirror block, as [Installation](/install#try-shadow-mode-beside-a-live-site-with-an-nginx-mirror) shows.

Watch the trial for several days that include the owner's admin work, scheduled jobs, backups and crawler peaks. Write down the stop date, and schedule the stop with a systemd timer or a similar scheduler. The job removes the mirror lines and reloads nginx, so the trial does not run on unnoticed.

**Before you move on:**

- [ ] The mirror and the sink are in place, and the router's log shows requests from the site.
- [ ] You have checked the log for double lines on `/`, and you know which requests nginx answers before the mirror runs.
- [ ] A secret header that the CDN adds is either dropped by name or stripped in nginx.
- [ ] The trial covers several days, including admin work, scheduled jobs, backups and crawler peaks.
- [ ] The stop is scheduled.

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
5. **The p99 of `latency_ms`.** Compare it with the timeout you set in phase 1.
6. **`input_tokens`.** Replace the estimate from phase 1 with these values.

Tell your own traffic from attacks by what the requests do, not by IP address. To see the User-Agent, add a second log beside the JSON log. Keep the JSON log, because `suggest-skip-rules` reads only that format:

```nginx
log_format review escape=json "$time_iso8601 $client_ip $method $path $query_shape $status $reason $decision_error $would_have $http_user_agent";

access_log /var/log/vigilant-heron/access.json json;   # for suggest-skip-rules
access_log /var/log/vigilant-heron/review.log review;  # adds the User-Agent
```

Your browsers and devices send recognizable User-Agent values, and an admin workflow has a recognizable order: a login, an edit, then an upload. Home and mobile addresses change, and a cloud-provider address is not a sign of a partner, because anyone can rent one.

By default the log keeps only `query_shape`, such as `id=<num>&s=<text>`, and never the values. To review a block, find the web server's own log line for the same second, client and path.

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
    method GET HEAD;
    path = /products;
    query ~ "^id=[0-9]+$";
}
```

Put the rule in a file under `rules.d/`, include that file, and check the configuration with `vigilant-heron -t`. `-t` reports the file and line of any error. See [Rules](/rules#write-your-own-rule).

Keep these facts in mind:

- A skip rule never overrides a block rule. The built-in block rules still run first.
- A skipped request is not seen by the model at all, headers and cookies included.

Test each rule before you reload. Run `test-request` on a request that the rule must skip. Then run it on near misses: a quote in the value, a `<script>` tag, an extra parameter, an encoded newline, a `POST`, and a longer path. A near miss is a request the rule must not skip. If `test-request` reports `skip_rule` for one, the rule is too wide.

```console
$ vigilant-heron -c vigilant-heron.conf test-request near-miss-extra.http
```

Use `suggest-skip-rules` to find candidates in the JSON log. Its thresholds are strict, so on a small site it may print nothing. Treat its output as candidates to review, not as rules to copy. It prints only; it changes no file. See [Learn skip rules from the access log](/cli#learn-skip-rules-from-the-access-log).

Cache-busting queries on static files, such as `?ver=1.2.3`, need `static_query_params`:

```nginx
site example.com {
    upstream http://127.0.0.1:8081;
    static_query_params ver;
}
```

A better fix is to let the web server serve static files without the router, as phase 5 describes.

**Before you move on:**

- [ ] Each rule has a method, an exact path and a narrow query regex.
- [ ] No skip rule matches a `POST` that carries credentials.
- [ ] `test-request` was run on the matching request and on each near miss.
- [ ] Each candidate from `suggest-skip-rules` was reviewed before it was copied, and the file passes `vigilant-heron -t`.

## 5. Putting the router in the request path

Until now the router only watched a copy of the traffic. In this phase the site's scripts go through it, and visitors receive its answers.

1. **Let nginx keep its deny rules and serve static files.** Send only script executions to the router. Each judged request costs a backend call and some latency.
2. **Run a second, local server block for the scripts.** It is the router's upstream. The outer nginx passes the client address and the scheme along, and the router forwards those headers:

   ```nginx
   # outer nginx, in front of the router
   upstream vigilant_heron {
       server 127.0.0.1:8080;           # the router
       server 127.0.0.1:8081 backup;    # the inner server, used only when the router cannot be reached
   }

   server {
       listen 443 ssl;
       server_name example.com;

       location / {
           proxy_pass http://vigilant_heron;
           proxy_next_upstream error;   # not "error timeout", see below
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-Proto https;
       }
   }
   ```

   The router must trust the address that nginx sends, and its upload limit must match nginx's:

   ```nginx
   # the router's configuration
   listen 127.0.0.1:8080;
   real_ip_from 127.0.0.1;              # trust X-Real-IP only from the outer nginx
   real_ip_header X-Real-IP;
   client_max_body_size 1m;             # the same as the web server's limit

   decision {
       backend jev;
       timeout 1000ms;
   }

   site example.com {
       upstream http://127.0.0.1:8081;  # the inner server
       mode shadow;
   }
   ```

   If `client_max_body_size` is lower than the web server's, a larger upload gets 413 from the router, and the upload fails. Set both to the same size.

3. **Fall back to the inner server only when the router cannot be reached.** That is what `backup` and `proxy_next_upstream error;` do. The nginx default, `proxy_next_upstream error timeout;`, also sends a request to the next server after a timeout. A slow request that the router is still judging would then be sent past the router. One failure would also send all traffic past it for the `fail_timeout` period.
4. **Keep a one-command switch back.** Keep a copy of the outer upstream block with only `server 127.0.0.1:8081;` in it. To take the router out, copy it into place and reload nginx.
5. **Test the fallback before you rely on it.** Stop the router and send a request to the site. It should still get the page. Start the router again afterwards.
6. **Run in the path with `mode shadow;` first.** The router then forwards every request and only records its verdict. Compare `latency_ms` with nginx's request time to measure the latency it adds.

**Before you move on:**

- [ ] Static files are served without the router.
- [ ] The inner server gets the client address and the scheme from the outer nginx.
- [ ] `client_max_body_size` is the same in the router and in nginx.
- [ ] The fallback uses `proxy_next_upstream error;` with the inner server as `backup`.
- [ ] The switch back is written down, and the fallback was tested with the router stopped.
- [ ] The latency added by the router was measured in shadow mode.

## 6. Switching to enforce

1. Change `mode shadow;` to `mode enforce;` in the site, and check the file:

   ```console
   $ vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf
   ```

2. Reload the router. A reload applies the new file to new requests, and requests already in flight finish with the configuration they started with:

   ```console
   $ vigilant-heron -s reload -c /etc/vigilant-heron/vigilant-heron.conf
   ```

   With the systemd unit from [Installation](/install#run-as-a-service-with-systemd), run `sudo systemctl reload vigilant-heron` instead.

3. Right after the reload, check these:
   - Send a known attack, such as a query with `UNION SELECT`. The answer should be `403 Forbidden`:

     ```console
     $ curl -i "https://example.com/?id=1%20UNION%20SELECT%20password%20FROM%20users"
     ```

   - Have the owner log in, save a post, upload a file larger than 1 MB, and use the admin screens. Set `client_max_body_size` first, so that the site accepts the upload.
   - Check the log for any block or 429 that came from these actions. A 429 means that a client held its share of backend calls (`client_busy`), so the router refused it without asking the backend. The refusal is a 429 because `on_client_busy` defaults to `block`.

4. Know the two ways back: `mode shadow;` and reload, which keeps recording, or the web-server switch from phase 5, which takes the router out of the path.

5. Review regularly: every block and 429, allowed requests whose `attack` score was close to `block_threshold`, decision errors per hour, and the cost per day. Change a rule only after `test-request` has checked it.

**Before you move on:**

- [ ] The `403` test attack was seen, and the owner's actions gave no unexpected block or 429.
- [ ] The way back is written down, and you know which one you would use.
- [ ] The review schedule is set: blocks, 429s, near-threshold allows, decision errors and cost.

## 7. Principles for running it safely

- **Layers.** Put the CDN or an edge WAF first, then the web server's deny rules, then the router's rules, then the model. The model only adds blocks. A model answer cannot turn a rule block into an allow.
- **What the backend receives.** The router removes credential headers and redacts sensitive fields, and it sends only the first `inspect_body` bytes of a body. Uploads can still carry personal data, such as a location in a photo's metadata. Add such field names with `redact_field`, which also applies to multipart parts by the part's name:

  ```nginx
  decision {
      backend jev;
      redact_field location gps_position;
  }
  ```

- **Availability-first defaults.** A failed decision forwards the request, because `on_decision_error` and `on_rate_limit` default to `allow`. A client over its share is refused, because `on_client_busy` defaults to `block`. For the few paths where a missed attack costs more than a refused visitor, such as a login page, use `fail_closed_path`. A failure on those paths blocks, whatever the other settings say:

  ```nginx
  site example.com {
      upstream http://127.0.0.1:8081;
      fail_closed_path /login /admin;
  }
  ```

  The cost of `allow` is that an attacker who makes the backend unavailable can get requests past the model. Limit each client with `limit_req` and `limit_conn` too. See [Security](/security#failure-behavior).
- **Configuration under version control.** Keep the router's configuration in the same version control as the server setup. Pin the release binary, and check it against `SHA256SUMS` before you install it, as [Installation](/install#download-a-release-binary) shows.
