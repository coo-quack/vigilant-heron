# Rules

Two deterministic checks run before the decision backend: an access list by
client address, and rules that match the request. Both use nginx syntax, and both
can be written at the top level or inside a `site`.

## Write your own rule

Follow these five steps to add a rule. The example blocks a retired admin path.

1. **Write the rule file.** Put the rule in a file under `rules.d/`, such as
   `rules.d/local.conf`, and include it from the top level of the configuration with
   `include rules.d/*.conf;`. The sample file `examples/rules.d/local.conf` has more
   examples. Rule ids must not start with `vh-`, which is reserved for the built-in
   rules.

   ```nginx
   rule local-old-admin {
       description "retired admin path";
       action block;
       site www.example.com;
       path ^~ /old-admin;
   }
   ```

2. **Check the syntax.** Run `vigilant-heron -t -c /etc/vigilant-heron/vigilant-heron.conf`.
   It reports the file and line of any error. It does not show what a rule matches.

3. **Test the rule on sample requests.** Save one request that the rule must block and
   one normal request that it must not block, as raw HTTP files. Then run
   `test-request` on each. The `rules:` line names the rule that matched, and the
   `result:` line gives the action. See [Check a request with test-request](/cli#check-a-request-with-test-request).

   ```console
   $ vigilant-heron -c /etc/vigilant-heron/vigilant-heron.conf test-request old-admin.http
   ```

4. **Reload the running router.** Run `vigilant-heron -s reload`. The router applies the
   new file and keeps its open connections. A file that fails the check keeps the old
   configuration.

5. **Check the access log.** Send a request that the rule should match, and look at its
   log line. `rule_id` is the id of the rule, and `reason` is `rule`. On a shadow site,
   `would_have=block` shows that the request would have been blocked, and the request
   is still forwarded. See [Logging](/logging).

For a new site, it is safer to start the site with `mode shadow;`, check the log for
`would_have=block` on the requests you expect, and switch to `mode enforce;` only after
that. Rules run in both modes.

## Access list

```nginx
allow <address|CIDR|all>;
deny  <address|CIDR|all>;
```

The entries are checked in order, and the first one that covers the client
decides, as in nginx's access module. A client that no entry covers is allowed.
A `site` with any `allow` or `deny` line replaces the top-level list. A site
without one inherits it. The client address is the one chosen by the realip
settings.

A denied client on an `enforce` site gets 403 with reason `access_denied`. The
body is not read and the backend is not called. The site's `action` does not
apply, as in nginx. On a `shadow` site the request is forwarded, and the log
records `would_have=block`. A request whose `Host` matches no site gets `default_status`
(421 by default) with reason `unknown_host`. A client that the top-level access list
denies gets 403 with reason `access_denied` instead.

```nginx
site admin.example.com {
    upstream http://admin:8080;
    allow 203.0.113.0/24;
    deny all;
}
```

## Rules

A rule is a block with an id:

```nginx
rule example-login-probe {
    description "login probe with a fixed user agent";
    action block;
    method POST;
    path = /login;
    header user-agent ~* "^probe/";
}
```

The fields of a rule are:

- **`description`**: required text for the log and for the reader.
- **`action`**: `block` or `skip`, required.
- **`site`**: top-level rules only. Names the sites the rule applies to. Each name must be a configured site.
- **`method`**: one or more methods, such as `method GET HEAD;`. Once per rule.
- **`path`**: a prefix, or one of `= <value>`, `^~ <value>`, `~ <regex>` and `~* <regex>`. Once per rule.
- **`query`**: `query <~|~*> <regex>;`. May repeat, and each repetition must match.
- **`header`**: `header <name> <~|~*> <regex>;`. May repeat.
- **`body`**: `body <~|~*> <regex>;`. May repeat.
- **`any`**: `any <~|~*> <regex>;`, which matches the path, the query, every header value or the body prefix. May repeat.
- **`client`**: `client <address|CIDR> ...;`, matched by the realip address. Once per rule.

A rule matches when every condition it lists matches, and it must list at least
one condition.

### Where a rule applies

- A rule at the top level applies to every site, unless it has a `site` directive
  that names the sites it applies to.
- A rule inside a `site` applies to that site only, and cannot have a `site`
  directive.
- Rule ids are unique across all files. An error names both places.
- Ids that start with `vh-` are reserved for the [built-in rules](/builtin-rules).
- A built-in rule written with `default off;` runs only where `enable_rule` names it. The directive is valid only in the built-in rules; a user rule is on as soon as it is written. See [Built-in rules](/builtin-rules#opt-in-rules).

### Block and skip

- `action block` is decided like `deny_path`. The site's `action` applies, and in
  shadow mode the request is forwarded and recorded in `would_have`. The reason is
  `rule`.
- `action skip` forwards the request without calling the backend. The reason is
  `skip_rule`. To find skip-rule candidates in your access log, see
  [Learn skip rules from the access log](/cli#learn-skip-rules-from-the-access-log).

Block rules are always checked before skip rules. A skip rule never lets through a
request that a block rule matches.

## Matching

Matching uses the normalized request. The forwarded request is never changed by
this.

- **Path**: six readings of the path, see [How it works](/how-it-works#path-readings).
  A block rule's `path` condition matches when any reading matches, and a skip
  rule's `path` condition only when every reading matches. The case is kept, so
  `path` and `path ~` are case-sensitive, as in nginx.
- **Query and form body**: `+` becomes a space, percent-decoding is applied at
  most twice, so a double-encoded escape is undone, and NUL bytes are removed.
- **Header values**: the same decoding as the query, except that `+` is literal.
- **Body**: only the first `inspect_body` bytes, decoded as the query. A body
  condition cannot see later bytes. Multipart structure is not parsed.
- **`client`**: the realip address.

Regexes use the `regex` crate. Matching takes time linear in the input and never
backtracks, so a pattern cannot make a request slow in proportion to a bad input.
Look-around and back-references are not available. A regex may be 512 bytes at
most, and its compiled form is limited to 1 MiB. The configuration holds at most
1000 rules, built-in ones included. Each violation is a configuration error that
names its file and line.

## Order

The complete order is in [How it works](/how-it-works#evaluation-order). In short:
the access list, then `deny_path`, then block rules, then skip rules, then the
static asset skip, then the model. No failure setting changes the outcome of the
first five.

## Logs

`$rule_id` is the id of the rule that decided the request. It is empty when no
rule did. The built-in `json` format logs it as `rule_id`, and a `log_format` can
include `$rule_id`. The reasons for these decisions are `access_denied`, `rule`
(also `deny_path`, which has no id) and `skip_rule`. See [Logging](/logging).
