# Built-in rules

The built-in rules ship in the binary, in
[`src/rules/builtin.conf`](https://github.com/coo-quack/vigilant-heron/blob/develop/src/rules/builtin.conf).
They are high-confidence signatures, and each one is a block rule with an id of
the form `vh-<category>-<nnn>`. They run on every site unless `builtin_rules off;`
turns the set off, and a single id can be turned off with `disable_rule`.

```nginx
builtin_rules on;                        # top level or site; default on
disable_rule vh-scanner-001 vh-xss-003;  # top level or site; built-in ids only
```

A rule is written to miss an attack rather than block ordinary traffic. A pattern
that could appear in a code paste, a post about SQL or HTML, a base64 blob or
Japanese text is left out, and such traffic goes to the decision model or to a
user rule. The table below shows what each rule inspects. `query`, `path`, `body`
and `header` are the normalized parts of the request described in
[Rules](/rules#matching). `any` is the path, the query, every header value, and
the body prefix. The rules are measured in
[the evaluation](/evaluation).

An unknown id in `disable_rule` is a configuration error. The
[documentation test](https://github.com/coo-quack/vigilant-heron/blob/develop/tests/docs.rs)
checks that this table lists exactly the ids of `builtin.conf`.

| Id | Category | What the rule matches | Inspects |
|---|---|---|---|
| `vh-sqli-001` | SQL injection | `UNION SELECT` in a query string | query |
| `vh-sqli-002` | SQL injection | A quote followed by a tautology and a comment terminator | any |
| `vh-sqli-003` | SQL injection | A quote followed by a stacked destructive statement (`drop`, `shutdown`, `exec`, `execute`, `truncate`) | any |
| `vh-sqli-004` | SQL injection | A time-based SQL function (`sleep`, `pg_sleep`, `benchmark`) or `WAITFOR DELAY` after a quote or a closing parenthesis | any |
| `vh-xss-001` | XSS | A `<script` tag in a query string | query |
| `vh-xss-002` | XSS | A `javascript:` URL in a query string | query |
| `vh-xss-003` | XSS | An inline event handler (`on...=`) in markup in a query string | query |
| `vh-traversal-001` | Path traversal | A `../` sequence, with plain or encoded dots and slashes, in a query string | query |
| `vh-traversal-002` | Path traversal | `etc/passwd`, `etc/shadow`, `win.ini`, `boot.ini` or `/proc/self/` in a query string | query |
| `vh-traversal-003` | Path traversal | `etc/passwd`, `etc/shadow`, `win.ini`, `boot.ini` or `/proc/self/` in the path | path |
| `vh-cmdi-001` | Command injection | A shell separator (`;`, `|`, `&` or a backtick) followed by a common command (`cat`, `id`, `whoami`, `uname`, `wget`, `curl`, `nc`, `bash`, `sh`) in a query string | query |
| `vh-cmdi-002` | Command injection | A `$(` command substitution in a query string | query |
| `vh-cmdi-003` | Command injection | A backtick followed by `cat`, `id`, `whoami`, `uname`, `wget` or `curl` in a query string | query |
| `vh-lfi-001` | File inclusion | A PHP stream wrapper (`php://filter`, `input`, `memory`, `temp` or `fd`) in any input | any |
| `vh-lfi-002` | File inclusion | A base64 data URI with a MIME type in a query string | query |
| `vh-lfi-003` | File inclusion | An `expect://` wrapper in a query string | query |
| `vh-lfi-004` | File inclusion | A remote `http`, `https` or `ftp` URL in a `file`, `template`, `include`, `inc`, `require` or `page` parameter of a query string | query |
| `vh-ssrf-001` | SSRF | The cloud metadata address `169.254.169.254` | any |
| `vh-ssrf-002` | SSRF | A `file`, `gopher`, `dict`, `ldap` or `tftp` URL in a query string | query |
| `vh-expr-001` | Template and expression injection | A JNDI lookup in the Log4Shell form (`${jndi:`) | any |
| `vh-expr-002` | Template and expression injection | The `{{7*7}}` or `${7*7}` template probe | any |
| `vh-expr-003` | Template and expression injection | The Spring class loader property path (`class.module.classloader`) | any |
| `vh-xxe-001` | XML external entities | An entity declared with `SYSTEM` in the body prefix | body |
| `vh-scanner-001` | Known scanners | The user agent of a known scanner (sqlmap, nikto, nuclei, masscan, zgrab, acunetix, havij, commix, wpscan, dirbuster, gobuster or nmap) | header user-agent |
