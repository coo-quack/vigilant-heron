# Built-in rules

The built-in rules ship in the binary, in
[`src/rules/builtin.conf`](https://github.com/coo-quack/vigilant-heron/blob/develop/src/rules/builtin.conf).
They are high-confidence signatures, and each one is a block rule with an id of
the form `vh-<category>-<nnn>`. Most of them run on every site unless `builtin_rules off;`
turns the set off, and a single id can be turned off with `disable_rule`. The rules
marked off in the Default column run only where `enable_rule` names them; see
[Opt-in rules](#opt-in-rules).

```nginx
builtin_rules on;                        # top level or site; default on
disable_rule vh-scanner-001 vh-xss-003;  # top level or site; built-in ids only
enable_rule vh-cve-2026-9103;            # top level or site; turns on a rule that is off by default
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

| Id | Category | Default | What the rule matches | Inspects |
|---|---|---|---|---|
| `vh-sqli-001` | SQL injection | on | `UNION SELECT` in a query string | query |
| `vh-sqli-002` | SQL injection | on | A quote followed by a tautology and a comment terminator | any |
| `vh-sqli-003` | SQL injection | on | A quote followed by a stacked destructive statement (`drop`, `shutdown`, `exec`, `execute`, `truncate`) | any |
| `vh-sqli-004` | SQL injection | on | A time-based SQL function (`sleep`, `pg_sleep`, `benchmark`) or `WAITFOR DELAY` after a quote or a closing parenthesis | any |
| `vh-xss-001` | XSS | on | A `<script` tag in a query string | query |
| `vh-xss-002` | XSS | on | A `javascript:` URL in a query string | query |
| `vh-xss-003` | XSS | on | An inline event handler (`on...=`) in markup in a query string | query |
| `vh-traversal-001` | Path traversal | on | A `../` sequence, with plain or encoded dots and slashes, in a query string | query |
| `vh-traversal-002` | Path traversal | on | `etc/passwd`, `etc/shadow`, `win.ini`, `boot.ini` or `/proc/self/` in a query string | query |
| `vh-traversal-003` | Path traversal | on | `etc/passwd`, `etc/shadow`, `win.ini`, `boot.ini` or `/proc/self/` in the path | path |
| `vh-cmdi-001` | Command injection | on | A shell separator (`;`, `|`, `&` or a backtick) followed by a common command (`cat`, `id`, `whoami`, `uname`, `wget`, `curl`, `nc`, `bash`, `sh`) in a query string, where the command is followed by whitespace, the end of the value, or a separator. A parameter such as `&id-from=3` or `&cat-name=x` is not matched | query |
| `vh-cmdi-002` | Command injection | on | A `$(` command substitution in a query string | query |
| `vh-cmdi-003` | Command injection | on | A backtick followed by `cat`, `id`, `whoami`, `uname`, `wget` or `curl` in a query string | query |
| `vh-lfi-001` | File inclusion | on | A PHP stream wrapper (`php://filter`, `input`, `memory`, `temp` or `fd`) in any input | any |
| `vh-lfi-002` | File inclusion | on | A base64 data URI with a MIME type in a query string | query |
| `vh-lfi-003` | File inclusion | on | An `expect://` wrapper in a query string | query |
| `vh-lfi-004` | File inclusion | on | A remote `http`, `https` or `ftp` URL in a `file`, `template`, `include`, `inc`, `require` or `page` parameter of a query string | query |
| `vh-ssrf-001` | SSRF | on | The cloud metadata address `169.254.169.254` | any |
| `vh-ssrf-002` | SSRF | on | A `file`, `gopher`, `dict`, `ldap` or `tftp` URL in a query string | query |
| `vh-expr-001` | Template and expression injection | on | A JNDI lookup in the Log4Shell form (`${jndi:`) | any |
| `vh-expr-002` | Template and expression injection | on | The `{{7*7}}` or `${7*7}` template probe | any |
| `vh-expr-003` | Template and expression injection | on | The Spring class loader property path (`class.module.classloader`) | any |
| `vh-xxe-001` | XML external entities | on | An entity declared with `SYSTEM` in the body prefix | body |
| `vh-scanner-001` | Known scanners | on | The user agent of a known scanner (sqlmap, nikto, nuclei, masscan, zgrab, acunetix, havij, commix, wpscan, dirbuster, gobuster or nmap) | header user-agent |
| `vh-cve-2026-9103` | Opt-in virtual patch (CVE-2026-9103, IBM Langflow OSS) | off | Any request to `/api/v1/login/auto_login`, which issues superuser tokens without authentication when `AUTO_LOGIN` is enabled, which is the default | path |
| `vh-cve-2026-8481` | Opt-in virtual patch (CVE-2026-8481, IBM Langflow OSS) | off | A `POST` to `/api/v1/validate/code`, which runs user-supplied Python through `exec()` without a sandbox; an authenticated user can exploit it, so the rule also covers a stolen or self-registered account | method and path |

## Opt-in rules

A rule with `off` in the Default column is a virtual patch for a known flaw in a
product. It blocks a whole endpoint, and that endpoint may be used legitimately by
the product's own users, so it is not on everywhere. Enable it on the sites that run
the affected product, and only there:

```nginx
site langflow.example.com {
    upstream http://langflow:7860;
    enable_rule vh-cve-2026-9103 vh-cve-2026-8481;
}
```

The two rules cover IBM Langflow OSS 1.0.0 through 1.10.0:

- `vh-cve-2026-9103`: [IBM bulletin](https://www.ibm.com/support/pages/node/7278926).
  IBM recommends upgrading to 1.10.1.
- `vh-cve-2026-8481`: [IBM bulletin](https://www.ibm.com/support/pages/node/7278923).
  Upgrade past 1.10.0, and check the bulletin for the fixed release.

Both rules block until the product is upgraded. Later Langflow bulletins can list
newer fixed releases, so run the latest release. The policy for these rules, and how
to write rules of your own for other advisories, is in
[From CVE advisories to rules](/cve-rules).

CVE-2026-8505 (a webhook that runs a flow without an API key when
`WEBHOOK_AUTH_ENABLE` is false) has no shipped rule, because the rule language cannot
express a missing header. The fix IBM gives is an upgrade to 1.10.1; see
[its bulletin](https://www.ibm.com/support/pages/security-bulletin-authentication-bypass-webhook-endpoints-allowed-unauthorized-flow-execution)
and [From CVE advisories to rules](/cve-rules#worked-example-cve-2026-8505).
