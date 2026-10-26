---
layout: home

hero:
  name: vigilant-heron
  text: Screen web requests before they reach your sites
  tagline: A reverse-proxy router with nginx-style configuration. It blocks known attacks with fixed rules, asks a decision model about everything else, and lets ordinary traffic through.
  image:
    src: /logo.svg
    alt: vigilant-heron
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started
    - theme: alt
      text: Install
      link: /install
    - theme: alt
      text: GitHub
      link: https://github.com/coo-quack/vigilant-heron

features:
  - icon: 🧱
    title: Fixed rules first
    details: Built-in signatures block SQL injection, XSS, path traversal and known scanners. The rules run before the model, and the model cannot override them.
  - icon: 🧠
    title: A decision model for the rest
    details: Requests the rules do not decide go to a model such as Jev, Clef, or your own. It returns two scores, and thresholds you set decide what gets blocked.
  - icon: 🐦
    title: Shadow mode
    details: Run a site in shadow mode first. Requests are forwarded, and the log records what would have been blocked. Malformed requests and oversized bodies are still refused.
  - icon: 🚦
    title: Request limits
    details: Limit requests and connections per client address or per path, before the body is read, with a dry-run mode for trying a limit out.
  - icon: 📝
    title: nginx-style configuration
    details: Directives, blocks and includes follow nginx. A wrong value fails the check with its file and line, so `-t` tells you what to fix.
  - icon: 🔍
    title: Logs you can read
    details: One access line per request, in JSON or a format you define. Every value is escaped, and credential headers never reach the log.
---

## Why vigilant-heron?

Most attacks on a web application follow patterns that do not occur in ordinary traffic. A `UNION SELECT` in a query string, or a request for `/.env`, has one purpose. The application still receives them, and it has to decide what to do with each one. vigilant-heron stands in front of the application and makes that decision first.

It does not try to be a perfect filter. It blocks the requests that are clearly malicious, and it lets everything else pass. When the decision model cannot answer, the router lets the request through by default, so a model outage does not take your site down.

| Without vigilant-heron | With vigilant-heron |
|------------------------|---------------------|
| `GET /?id=1 UNION SELECT password FROM users` reaches the application | Blocked with 403 by rule `vh-sqli-001`, without asking the model |
| `GET /.env` reaches the application, which may return its contents | Blocked with 403 when the site has `deny_path /.env;` |
| A prompt-injection payload in a request to an AI endpoint is forwarded | The model scores it on `ai_instruction`, and a score at or above `instruction_threshold` (0.8 by default) blocks it |
| One address sends 500 requests a second, and all of them reach the application | A `limit_req` zone refuses the excess with the status you set, such as 429 |
| The decision model is down | Rules still block the attacks above. A request the model cannot judge is let through, which is the default (`on_decision_error allow`) |

- **Ordinary requests pass.** A request is blocked only by the access list, a limit, a rule, or a score above a threshold.
- **Shadow mode first.** A new site records its decisions in the log before anything is blocked.
- **Failures are visible.** Each access line records the decision, the reason, and any decision error.
- **Your own rules.** Add a `rule` block for a pattern that only your application has.

## Rules

The router ships with built-in rules. Each rule has an id such as `vh-sqli-001`, and each is turned off with `disable_rule` if it does not fit your application.

| Category | Examples |
|----------|---------|
| **SQL injection** | `UNION SELECT` in a query string, a quote with a tautology, a stacked `DROP` |
| **XSS** | A `<script` tag in a query string, a `javascript:` URL, an inline event handler |
| **Path traversal** | `../` sequences in a query string or the path, `etc/passwd`, `win.ini` |
| **Command injection** | A shell separator followed by `cat`, `id` or `whoami`, a `$(` substitution |
| **File inclusion** | PHP stream wrappers such as `php://filter`, a remote URL in a `file` or `page` parameter |
| **SSRF** | The cloud metadata address `169.254.169.254`, `gopher://` and `file://` URLs in a query string |
| **Template and expression** | The Log4Shell lookup `${jndi:`, the `{{7*7}}` probe |
| **XML external entities** | An entity declared with `SYSTEM` in a request body |
| **Known scanners** | The user agent of sqlmap, nikto, nuclei, masscan and similar tools |

[View all built-in rules →](/builtin-rules)
