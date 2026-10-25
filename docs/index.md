---
layout: home

hero:
  name: vigilant-heron
  text: Screen web requests before they reach your sites
  tagline: A reverse-proxy router with nginx-style configuration. It checks each request with limits, an access list, rules and a typed decision model, then blocks, redirects or forwards it.
  image:
    src: /logo.svg
    alt: vigilant-heron
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: Configuration
      link: /configuration

features:
  - title: Decision models
    details: Jev (the default) and Clef answer typed questions about each request, and a small JSON protocol lets you run your own model. Thresholds decide what counts as an attack.
  - title: nginx-style configuration
    details: Directives, blocks and includes follow nginx syntax. Limits, timers, log formats and location blocks use nginx's names and defaults, and a bad value fails with its file and line.
  - title: Rules and built-in signatures
    details: Deterministic rules run before the model and cannot be overridden by it. Twenty-four built-in signatures cover SQL injection, XSS, traversal, command injection and scanners.
  - title: Limits
    details: limit_req and limit_conn zones throttle requests per client, site or path before the body is read, with dry-run mode for trying a limit out.
  - title: Logging
    details: One access line per request in JSON or a format you define, sent to stdout, a file or syslog. Every value is escaped, and credential headers can never reach the log.
  - title: Timeouts and failure settings
    details: Client, upstream and body timers follow nginx. Choose whether a rate-limited or failed decision allows or blocks the request, and mark paths that must always block.
  - title: Evaluation
    details: The labelled-dataset measurements of both models and of the built-in rules are published with their method and their caveats.
---
