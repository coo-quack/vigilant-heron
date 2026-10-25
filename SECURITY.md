# Security

## Reporting

Report vulnerabilities privately to the maintainers of the coo-quack
organization. Do not open a public issue.

## Data Disclosure

For every request that is not skipped or blocked by a rule, the router sends
the request line, headers and up to `inspect_body_bytes` of the body to the
configured decision backend. It drops `Cookie`, `Authorization`,
`Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token` and any header listed in
`redact_headers`, and replaces the values of password-, token- and card-like
form and JSON fields with `[REDACTED]` before sending. Multipart
(`multipart/form-data`) bodies are only lexically redacted, so a sensitive field
inside one can still reach the backend in some layouts. Everything else, which
can include personal data typed into forms, reaches the backend. Point the
router at a backend you may disclose that data to, or run the decision model
yourself.

With `backend = "clef"`, the same sanitized event is sent to Cloudflare Workers
AI (`api.cloudflare.com`), a third party, as the `state` of a Clef request. The
bearer token is sent in the `Authorization` header to that endpoint only. Use
an account whose Workers AI data handling you have accepted, and keep the token
in the environment, not in the config file. The router never logs the token.

## Limits of the decision model

The model judges text written by the attacker. Payloads can try to steer it,
and it can miss attacks or flag legitimate requests. The router limits what a
steered model can do:

- Attacker-controlled data is sent under a separate `untrusted` field.
- Rule blocks (`deny_paths`) are decided before the model is called, so a
  model answer can never turn a rule block into an allow.
- Requests whose content addresses an AI model are a block signal of their own
  (`instruction_threshold`).

Keep a rule-based WAF in front of the router, start each site in `shadow`
mode, and switch to `enforce` only after measuring missed attacks and false
positives on real traffic.

## Failure behavior

When the backend times out or fails, requests are forwarded (fail-open),
except on `fail_closed_paths`, where they are blocked.
