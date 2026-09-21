# Agentic Firewall v2

A small, deterministic security gateway between an AI agent (MCP client) and an MCP server, plus a red-team
benchmark that attacks it. No LLM makes any security decision.

```
Agent -> MCP client -> [ authn -> rate limit -> risk -> RBAC -> integrity -> input scan
                         -> circuit breaker -> MCP server -> output scan -> audit ] -> Agent
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

pytest                         # 176 tests
python benchmark/run.py        # red-team benchmark (attacks + benign controls)

python -m app.main create-user alice analyst     # prints an API key once
python -m app.main create-user root admin
python -m app.main serve                         # http://127.0.0.1:8000/docs
```

Use a real MCP server instead of the in-process demo: `FIREWALL_UPSTREAM=stdio python -m app.main serve`
(spawns `python -m app.mcp.server`, the demo tools served through the official SDK).

Typical flow: admin logs in -> `POST /api/tools/approve` (pins each tool's SHA-256) -> agents log in ->
`POST /api/request {"tool": ..., "arguments": {...}}` with header `X-Session-Id`.

## What each layer defends against

| Layer (file) | Threat | Mechanism |
|---|---|---|
| authentication.py | anonymous / forged / stale callers | API key -> random session id (only its hash is stored), TTL, revocation; role is read server-side, never from the client |
| rate_limiter.py | hammering, brute-forced logins | per-user sliding window; separate per-client limiter on login |
| risk.py | over-powered tools | name-based LOW/MEDIUM/HIGH/CRITICAL, overridable in YAML |
| authorization.py | unauthorized tools, privilege escalation | exact-name allowlist per role **and** a max risk per role; deny by default, no wildcards |
| integrity.py | rug pulls, tool poisoning, unapproved tools | SHA-256 over name+description+schema+annotations+extras; any change or never-approved -> block; poisoned definitions refused at approval |
| scanner.py | prompt injection, secret exfiltration, command injection | regex rules on arguments (in), responses (out), tool metadata; Unicode-normalised; findings never echo matched text |
| circuit_breaker.py | cascading failure | per-tool CLOSED/OPEN/HALF_OPEN |
| audit.py | no visibility | every decision (incl. early denials) -> SQLite + logger; log-injection safe |

Design rules: fail closed (internal error = deny); nothing unscanned reaches the agent (non-text MCP content is replaced by a
placeholder); `GET /api/tools` only relays approved, unchanged, permitted tools so a poisoned description is never shown to an agent.

## Why the LLM isn't in the loop

The model is part of the untrusted system being protected. The security boundary (identity, permissions, fingerprints,
limits) is deterministic and testable; the scanner is a best-effort extra layer, not the foundation.

## Known limitations (read before trusting it)

- **The scanner is regex, not semantic.** Paraphrased or encoded (base64, URL-encoded, other-language) injections pass.
  RBAC, fingerprinting and rate limits do not depend on it; the scanner does. Expect false positives too (e.g. a news
  article that literally contains `.env` or "ignore previous instructions" is blocked on output).
- **The benchmark is a regression suite, not a security proof.** The attacks were written by the firewall's author.
  It also reports a false-positive rate on benign controls so "100% blocked" can't be achieved by blocking everything.
- Sessions, rate limits and breakers are per process (in-memory); run one worker or move them to shared storage.
- Fingerprints depend on what the SDK reports; after upgrading the `mcp` package, re-approve tools if they show `changed`.
- The definition is checked on each request but fetched separately from the call (tiny TOCTOU window).
- Login rate limit keys on the socket address; behind a reverse proxy configure trusted forwarded headers or it keys on the proxy.
- No TLS, request-size limit, or IP allowlisting: put it behind a reverse proxy.
- Argument values are not validated against the tool's JSON schema.
- All demo tools are simulated; nothing touches files, network or a shell.

## Layout

```
app/main.py                FastAPI + CLI          app/firewall/gateway.py   the request lifecycle
app/firewall/*             one file per layer     app/mcp/{client,server}.py  upstream adapters + demo server
app/models/*               pydantic models        app/storage/database.py     SQLite
app/config/policies.yaml   roles, risk, limits    attacks/  benchmark/  tests/
```
