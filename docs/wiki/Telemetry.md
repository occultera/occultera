# Error reports and usage data

**For:** anyone running Occultera who wants to know what leaves the installation. *(1.0)*

Occultera sends **crash reports** and, once a week, **which versions and features are in use**. It is on by default
and you switch it off with one setting. The reason: to fix crashes we never hear about, and to see how fast
installations move to Wazuh 5.x.

## Levels

| `TELEMETRY` | What is sent |
|---|---|
| `errors+usage` (default) | crash reports and a weekly usage ping |
| `errors` | crash reports only |
| `off` | nothing |

The public demo (`WDT_PUBLIC_DEMO`) never sends anything. If outbound HTTPS is blocked, sending fails silently;
nothing else is affected. **Settings → About → Error reports and usage data** shows the level and exactly what an
event looks like.

## What a crash report contains

| Field | Example |
|---|---|
| exception class | `KeyError` |
| error category | `internal`, `timeout`, `auth` … (the same categories MCP clients see) |
| frames inside the application | `app.collector.core:collect`, `app.agent.tools:call` — module and function only |
| fingerprint | hash of the class and the last five frames, used to group repeats |
| versions | Occultera, Python, how it was installed (`helm`, `kustomize`, `compose`) |
| installation id | 16 hex characters derived from your secret salt — not reversible; `TELEMETRY_ID` changes it |

**Never sent:** the exception message, log lines, alert or report content, IP addresses, host, agent or user names,
file paths, URLs, model names, keys or tokens. The event is checked against a fixed list of keys before it is sent;
an event with any other key is dropped. The same crash is sent at most once a day, at most 20 reports a day.

## What the weekly usage ping contains

Occultera version, Wazuh versions of the environments (from the Wazuh API), number of environments, LLM provider
*type* (`anthropic`, `openai`, `none` … — never the model or endpoint), installation type and yes/no flags: MCP,
Prometheus, Loki, Kubernetes, masking, rule deployment, SSO.

## Where it goes

`https://telemetry.occultera.dev/v1/events` — a Cloudflare Worker with a D1 database. It accepts only these two
event shapes, stores no IP address or request header, deletes rows after 90 days and opens one GitHub issue
(label `crash`) per new crash fingerprint. Its source is public (`occultera/telemetry`).
Point `TELEMETRY_URL` elsewhere to run your own collector.

## Report a problem yourself

**Settings → About → Report a problem yourself** opens a GitHub issue form (`crash`). Paste masked log lines only.
