# Roadmap

Where the project is going, roughly ordered by impact. This is a living document — ideas and PRs welcome
(see [CONTRIBUTING.md](CONTRIBUTING.md)). Status legend: ✅ shipped · 🚧 in progress · ⬜ planned.

## Reach & distribution

| Status | Item | Why |
|---|---|---|
| ✅ | **Helm chart** + a one-line install (published to a Helm repo, kind-tested in CI, Artifact Hub-ready) | most Wazuh users deploy with `wazuh-kubernetes`/Helm; a chart is the single biggest adoption lever. |
| ✅ | Docker Compose + Kubernetes (kustomize) | single container, read-only FS, non-root, no PVC. |
| ⬜ | Signed container images (cosign) + SLSA provenance (SBOM ✅ per build) | a requirement in enterprise evaluations. |
| ✅ | Multi-language UI (en, tr, es, de) | more languages = more users; the catalogue is tiny (`app/i18n.py`). |
| ⬜ | Interactive demo (one-click temporary deploy) | let people try it without a Wazuh of their own. |

## Integrations

| Status | Item | Why |
|---|---|---|
| ✅ | e-mail, Telegram, Microsoft Teams, Slack, Discord, generic webhook, ntfy | cover every team's channel. |
| ✅ | MCP server (`/mcp`) | Claude Desktop / any MCP client can investigate with live data. |
| ✅ | LLM providers: Anthropic, OpenAI, Azure OpenAI, Gemini, DeepSeek, Ollama/vLLM/LM Studio/LiteLLM | bring your own key, or run fully offline. |
| ✅ | Ticketing: **Jira**, Zammad (ServiceNow, GitLab/GitHub issues planned) | the incident-record draft already has a clean provider hook. |
| ⬜ | PagerDuty / Opsgenie | for on-call escalation of `real_incident` findings. |

## Product

| Status | Item | Why |
|---|---|---|
| ✅ | Deterministic collection → LLM triage → structured report → recommendation inbox → knowledge base. | the core loop. |
| ✅ | Rule drafts with validation, rollback and two-way logtest (opt-in deployment). | the differentiator. |
| ✅ | Live verification of deployed/promoted rules on real events. | "logtest passed" is not proof; real events are. |
| ✅ | Monthly audit report (ISMS evidence) + agent coverage + vulnerability SLA + mail saturation + anomalies. | regulatory story. |
| ✅ | **PDF export** of the monthly audit report (reportlab, Unicode-safe) | regulated customers want a printable artefact. |
| ⬜ | **Decoder drafts** next to rule drafts (validate + logtest + rollback). | onboarding new log sources. |
| ✅ | **Read-only viewer role** (`VIEWER_PASSWORD`) with a permission matrix and per-role environment allow-lists. | team deployments need role separation. |
| ⬜ | Embedded SVG time-series charts in reports. | readability + "wow" factor without a JS build step. |
| ⬜ | False-positive feedback loop polish: auto-baseline suggestions after N days unchanged. | turns decisions into automation. |

## Trust & security

| Status | Item | Why |
|---|---|---|
| ✅ | Read-only by default; separate least-privilege deploy user; prompt-injection-aware agent; strict CSP. | see [SECURITY.md](SECURITY.md). |
| ✅ | defusedxml (no DTD/entities), bounded regexes, signed session cookie, login throttling. | |
| ✅ | **CodeQL + dependency audit in CI** (fails on a known vulnerability), CycloneDX SBOM artifact, hash-chained audit trail, `/metrics`, production startup checks. | signals enterprise readiness. |
| ⬜ | Published eval results (`python -m app.eval`) per model in the README. | nobody else shows their numbers this openly. |

## Wazuh 5

Details: [Wazuh 5](https://github.com/occultera/occultera/wiki/Wazuh-5). Wazuh 4.x stays fully supported.
The current published release is 0.17.0. Items marked as 1.0 preview are present on the
`feat/1.0-wazuh-adapter` development branch and are not part of the 0.17.0 release.

| Status | Item | Why |
|---|---|---|
| 🚧 | **Version adapter (1.0 preview)**: the 4.x schema layer and version detection are implemented; the Wazuh 5 schema/field mappings, live validation and stable release remain | Wazuh 5 changes indices, field names, severities and the rule engine. |
| 🚧 | **Rule migration preview**: custom 4.x XML rules → Sigma, with a review list, field mapping and sample-event match check; run with `python -m app.migrate` | Custom XML rules are not migrated by Wazuh; every generated rule needs review. |
| 🚧 | **Annex A evidence summary (1.0 preview)** in the monthly audit report | Ten selected controls with evidence/gap status and references; this is supporting evidence, not certification. |
| 🚧 | **Error reports and anonymous usage data (1.0 preview)**; configurable with `TELEMETRY=off` or `TELEMETRY=errors`, no alert or log content | Helps identify crashes and supported Wazuh versions. |
| 🚧 | **AI review without an API key** and **Indexer health advice** are implemented on the preview branch | Use an MCP client or a chat model with a masked brief; health checks report actionable Indexer signals. |
| ⬜ | Public Wazuh 5 demo and a 4.x/5.x smoke-test matrix against real Wazuh | Verify behavior against real supported deployments. |
| ⬜ | **Wazuh 5.x production support — Occultera 1.0**, after Wazuh 5.0 is generally available | |
| ⬜ | Sigma rule drafts on Wazuh 5.x | Detection workflows must match the 5.x rule engine. |

## Earlier releases

- v0.10.0 — the watch (rule-based alerts without the AI), AI-round verdicts, settings page, masking profile,
  encrypted backup/restore with S3, storage safety checks, per-environment pseudonyms, proxy verification.
- v0.5.0 — mail saturation, coverage, vuln SLA, live verification, promotion package, monthly audit report.
- v0.6.0 — MCP server, Prometheus/Loki/Kubernetes tools, anomalies, incident drafts, evaluation.
- v0.6.1 — CodeQL fixes, defusedxml, bounded regexes, safe language cookie.
- v0.6.3 — Slack/Discord/webhook/ntfy notifications, Spanish & German UI, Helm chart + chart publishing, Jira,
  PDF export, read-only viewer role, dependency audit + SBOM.
