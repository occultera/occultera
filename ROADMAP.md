# Roadmap

> Also on the website: https://occultera.dev/roadmap/ (5 languages) and in the wiki. Source of truth: `src/roadmap_data.py` in the occultera.dev repository.

What Occultera does today, what is being built and what comes next. Wazuh 4.x stays fully supported; Wazuh 5.x support arrives with 1.0, after Wazuh 5.0 is generally available.

Current release: **0.18.0** · Updated 2026-11-23

## ✅ Shipped

| Item | What it gives you |
|---|---|
| **MCP server for Wazuh** | Claude Desktop, Cursor, VS Code or any MCP client investigates with read-only tools and live data. |
| **AI alert triage with your own model** | Claude, OpenAI, Gemini, DeepSeek or a local model (Ollama, vLLM): one report with evidence, questions and rule drafts. |
| **GDPR / KVKK masking** | Detected personal data is pseudonymised before the AI and every MCP client; secrets are removed. |
| **Urgent-alert watch without an AI call** | Critical alerts, login after failures, spikes, silent agents, unusual outbound transfer — within minutes. |
| **Rule drafts you can trust** | Replayed on two weeks of real alerts, logtest in both directions, deployment with rollback, live verification. |
| **Cluster pulse** | Prometheus and Thanos, several Kubernetes and OpenShift clusters per Wazuh, firing alerts explained by AI. |
| **Monthly audit report and PDF** | Volume, decisions, rule changes, outages, agent coverage, vulnerability SLA — ISMS evidence. |
| **Helm, Kustomize, Docker Compose; signed images** | One container, no extra database, read-only file system; release images signed with cosign, SBOM per build. |
| **Internal groundwork for Wazuh 5 (0.17)** | A schema layer between Occultera and Wazuh; 4.x queries unchanged, checked against a golden report. |
| **AI round without an API key** | Run the daily review in an MCP client (daily_review prompt) or paste a masked brief into Gemini, ChatGPT or Claude and upload the answer. |
| **Indexer health with advice** | Heap, circuit breaker (“Data too large”), shards per GB of heap, unassigned shards — with what to do. |
| **Wazuh version detection** | The connection test shows the Wazuh version; a 5.x server is recognised and explained. |
| **Error reports and anonymous usage data** | On by default, switch off in Settings; structured data only, never alert or log content; open-source collector. |
| **Rule migration tool (preview): custom 4.x XML → Sigma** | Converts simple rules, lists what needs a person, maps fields, checks matches on sample events. Usable on its own. |
| **ISO 27001 Annex A mapping in the audit report** | Each section of the monthly report linked to the controls it evidences. |

## ⬜ Next (0.19)

| Item | What it gives you |
|---|---|
| **Public demos for Wazuh 4.x and 5.x** | demo.occultera.dev on 4.x data and demo5.occultera.dev as a 5.x preview. |

## ⬜ Towards 1.0

| Item | What it gives you |
|---|---|
| **Wazuh 5.x support — Occultera 1.0** | Findings, events and states through the version adapter; severity mapping; Sigma drafts on 5.x. After Wazuh 5.0 is generally available. |
| **Decoder drafts; PagerDuty and Opsgenie** | New log sources next to rule drafts; on-call escalation of real incidents. |

Missing something? Open an issue or write to hello@occultera.dev · https://github.com/occultera/occultera/issues · https://occultera.dev/roadmap/

## Earlier releases

- v0.10.0 — the watch (rule-based alerts without the AI), AI-round verdicts, settings page, masking profile,
  encrypted backup/restore with S3, storage safety checks, per-environment pseudonyms, proxy verification.
- v0.5.0 — mail saturation, coverage, vuln SLA, live verification, promotion package, monthly audit report.
- v0.6.0 — MCP server, Prometheus/Loki/Kubernetes tools, anomalies, incident drafts, evaluation.
- v0.6.1 — CodeQL fixes, defusedxml, bounded regexes, safe language cookie.
- v0.6.3 — Slack/Discord/webhook/ntfy notifications, Spanish & German UI, Helm chart + chart publishing, Jira,
  PDF export, read-only viewer role, dependency audit + SBOM.
