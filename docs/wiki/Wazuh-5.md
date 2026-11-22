# Wazuh 5

**For:** anyone running Wazuh who plans to move to 5.x. **Status:** planned for Occultera **1.0**. Wazuh 4.x stays
fully supported; nothing on this page changes a running installation.

> Based on the Wazuh 5.0 release candidates (rc1/rc2, October–November 2026). This page is revised when 5.0 is
> generally available.

## What changes in Wazuh 5.0

| | Wazuh 4.x | Wazuh 5.0 | What it means for Occultera |
|---|---|---|---|
| Alerts | `wazuh-alerts-4.x-*` | events in `wazuh-events-v5-*`, detections in `wazuh-findings-v5-*`, state in `wazuh-states-*` | collection, the watch and the MCP tools read new indices |
| Field names | `rule.level`, `rule.description`, `agent.name`, `data.srcip` | Wazuh Common Schema: `wazuh.rule.level`, `wazuh.rule.title`, `wazuh.agent.name`, `source.ip` | every query goes through a field map |
| Severity | a number, 0–16 | informational, low, medium, high, critical | thresholds and charts use categories |
| Detection | XML rules on the manager | Sigma-compatible detectors in the indexer | rule drafts become Sigma drafts |
| Custom XML rules | yes | not migrated automatically | see the migration tool below |
| Rule test | `wazuh-logtest`, API `/logtest` | moved to the dashboard and API | two-way logtest is 4.x only for now |
| Rule ID | a number (5710) | a UUID | the noise map and the knowledge base key on rule ID and title |
| Manager paths | `/var/ossec`, `ossec.conf` | `/var/wazuh-manager`, `wazuh-manager.conf` | promotion scripts |
| Indexer | OpenSearch 2.x | OpenSearch 3.x | queries are tested on both |

## The plan

1. **Version adapter** (in progress). The Wazuh-facing code moves behind one interface with a 4.x and a 5.x
   implementation. Occultera detects the version from the Wazuh API and the index patterns; `wazuh_version: 4 | 5`
   in the environment overrides it. Reports, the watch, the dashboard and the MCP server look the same on both.
2. **Severity mapping.** Wazuh publishes no mapping between 4.x levels and 5.x severities. Occultera's default,
   configurable per environment:

   | 4.x level | 5.x severity |
   |---|---|
   | 0–3 | informational |
   | 4–6 | low |
   | 7–9 | medium |
   | 10–12 | high |
   | 13–16 | critical |

3. **Sigma drafts on 5.x.** On 4.x the AI drafts XML rules you validate, test and deploy (see
   [Rule lifecycle](Rule-Lifecycle)). On 5.x it drafts Sigma rules; deployment through the Wazuh content API
   follows when that API is stable.
4. **Rule migration tool** (planned, preview before 1.0), described below.
5. **Wazuh 5.x support in 1.0**, after Wazuh 5.0 is generally available.

## Migration tool for custom 4.x rules

Usable inside Occultera or alone, without the rest of the application.

| Input | Output |
|---|---|
| `local_rules.xml` and other custom rule files | Sigma rules for the rules that convert cleanly |
| custom decoders, CDB lists | a "needs a person" list with the reason per rule |
| optional: sample events | a match check per rule: the 4.x rule and the Sigma rule on the same events |
| your watch rules | the same rules with 4.x field names mapped to the Wazuh Common Schema |

Converted automatically: field matches, `match` / `regex`, groups, level → severity, MITRE ATT&CK.
Listed for review: `if_sid` / `if_matched_sid` chains, `frequency` / `timeframe`, CDB lists, `overwrite="yes"`
rules, regex dialect differences. Custom decoders are reported, not converted, in the first version.

### Try the preview (1.0 branch)

```sh
docker run --rm -v "$PWD:/w" -w /w ghcr.io/occultera/occultera:1.0-preview \
  python -m app.migrate /w/local_rules.xml --events /w/alerts.jsonl --out /w/migrate-out --json
```

`migrate-out/` gets one Sigma file per convertible rule (`wazuh-<id>.yml`; rules with `frequency` also carry a
Sigma *correlation* draft), `report.md` with the status, the review reasons and the match check per rule, and the
field map. `--events` takes 4.x alert documents, one JSON object per line — for example an export of a day of
`wazuh-alerts-4.x-*`; each event goes through the 4.x rule and the Sigma rule and the report shows where they agree.
Rules whose parent (`if_sid`) is in the same file get the parent's conditions inlined; a stock parent is listed for
review. Field names follow the 5.0 release candidates and are re-checked at GA.

## What you can do now

- Stay on Wazuh 4.x in production; 5.0 is a migration, not an in-place upgrade.
- Keep custom rules in `local_rules.xml` or dedicated files with your own ID range, so the migration tool can find
  them.
- Running a 5.0 test system and willing to try a preview? Write to hello@occultera.dev.
- Follow [releases](https://github.com/occultera/occultera/releases) and the
  [CHANGELOG](https://github.com/occultera/occultera/blob/main/CHANGELOG.md).

See also: [Compatibility](Compatibility) · [Upgrade](Upgrade) · [Türkçe](Wazuh-5-TR)
