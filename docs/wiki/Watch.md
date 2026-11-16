# Watch: urgent alerts without the AI

*Since 0.10.0.* Two loops with different jobs:

| | The watch | The AI round |
|---|---|---|
| When | every few minutes (default 5) | once or twice a day, at the times you set |
| How it decides | local rules — **no model is called** | the model reviews the whole period |
| What it does | notifies at once: "rule-based alert — not reviewed by AI" | one verdict per watch event, findings, tuning suggestions |
| Cost | none | one model call per round |

The watch is **off** until an administrator switches it on in **Settings → Watch** (`/e/<env>/settings`).

## What counts as urgent

| Trigger | Fires when | Tune with |
|---|---|---|
| Critical level | an alert at or above `critical_level` (default 12; level 15+ is *critical*) | level |
| Watched rule | any alert of a rule in the list (default: the environment's `watch_rules`) | list |
| Watched group | an alert of a watched group at or above `group_min_level` (default 10) | list, level |
| Active Response | Wazuh executed an automatic action (`rule.groups: active_response`) | — |
| Login after failed attempts | a successful login from a source address with ≥ `brute_failures` failed logins in the `brute_window_minutes` before it — always *critical* | count, window |
| Sudden increase | alerts at `spike_min_level` (default 7) and above in one interval are ≥ `spike_factor` × their 7-day average and ≥ `spike_min` (default 50). The scan groups (`syscheck`, `sca`, `vulnerability-detector`, `rootcheck`, `syscollector`, `ciscat`, `oscap`) do not count. The message names the rules behind the burst | factor, minimum, level, groups |
| Unusual outbound transfer (off by default) | a Kubernetes workload sent ≥ `egress_min_mb` (default 500 MB) out of its pods in one interval and ≥ `egress_factor` (default 5) × its 7-day average. Needs a Prometheus source; see [below](#unusual-outbound-transfer) | factor, MB, namespaces |
| Agents lost | an agent disconnected for more than `agent_minutes` (`ignore_agents` are skipped; 5 or more at once is *critical*). The first scan after a start only learns the current state | minutes |

## Sorting out

Before anything is sent, an event is dropped from the notification (it is still recorded and still judged
by the AI) when

- its key is in the **mute** list (an exact key, a prefix ending in `*`, or `rule:<id>`),
- its rule is an active **baseline** entry in the knowledge base (never for critical events),
- the same key was announced within `repeat_hours` (default 6) — the count on the existing event goes up,
- it is a **recurring burst**: a sudden increase whose rules already produced a burst of at least half the size
  in a window of the same length during the last 7 days (scheduled jobs, nightly batches),
- it is a **recurring transfer**: an outbound transfer the same workload already made at half the size or more in
  a window of the same length during the last 7 days (backups, sync and export jobs).

### Why the sudden increase works this way

Counting every alert made the trigger fire on scheduled work: a registry scan on a Windows desktop (rules
750–752, level 5, thousands in a minute), the vulnerability detector closing CVEs after an update (23502, level
3), an SCA run (19007) or rootcheck. None of these is an attack, and the old message did not even say which rule
it was. Now only alerts that matter count, scans are left out, the 7-day average replaces the 24 h one, the event
key is the main rule (`spike:<rule id>`) so it can be muted or filed as baseline like any other rule, and a burst
the same rules already did this week stays on the watch page without a notification. To get the old behaviour
back, set the level to 0 and the groups to `-`.

### Unusual outbound transfer

A data leak rarely raises a Wazuh alert of its own: a stolen token or a compromised application simply sends a
lot of data out. This trigger watches that volume. Every interval it reads cAdvisor's
`container_network_transmit_bytes_total` from the environment's Prometheus source, sums it per namespace and
**workload** (the pod name without its ReplicaSet or DaemonSet suffix, so a rollout keeps its history; StatefulSet
pods stay separate) and compares the window with the 7-day average of the same workload. The event names the
workload, the volume and the factor, for example *erp/odoo sent 900 MB out in 5 min — 450× its 7-day average
(2.0 MB)*; its key is `egress:<namespace>/<workload>`, so it can be muted like any other event.

What it does not do:

- **It never looks at content.** A backup, a sync job and a leak look the same; the AI round and a human decide.
- **It counts the pod's whole interface**, so traffic to other pods (databases, object storage, replication)
  counts too. Cluster plumbing namespaces are left out by default (`kube-system`, `longhorn-system`,
  `cattle-*`, `monitoring`, `logging`, `calico-system`, `tigera-operator`, `cert-manager`); add yours, or `-` to
  leave out nothing.
- **Pods with `hostNetwork`** report the node's traffic or none, and traffic outside Kubernetes is not seen.

Turn it on in Settings → Watch. It stays off by default and the checkbox is disabled without a
`sources.prometheus` entry. Start with the defaults: on a busy cluster, a burst that already happened this week
(Kafka rebalancing, nightly backups) is kept silent as recurring.

## Channels and quiet hours

The watch uses the channels you tick, **among those defined in the configuration file**; addresses, tokens
and webhook URLs are never entered in the UI. During quiet hours nothing is sent except — if you leave that
option on — critical events; everything held back goes out as one message when the quiet period ends.

## The AI round

The scheduled run gets every event without a verdict in one request and answers with `event_verdicts`:
`real_incident`, `investigate`, `expected` or `noise`, each with a reason. It may add a suggestion — mute this
event key, or change one threshold. **A suggestion changes nothing**: it appears in Settings → "AI suggestions
for the watch", where an administrator accepts or dismisses it. Accepting is written to the audit trail.

Set the round times in **Settings → AI round** (one or two a day). Empty means: use `schedule` from the
configuration file. Manual runs ("Run now") and incident drafts are not limited.

## Where things are stored

`<prefix>-events` holds the events and verdicts, `<prefix>-settings` the settings document and small state
(scan cursor, known disconnected agents). Events older than 180 days are pruned (`backup.keep_events_days`).

## Trying it out

Switch the watch on with the defaults, leave quiet hours off for a week, and read the verdicts on the Watch
page after each AI round. Accept the mute suggestions that are right; raise a threshold when a trigger fires
daily for something you already know.

See also: [Backup](Backup) · [Configuration](Configuration) · [Features](Features)

---

[English](Watch) · [Türkçe](Watch-TR)
