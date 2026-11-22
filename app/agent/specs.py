# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The tool definitions (JSON schemas) the model and MCP clients see; the implementations are in ``tools.py``."""
from __future__ import annotations

from ..store import KNOWLEDGE_KINDS

TIME_PROPS = {
    "from": {"type": "string", "description": "Start: ISO-8601 or OpenSearch date math (now-24h). Default now-24h"},
    "to": {"type": "string", "description": "End: ISO-8601 or now. Default now"},
}
FILTER_PROPS = {
    "query": {"type": "string", "description": "Optional Lucene query_string, e.g. data.srcip:192.0.2.10 AND rule.groups:sshd"},
    "rule_ids": {"type": "array", "items": {"type": "string"}, "description": "Rule ID filter"},
    "agent": {"type": "string", "description": "Agent name (agent.name) filter"},
    "min_level": {"type": "integer", "description": "Minimum rule.level"},
    **TIME_PROPS,
}


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


LABELS = ["real_incident", "investigate", "detection_gap", "false_positive", "baseline_increase",
          "measurement", "expected", "correction"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]

FINDING = _obj({
    "label": {"type": "string", "enum": LABELS,
              "description": "real_incident=confirmed or very likely incident; investigate=evidence insufficient; "
                             "detection_gap=something that should alert but does not; false_positive=noise, "
                             "level-lowering candidate; baseline_increase=known noise with abnormal volume; "
                             "measurement=result of a watched rule/metric; expected=explained/verified; "
                             "correction=corrects an earlier assessment"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "title": {"type": "string", "description": "One-line title"},
    "detail": {"type": "string", "description": "Evidence and reasoning (markdown, short)"},
    "evidence": {"type": "array", "items": {"type": "string"}, "description": "Concrete numbers / times / IPs"},
    "rule_ids": {"type": "array", "items": {"type": "string"}},
    "agents": {"type": "array", "items": {"type": "string"}},
    "mitre": {"type": "array", "items": {"type": "string"},
              "description": "MITRE ATT&CK technique ids the evidence supports, e.g. T1110.001 (optional)"},
    "recommendation": {"type": "string", "description": "Recommended manual action or next step"},
    "rule_draft_xml": {"type": "string", "description": "Optional Wazuh rule draft (XML). Also propose it as a rule_draft so the user can approve it."},
    "manual_checks": {"type": "array", "description":
        "Checks only a human can do on hosts you cannot reach (log greps, config/service state, who logged in). "
        "Exact READ-ONLY commands, one host each. Omit when the indexer data is enough.",
        "items": _obj({"host": {"type": "string", "description": "agent/host name"},
                       "purpose": {"type": "string", "description": "what the output will tell us"},
                       "command": {"type": "string", "description": "read-only shell command (sudo allowed)"}},
                      ["host", "command"])},
}, ["label", "severity", "title", "detail"])

SPECS: dict[str, dict] = {
    "search_alerts": {"name": "search_alerts", "description":
        "Search the alerts index; returns compact events (max 25). Use it to look at raw samples.",
        "parameters": _obj({**FILTER_PROPS, "size": {"type": "integer"},
                            "oldest_first": {"type": "boolean"}})},
    "aggregate_alerts": {"name": "aggregate_alerts", "description":
        "Count filtered alerts by a field (terms). Fields: rule.id, agent.name, data.srcip, data.url, "
        "data.id (HTTP status), rule.groups, data.srcuser, data.dstuser, syscheck.path, location, decoder.name, "
        "data.user.username, data.verb, data.objectRef.resource ... Optional sub_field for a second split.",
        "parameters": _obj({**FILTER_PROPS, "field": {"type": "string"}, "sub_field": {"type": "string"},
                            "size": {"type": "integer"}}, ["field"])},
    "rule_timeline": {"name": "rule_timeline", "description":
        "Time distribution (date_histogram) of matching alerts. Use it BEFORE interpreting a rule's volume.",
        "parameters": _obj({**FILTER_PROPS, "interval": {"type": "string", "description": "10m, 1h, 1d"}})},
    "ip_profile": {"name": "ip_profile", "description":
        "Profile of one IP or a prefix ('203.0.113.' / '2001:db8:0:'): rules, HTTP codes, distinct paths, "
        "users, timeline, samples.",
        "parameters": _obj({"ip": {"type": "string"}, "interval": {"type": "string"}, **TIME_PROPS}, ["ip"])},
    "correlate_around": {"name": "correlate_around", "description":
        "Other alerts within ±N minutes (default 30) of a timestamp, optionally on the same agent.",
        "parameters": _obj({"timestamp": {"type": "string"}, "agent": {"type": "string"},
                            "minutes": {"type": "integer"}, "min_level": {"type": "integer"}}, ["timestamp"])},
    "vulnerabilities": {"name": "vulnerabilities", "description":
        "Vulnerability state index summary (severity, top CVEs, packages); optional agent/severity filter.",
        "parameters": _obj({"agent": {"type": "string"}, "severity": {"type": "string"}, "size": {"type": "integer"}})},
    "agent_info": {"name": "agent_info", "description":
        "Agent details from the Wazuh API (status, version, OS, last keepalive) plus a 24 h alert summary.",
        "parameters": _obj({"agent": {"type": "string", "description": "agent name or id"}}, ["agent"])},
    "rule_info": {"name": "rule_info", "description": "Rule definitions (level, description, file, groups, conditions).",
        "parameters": _obj({"rule_ids": {"type": "array", "items": {"type": "string"}}}, ["rule_ids"])},
    "logtest": {"name": "logtest", "description":
        "Run a log line through the manager's CURRENT ruleset (wazuh-logtest API) and see which decoder/rule/level "
        "matches. Cannot test a new draft rule (it is not loaded).",
        "parameters": _obj({"event": {"type": "string"}, "log_format": {"type": "string"},
                            "location": {"type": "string"}}, ["event"])},
    "validate_rule_xml": {"name": "validate_rule_xml", "description":
        "Check a rule draft for XML syntax, OS_Regex pitfalls, rule ID collisions and whether the new rule IDs are "
        "inside the environment's allowed range (returned as allowed_id_range; list_environments shows it too). "
        "On a range error it returns suggested_id. Never applies it.",
        "parameters": _obj({"xml": {"type": "string"}}, ["xml"])},
    "simulate_rule": {"name": "simulate_rule", "description":
        "Replay a child-rule draft (if_sid) against the last N days of real alerts: estimated alerts/day it would "
        "take over, how many were at or above the high level, affected agents/IPs/locations, matched and "
        "unmatched examples. Use it before proposing a rule_draft and put the numbers in the proposal body.",
        "parameters": _obj({"xml": {"type": "string"}, "days": {"type": "integer", "description": "1-30, default 14"}},
                           ["xml"])},
    "propose_knowledge": {"name": "propose_knowledge", "description":
        "Add a PROPOSAL to the knowledge base (baseline, decision, open item, lesson, rule draft). It has no "
        "effect until the user approves it. Only for durable, reusable knowledge. For kind=rule_draft put the full "
        "<group> XML in `xml` and two-way test events in `tests`; new rule IDs MUST be inside the environment's "
        "rule_id_range (list_environments / validate_rule_xml), otherwise the draft is refused with a suggested_id.",
        "parameters": _obj({"kind": {"type": "string", "enum": [k for k in KNOWLEDGE_KINDS if k != "answer"]},
                            "title": {"type": "string"}, "body": {"type": "string"},
                            "rule_ids": {"type": "array", "items": {"type": "string"}},
                            "xml": {"type": "string", "description": "rule_draft only: complete <group>...</group> XML"},
                            "tests": {"type": "array", "description": "rule_draft only: logtest events", "items": _obj({
                                "event": {"type": "string"}, "log_format": {"type": "string"},
                                "location": {"type": "string", "description": "original location (log file path)"},
                                "expect": {"type": "string", "enum": ["match", "no_match"]}}, ["event", "expect"])}},
                           ["kind", "title"])},
    "prom_query": {"name": "prom_query", "description":
        "Prometheus instant query (PromQL), e.g. node disk usage, pod restarts, up{job=...}. Read-only.",
        "parameters": _obj({"expr": {"type": "string"}, "time": {"type": "string", "description": "ISO-8601 or now-1h"},
                            "cluster": {"type": "string", "description": "cluster name when the environment has "
                                        "several (list_environments → clusters); empty = the first"}},
                           ["expr"])},
    "prom_range": {"name": "prom_range", "description":
        "Prometheus range query: min/max/last and up to 60 sampled points per series (max 20 series).",
        "parameters": _obj({"expr": {"type": "string"}, "from": {"type": "string"}, "to": {"type": "string"},
                            "step": {"type": "string", "description": "e.g. 60s, 5m"},
                            "cluster": {"type": "string", "description": "cluster name; empty = the first"}}, ["expr"])},
    "prom_alerts": {"name": "prom_alerts", "description":
        "Alerts the cluster's own Prometheus is firing right now (KubePodCrashLooping, TargetDown, disk filling up, "
        "certificates …), grouped by alert name and severity with namespaces, targets, start time and summary. "
        "Correlate them with Wazuh alerts of the same hosts and time.",
        "parameters": _obj({"cluster": {"type": "string", "description": "one cluster; empty = all clusters"}})},
    "loki_query": {"name": "loki_query", "description":
        "Loki LogQL query over a time range: log lines (newest first, max 500) or a metric query "
        "(count_over_time …). Always use a label selector, e.g. {namespace=\"wazuh\"} |= \"error\".",
        "parameters": _obj({"query": {"type": "string"}, "from": {"type": "string", "description": "ISO-8601 or now-2h"},
                            "to": {"type": "string"}, "limit": {"type": "integer"},
                            "oldest_first": {"type": "boolean"}}, ["query"])},
    "loki_labels": {"name": "loki_labels", "description": "Loki label names, or the values of one label (name).",
        "parameters": _obj({"name": {"type": "string"}})},
    "k8s_get": {"name": "k8s_get", "description":
        "Read-only Kubernetes listing: pods (phase, restarts, last termination reason), nodes (Ready, pressure, "
        "kernel), events (newest first), deployments/statefulsets/daemonsets/replicasets, jobs/cronjobs, "
        "services, ingresses, pvcs, namespaces. Secrets and configmaps are never available.",
        "parameters": _obj({"kind": {"type": "string"}, "namespace": {"type": "string"}, "name": {"type": "string"},
                            "label_selector": {"type": "string"}, "field_selector": {"type": "string"},
                            "limit": {"type": "integer"}}, ["kind"])},
    "k8s_logs": {"name": "k8s_logs", "description":
        "Last lines of a pod's log (tail ≤ 1000; previous=true for the crashed container).",
        "parameters": _obj({"namespace": {"type": "string"}, "pod": {"type": "string"}, "container": {"type": "string"},
                            "tail": {"type": "integer"}, "previous": {"type": "boolean"},
                            "since_seconds": {"type": "integer"}}, ["namespace", "pod"])},
    "list_reports": {"name": "list_reports", "description": "List of recent daily triage reports.",
        "parameters": _obj({"size": {"type": "integer"}})},
    "get_report": {"name": "get_report", "description": "A full report (the last successful one if run_id is omitted).",
        "parameters": _obj({"run_id": {"type": "string"}})},
    "knowledge": {"name": "knowledge", "description": "Knowledge base entries (baseline, decisions, open items...).",
        "parameters": _obj({"kinds": {"type": "array", "items": {"type": "string"}},
                            "status": {"type": "array", "items": {"type": "string"}}})},
    "submit_report": {"name": "submit_report", "description":
        "Submit the daily diagnostic report. The LAST step of the run. Keep it compact so it fits the output "
        "limit: at most 10 findings, each `detail` a few sentences.",
        "parameters": _obj({
            "summary_md": {"type": "string", "description": "2-6 sentence executive summary (markdown): volume, is there real risk, what awaits approval."},
            "health_assessment": {"type": "string", "description": "One paragraph on infrastructure health (SIEM flow, agents, disk)."},
            "findings": {"type": "array", "items": FINDING},
            "questions": {"type": "array", "description": "Questions for the user (e.g. 'Was this SSH login yours?'). Answers become context for the next run.",
                          "items": _obj({"question": {"type": "string"}, "why": {"type": "string"}}, ["question"])},
            "open_items": {"type": "array", "items": {"type": "string"}, "description": "Still open / to measure next run"},
            "closed_items": {"type": "array", "items": {"type": "string"}, "description": "Open items from the knowledge base that this run shows as closed (use their titles)"},
            "event_verdicts": {"type": "array", "description":
                "One entry per watch event listed in the request (only when that section is present).",
                "items": _obj({
                    "event_id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["real_incident", "investigate", "expected", "noise"]},
                    "reason": {"type": "string", "description": "One or two sentences with the evidence"},
                    "suggestion": _obj({
                        "mute": {"type": "boolean", "description": "true = stop announcing this exact event key"},
                        "param": {"type": "string", "enum": ["critical_level", "group_min_level", "brute_failures",
                                                             "spike_factor", "spike_min", "spike_min_level", "agent_minutes",
                                                             "egress_factor", "egress_min_mb"]},
                        "value": {"type": "number"},
                        "why": {"type": "string"}}),
                }, ["event_id", "verdict"])},
        }, ["summary_md", "findings"])},
}
