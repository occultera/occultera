# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The configuration blocks an environment is made of: endpoints, sources, schedules, LLM, rule deployment."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .base import DAYS


class Endpoint(BaseModel):
    url: str
    username: str = ""
    password: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    # optional mutual TLS (client certificate authentication)
    client_cert: str | None = None
    client_key: str | None = None
    timeout: float = 30.0

    @property
    def verify(self):
        if self.ca_file:
            return self.ca_file
        return self.verify_tls

    @property
    def cert(self):
        if self.client_cert:
            return (self.client_cert, self.client_key) if self.client_key else self.client_cert
        return None



class LivenessCfg(BaseModel):
    """Quick health check every few minutes, without the LLM: notifies when Wazuh breaks and when it recovers."""
    enabled: bool = True
    interval_minutes: int = Field(10, ge=2, le=120)
    silence_minutes: int | None = None    # default: the environment's max_silence_minutes
    repeat_hours: float = 2               # remind while a problem persists
    notify_recovery: bool = True


class QueryLimitsCfg(BaseModel):
    """Hard limits for every query the AI (or an MCP client) can trigger.

    The model can only narrow or widen a window inside these bounds; field names are checked against an
    allow-list, so a prompt-injected instruction cannot turn into an expensive or arbitrary query.
    """
    max_range_hours: int = Field(24 * 14, ge=1, le=24 * 366)   # widest window per tool call
    max_buckets: int = Field(200, ge=10, le=10_000)            # date_histogram buckets per query
    max_terms_size: int = Field(50, ge=1, le=10_000)           # terms aggregation bucket count
    max_size: int = Field(25, ge=1, le=1_000)                  # documents returned
    min_interval: str = "1m"                                   # smallest histogram interval
    max_concurrent: int = Field(8, ge=1, le=64)                # parallel queries per environment
    request_timeout: float | None = Field(None, gt=0, le=600)  # overrides indexer.timeout when set
    extra_fields: list[str] = Field(default_factory=list)      # allow-listed fields on top of the built-ins

    @field_validator("min_interval")
    @classmethod
    def _interval(cls, v):
        if not re.fullmatch(r"\d+[smhdw]", v):
            raise ValueError("min_interval must look like 30s, 1m, 1h")
        return v


class PrivacyCfg(BaseModel):
    """Personal data (GDPR / KVKK). On by default since 0.10.1. ``mode: mask`` pseudonymises personal data in everything sent to the model
    (e-mail, phone, national IDs, IBAN, card, secrets; IPs per ``ips``) and maps it back in tool calls and reports.
    ``detect`` scans a sample of each window's alerts for personal data stored in clear text."""
    mode: Literal["off", "mask"] = "mask"            # 0.10.1: on by default (KVKK/GDPR); off only on purpose
    ips: Literal["keep", "public", "all"] = "keep"   # IPs are personal data under GDPR, but the analysis needs them
    kinds: list[str] = Field(default_factory=list)   # empty = all detectors (app/privacy.py KINDS)
    allow: list[str] = Field(default_factory=list)   # regexes never masked / reported (e.g. "noreply@example\\.com")
    detect: bool = True
    detect_sample: int = Field(default=1000, ge=0, le=5000)   # alerts scanned per run (0 = off)

    @field_validator("mode", mode="before")
    @classmethod
    def _mode(cls, v):   # YAML 1.1 reads a bare `off` / `on` as a boolean
        if isinstance(v, bool):
            return "mask" if v else "off"
        return str(v).lower()


class MailCfg(BaseModel):
    """The manager's e-mail limits (ossec.conf <global>). When set, each run shows the hours in which the alert mail
    channel was saturated and the alerts that may never have been mailed in those hours."""
    alert_level: int = 7          # email_alert_level
    max_per_hour: int = 12        # email_maxperhour (Wazuh default 12)


class VulnSlaCfg(BaseModel):
    """Days an active vulnerability may stay open, per severity (0 = not tracked)."""
    critical: int = 15
    high: int = 30
    medium: int = 90
    low: int = 0

    def days(self) -> dict[str, int]:
        return {k.capitalize(): v for k, v in self.model_dump().items() if v}


class PromoteCfg(BaseModel):
    """How a tested rule draft becomes a permanent rule in your own configuration management ("promotion package").

    mode `host`: the rules file lives on the manager host. mode `kubernetes`: the file is in a kustomize repo
    (e.g. wazuh-kubernetes) and is rolled out with `kubectl apply -k`.
    """
    mode: Literal["host", "kubernetes"] = "host"
    repo_dir: str = ""                    # kubernetes: repository root on the operator's machine
    rules_file: str = "/var/ossec/etc/rules/local_rules.xml"   # host: absolute; kubernetes: relative to repo_dir
    catalog_file: str = ""                # optional markdown alert catalogue (relative to repo_dir) — a § draft is generated
    kubeconfig: str = ""
    namespace: str = "wazuh"
    master_pod: str = "wazuh-manager-master-0"
    kustomize_dir: str = ""               # relative to repo_dir, e.g. k8s/wazuh
    manager_label: str = "app=wazuh-manager"   # pods that must become Ready again after the rollout


class SourceEndpoint(BaseModel):
    name: str = ""                        # Prometheus: the cluster's name when an environment has more than one
    url: str = ""
    username: str = ""
    password: str = ""
    bearer_token: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    timeout: float = 30.0
    org_id: str = ""                      # Loki multi-tenancy (X-Scope-OrgID)

    @property
    def verify(self):
        return self.ca_file or self.verify_tls


class KubernetesSource(BaseModel):
    """Read-only Kubernetes API (pods, nodes, events, workloads, pod logs; never secrets or configmaps)."""
    enabled: bool = False
    in_cluster: bool = True               # use the pod's service account (needs the rbac-readonly component)
    api_url: str = ""                     # when not in cluster
    token: str = ""
    verify_tls: bool = True
    ca_file: str | None = None
    namespaces: list[str] = Field(default_factory=list)   # optional allow-list; empty = all
    pod_logs: bool = True


class SourcesCfg(BaseModel):
    """Extra read-only data sources the AI can query next to Wazuh."""
    prometheus: SourceEndpoint | None = None
    # more clusters behind the same Wazuh (e.g. OpenShift Thanos Querier), each with a unique ``name``
    prometheus_extra: list[SourceEndpoint] = Field(default_factory=list)
    loki: SourceEndpoint | None = None
    kubernetes: KubernetesSource = Field(default_factory=KubernetesSource)

    @field_validator("prometheus", "loki", mode="before")
    @classmethod
    def _empty(cls, v):
        return None if isinstance(v, dict) and not v.get("url") else v

    @field_validator("prometheus_extra", mode="before")
    @classmethod
    def _extra(cls, v):
        return [x for x in (v or []) if not (isinstance(x, dict) and not x.get("url"))]

    @model_validator(mode="after")
    def _names(self):
        names = [self.prometheus.name or "default"] if self.prometheus else []
        for ep in self.prometheus_extra:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", ep.name or ""):
                raise ValueError(f"sources.prometheus_extra: every entry needs a name (a-z, 0-9, -): {ep.name!r}")
            names.append(ep.name)
        if len(names) != len(set(names)):
            raise ValueError(f"sources: Prometheus cluster names must be unique: {names}")
        return self

    def prometheus_names(self) -> list[str]:
        return ([self.prometheus.name or "default"] if self.prometheus else []) + [e.name for e in self.prometheus_extra]


class ZammadCfg(BaseModel):
    url: str = ""
    token: str = ""
    group: str = "Users"
    customer: str = ""                    # e-mail of the ticket customer
    verify_tls: bool = True


class JiraCfg(BaseModel):
    url: str = ""                         # https://<site>.atlassian.net (or a self-hosted base URL)
    email: str = ""                       # the account e-mail (basic auth user)
    token: str = ""                       # Jira Cloud API token / personal access token
    project: str = ""                     # project key, e.g. SEC
    issue_type: str = "Task"              # issue type name, e.g. Task / Incident
    verify_tls: bool = True


class IncidentCfg(BaseModel):
    """Incident record drafts from findings (e.g. ISO 27001 / ISMS-18 records)."""
    id_prefix: str = "INC-"
    template_file: str | None = None      # markdown skeleton the AI fills; default: built-in
    template: str | None = None           # … or the skeleton inline ({id} {title} {by} are filled in)
    zammad: ZammadCfg | None = None       # optional: open the draft as an internal Zammad ticket
    jira: JiraCfg | None = None           # optional: open the draft as a Jira issue

    @field_validator("zammad", "jira", mode="before")
    @classmethod
    def _z(cls, v):
        return None if isinstance(v, dict) and not v.get("url") else v


class RuleDeployCfg(BaseModel):
    """Optional: let "Approve and deploy" write approved rule drafts to the manager.

    Off by default. Uses a SEPARATE Wazuh API user whose only write rights are uploading custom rules files and
    manager/cluster restart (docs/rule-deployment.md); the application writes only the file below.
    """
    enabled: bool = False
    username: str = ""
    password: str = ""
    file: str = "wdt_rules.xml"          # in etc/rules on the manager (master node in a cluster)
    id_min: int = 100000                 # drafts outside this ID range are refused
    id_max: int = 119999
    restart_timeout: int = 180           # seconds to wait for the manager to come back
    # deployment gate (fail closed): a draft without logtest samples, or with a sample that cannot be
    # reproduced, is not deployed automatically. Set require_tests: true to enforce samples for every draft.
    require_tests: bool = False
    allow_inconclusive: bool = False     # true = an unreproducible sample is still deployed (with a warning)

    @field_validator("file")
    @classmethod
    def _file(cls, v):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}\.xml", v):
            raise ValueError("rule_deploy.file must be a plain file name ending in .xml")
        return v


_HM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


class Schedule(BaseModel):
    enabled: bool = True
    time: str = "07:30"  # HH:MM in app.timezone (single run per day)
    times: list[str] = Field(default_factory=list)  # several runs per day, e.g. ["07:50", "19:50"]; overrides `time`
    days: list[str] = Field(default_factory=lambda: list(DAYS))

    @property
    def all_times(self) -> list[str]:
        return sorted(set(self.times)) if self.times else [self.time]

    @field_validator("times")
    @classmethod
    def _times(cls, v):
        bad = [x for x in v if not _HM.fullmatch(x)]
        if bad:
            raise ValueError(f"times must be HH:MM: {bad}")
        return v

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        v = [d.lower()[:3] for d in v]
        bad = [d for d in v if d not in DAYS]
        if bad:
            raise ValueError(f"invalid day(s): {bad}")
        return v

    @field_validator("time")
    @classmethod
    def _time(cls, v):
        if not _HM.fullmatch(v):
            raise ValueError("time must be HH:MM")
        return v


class LLMConfig(BaseModel):
    provider: Literal["anthropic", "openai", "mock"] = "anthropic"
    model: str = ""
    base_url: str | None = None
    api_key: str = ""
    max_tokens: int = 4096
    temperature: float | None = 0.2   # leave empty for reasoning models that only accept the default
    # OpenAI-compatible: newer models want max_completion_tokens
    token_param: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    extra_body: dict = Field(default_factory=dict)  # passed through to the provider verbatim
    max_tool_steps: int = 14
    max_retries: int = 4              # retries on 429/5xx/overload with backoff (honours Retry-After)
    timeout: float = 180.0

    @field_validator("temperature", mode="before")
    @classmethod
    def _temp(cls, v):
        return None if v in ("", None) else v
