# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""One environment, the application settings and the whole file."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, field_validator, model_validator

from ..backupcfg import BackupCfg
from ..notify import NotifyCfg
from ..wazuh.schema import V4
from .base import LANGUAGES
from .models import (
    ComplianceCfg,
    Endpoint,
    IncidentCfg,
    LivenessCfg,
    LLMConfig,
    MailCfg,
    PrivacyCfg,
    PromoteCfg,
    QueryLimitsCfg,
    RuleDeployCfg,
    Schedule,
    SourcesCfg,
    VulnSlaCfg,
)


class Environment(BaseModel):
    id: str
    name: str
    description: str = ""
    indexer: Endpoint
    api: Endpoint | None = None
    # Wazuh major version: "auto" reads it from the server API at startup (4 when it cannot tell). 5 is planned for
    # 1.0; see app/wazuh/schema.py and the wiki page "Wazuh 5".
    wazuh_version: Literal["auto", "4"] = "auto"

    @field_validator("wazuh_version", mode="before")
    @classmethod
    def _wv(cls, v):
        v = str(v).strip().lower() if v is not None else "auto"
        if v in ("5", "5.x"):
            raise ValueError("Wazuh 5.x is not supported yet: it is planned for Occultera 1.0 (wiki: Wazuh 5)")
        return {"4.x": "4", "": "auto"}.get(v, v)

    alerts_index: str = V4.alerts_index
    vuln_index: str = V4.vuln_index
    storage_prefix: str = "daily-triage"
    schedule: Schedule = Field(default_factory=Schedule)
    # Window: since the last successful run; min = fallback without a report, max = cap
    window_min_hours: int = 24
    window_max_hours: int = 96
    high_level: int = 7
    max_silence_minutes: int = 60
    disk_warn_percent: int = 75
    # Known, accepted warning flags (e.g. vuln_overdue while a patch plan runs): still listed, shown as "accepted"
    # and no longer turn the run's health into "warn". Critical flags (silence, daemons, red indexer) are never
    # downgraded.
    health_accept: list[str] = Field(default_factory=list)
    # Agent names (fnmatch patterns allowed) left out of the "agents not active" flag: retired machines not yet
    # removed, personal laptops that are often offline … They stay in the collected data.
    ignore_agents: list[str] = Field(default_factory=list)
    required_daemons: list[str] = Field(default_factory=lambda: [
        "wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd", "wazuh-apid"])
    watch_rules: list[str] = Field(default_factory=list)
    watch_groups: list[str] = Field(default_factory=list)
    context_file: str | None = None
    seed_file: str | None = None      # imported into the knowledge base once, on first use
    redact: bool = False              # legacy alias for privacy.mode: mask
    privacy: PrivacyCfg = Field(default_factory=PrivacyCfg)
    language: str | None = None       # report language override (en|tr)
    llm: LLMConfig | None = None      # per-environment model override (e.g. local model for regulated data)
    notify: NotifyCfg | None = None   # per-environment notification override
    rule_deploy: RuleDeployCfg = Field(default_factory=RuleDeployCfg)
    liveness: LivenessCfg = Field(default_factory=LivenessCfg)
    query: QueryLimitsCfg = Field(default_factory=QueryLimitsCfg)
    mail: MailCfg | None = None          # set to analyse e-mail channel saturation
    vuln_sla: VulnSlaCfg = Field(default_factory=VulnSlaCfg)
    compliance: ComplianceCfg = Field(default_factory=ComplianceCfg)
    promote: PromoteCfg = Field(default_factory=PromoteCfg)
    inventory: list[str] = Field(default_factory=list)   # expected agent names (coverage reconciliation)
    inventory_file: str | None = None    # one agent name per line (# comments allowed)
    sources: SourcesCfg = Field(default_factory=SourcesCfg)
    incident: IncidentCfg = Field(default_factory=IncidentCfg)
    anomaly: bool = True                  # deterministic rule×agent anomalies against a 14-day baseline
    run_retention_days: int = Field(default=0, ge=0)   # 0 = keep runs forever; knowledge is never pruned

    @field_validator("id")
    @classmethod
    def _id(cls, v):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,40}", v):
            raise ValueError("id must be lowercase letters/digits/-/_")
        return v

    @model_validator(mode="after")
    def _redact_alias(self):
        if self.redact and self.privacy.mode == "off":
            self.privacy.mode = "mask"
        self.redact = self.privacy.mode == "mask"
        return self

    @field_validator("watch_rules", mode="before")
    @classmethod
    def _rules(cls, v):
        return [str(x) for x in (v or [])]

    @field_validator("api", mode="before")
    @classmethod
    def _api(cls, v):
        if isinstance(v, dict) and not v.get("url"):
            return None
        return v

    def resolve(self, base: Path, rel: str | None) -> Path | None:
        if not rel:
            return None
        p = Path(rel)
        return p if p.is_absolute() else base / p

    def inventory_names(self, base: Path) -> list[str]:
        names = list(self.inventory)
        p = self.resolve(base, self.inventory_file)
        if p:
            try:
                names += [ln.split("#", 1)[0].strip() for ln in p.read_text(encoding="utf-8").splitlines()]
            except OSError:
                pass
        return sorted({n for n in names if n})

    def context_text(self, base: Path) -> str:
        p = self.resolve(base, self.context_file)
        try:
            return p.read_text(encoding="utf-8") if p else ""
        except OSError:
            return ""


class AppConfig(BaseModel):
    timezone: str = "UTC"
    language: str = "en"
    title: str = "Occultera"

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as e:
            raise ValueError(f"unknown timezone {v!r}; install the tzdata package") from e
        return v

    @field_validator("language")
    @classmethod
    def _lang(cls, v):
        if v not in LANGUAGES:
            raise ValueError(f"language must be one of {LANGUAGES}")
        return v


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    notify: NotifyCfg = Field(default_factory=NotifyCfg)
    backup: BackupCfg = Field(default_factory=BackupCfg)
    environments: list[Environment]
    base_dir: Path = Path(".")

    def env(self, env_id: str) -> Environment:
        for e in self.environments:
            if e.id == env_id:
                return e
        raise KeyError(env_id)

    def llm_for(self, env: Environment) -> LLMConfig:
        return env.llm or self.llm

    def notify_for(self, env: Environment) -> NotifyCfg:
        cfg = env.notify or self.notify
        if cfg.mask:
            from ..privacy import Masker, masker_for
            cfg = cfg.model_copy()
            cfg._masker = masker_for(env) or Masker(scope=env.id)
        return cfg

    def lang_for(self, env: Environment) -> str:
        return env.language if env.language in LANGUAGES else self.app.language
