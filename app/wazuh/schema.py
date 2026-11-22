# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Where things live in a Wazuh major version: index patterns, field paths and the level predicate.

Everything that builds an indexer query names fields through ``S`` instead of writing ``"rule.level"``: ``S`` is
the schema of the environment being worked on (``bind(env)`` at the entry points). Wazuh 4.x is the only schema
today; Wazuh 5.x (``wazuh-findings-v5-*``, Wazuh Common Schema, categorical severity) gets its own instance in
``v5`` and nothing outside this package changes. ``tests/test_layering.py`` keeps raw 4.x field paths from
creeping back into the rest of the code.

The level is kept as a number on every version: 5.x severities map to 4.x-style levels through
``SEVERITY_LEVELS`` so thresholds, bands and the watch keep one meaning.
"""
from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Schema:
    version: int
    alerts_index: str
    vuln_index: str
    # time and rule
    TS: str = "timestamp"
    RULE_ID: str = "rule.id"
    RULE_LEVEL: str = "rule.level"
    RULE_DESC: str = "rule.description"
    RULE_GROUPS: str = "rule.groups"
    MITRE: str = "rule.mitre"
    MITRE_ID: str = "rule.mitre.id"
    MITRE_TACTIC: str = "rule.mitre.tactic"
    # where it came from
    AGENT_ID: str = "agent.id"
    AGENT_NAME: str = "agent.name"
    AGENT_IP: str = "agent.ip"
    MANAGER: str = "manager.name"
    LOCATION: str = "location"
    DECODER: str = "decoder.name"
    DECODER_PARENT: str = "decoder.parent"
    PROGRAM: str = "predecoder.program_name"
    HOSTNAME: str = "predecoder.hostname"
    FULL_LOG: str = "full_log"
    DATA: str = "data"
    # decoded event data
    SRCIP: str = "data.srcip"
    DSTIP: str = "data.dstip"
    SRCPORT: str = "data.srcport"
    DSTPORT: str = "data.dstport"
    SRCUSER: str = "data.srcuser"
    DSTUSER: str = "data.dstuser"
    USER: str = "data.user"
    USERNAME: str = "data.user.username"
    URL: str = "data.url"
    VERB: str = "data.verb"
    PROTOCOL: str = "data.protocol"
    STATUS: str = "data.status"
    ACTION: str = "data.action"
    EVENT_ID: str = "data.id"
    SYSTEM_NAME: str = "data.system_name"
    EXTRA_DATA: str = "data.extra_data"
    DATA_DATA: str = "data.data"
    K8S_OBJECT: str = "data.objectRef"
    K8S_RESOURCE: str = "data.objectRef.resource"
    K8S_STATUS: str = "data.responseStatus.code"
    FIM_PATH: str = "syscheck.path"
    FIM_EVENT: str = "syscheck.event"
    # vulnerability detector events in the alerts index
    ALERT_CVE: str = "data.vulnerability.cve"
    ALERT_VULN_ID: str = "data.vulnerability.id"
    ALERT_VULN_SEV: str = "data.vulnerability.severity"
    ALERT_VULN_PKG: str = "data.vulnerability.package.name"
    # vulnerability state index
    VULN_ID: str = "vulnerability.id"
    VULN_SEV: str = "vulnerability.severity"
    VULN_DETECTED: str = "vulnerability.detected_at"
    PKG_NAME: str = "package.name"
    PKG_VERSION: str = "package.version"
    capabilities: frozenset[str] = field(default_factory=frozenset)

    # ------------------------------------------------------------ predicates whose shape differs per version
    def level_gte(self, n: int) -> dict[str, Any]:
        return {"range": {self.RULE_LEVEL: {"gte": int(n)}}}

    def level_range(self, gte: int | None = None, lte: int | None = None) -> dict[str, Any]:
        r: dict[str, int] = {}
        if gte is not None:
            r["gte"] = int(gte)
        if lte is not None:
            r["lte"] = int(lte)
        return {"range": {self.RULE_LEVEL: r}}

    def can(self, capability: str) -> bool:
        return capability in self.capabilities


V4 = Schema(
    version=4, alerts_index="wazuh-alerts-4.x-*", vuln_index="wazuh-states-vulnerabilities-*",
    capabilities=frozenset({"alerts", "vulnerabilities", "agents", "logtest", "rule_deploy", "rule_simulate"}),
)

SCHEMAS = {4: V4}


# ------------------------------------------------------------------ the query vocabulary (decision 22 Nov 2026)
# The AI and MCP clients always name fields with their Wazuh 4.x names (`rule.level`, `agent.name`,
# `data.srcip` …). The adapter translates them to the schema of the environment being queried, so prompts,
# tool parameters, the knowledge base and saved queries stay the same on 4.x and 5.x.
def _logical() -> dict[str, str]:
    from dataclasses import fields as _fields
    return {getattr(V4, f.name): f.name for f in _fields(Schema)
            if f.name.isupper() and isinstance(getattr(V4, f.name), str)}


LOGICAL: dict[str, str] = _logical()          # 4.x field name -> Schema attribute


def to_physical(name: str, schema: Schema | None = None) -> str:
    """A 4.x (logical) field name in the bound schema; unknown names (operator extra fields) pass unchanged."""
    attr = LOGICAL.get(name)
    if attr is None:
        attr = next((a for k, a in LOGICAL.items() if name.startswith(k + ".")), None)
        if attr is None:
            return name
        base = getattr(V4, attr)
        return getattr(schema or _CUR.get(), attr) + name[len(base):]
    return getattr(schema or _CUR.get(), attr)


def to_logical(name: str, schema: Schema | None = None) -> str:
    """The 4.x name for a field of the bound schema (so a physical name can be checked against the allow-list)."""
    sc = schema or _CUR.get()
    for k, attr in LOGICAL.items():
        if getattr(sc, attr) == name:
            return k
    return name

# 5.x severity → the 4.x-style level Occultera uses for thresholds (Wazuh publishes no mapping; this is ours).
SEVERITY_LEVELS = {"informational": 3, "low": 6, "medium": 9, "high": 12, "critical": 15}
LEVEL_BANDS = ((0, 3, "informational"), (4, 6, "low"), (7, 9, "medium"), (10, 12, "high"), (13, 16, "critical"))


def severity_of(level: int) -> str:
    for lo, hi, name in LEVEL_BANDS:
        if lo <= int(level) <= hi:
            return name
    return "critical"


# ------------------------------------------------------------------ the active schema
_CUR: contextvars.ContextVar[Schema] = contextvars.ContextVar("occultera_schema", default=V4)


def schema_for(env: Any) -> Schema:
    v = getattr(env, "wazuh_version", None)
    try:
        return SCHEMAS[int(v)] if v not in (None, "auto") else V4
    except (KeyError, TypeError, ValueError):
        return V4


def bind(env: Any) -> Schema:
    """Make ``S`` the schema of ``env`` for the current task (and the tasks it starts)."""
    s = schema_for(env)
    _CUR.set(s)
    return s


@contextmanager
def using(schema: Schema):
    tok = _CUR.set(schema)
    try:
        yield schema
    finally:
        _CUR.reset(tok)


def current() -> Schema:
    return _CUR.get()


class _Active:
    """``S.RULE_LEVEL`` reads the field of the schema bound to the current task."""

    __slots__ = ()

    def __getattr__(self, name: str) -> Any:
        return getattr(_CUR.get(), name)


S: Schema = _Active()  # type: ignore[assignment]
