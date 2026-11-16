# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Settings an administrator changes in the UI, stored in ``<prefix>-settings`` (one document per environment).

The YAML file stays the place for connections and credentials. What lives here is behaviour that should be
adjustable without a redeploy: the watch (rule-based alerts between AI rounds), when the AI round runs,
which of the *configured* notification channels the watch uses and when it stays quiet, the personal-data
masking profile and the backup reminder. No address, token or key is ever entered in the UI or stored
here — channels are referenced by name only.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import DAYS, Schedule

HM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")
CHANNELS = ("email", "telegram", "teams", "slack", "discord", "webhook", "ntfy")
TRIGGERS = ("level", "rules", "groups", "brute_force", "spike", "agents", "active_response")
# what the AI may suggest to change (and an admin may accept): name → (min, max)
TUNABLE: dict[str, tuple[float, float]] = {
    "critical_level": (1, 16), "group_min_level": (1, 16), "brute_failures": (3, 1000),
    "spike_factor": (1.5, 100), "spike_min": (10, 10_000_000), "agent_minutes": (5, 1440),
    "spike_min_level": (0, 16),
}
# groups whose alerts come in scheduled batches (scans): a burst of them is expected, not an attack
SPIKE_EXCLUDE = ("syscheck", "sca", "vulnerability-detector", "rootcheck", "syscollector", "ciscat", "oscap")
CUSTOM_NAME = re.compile(r"x_[a-z0-9_]{1,24}")
MAX_CUSTOM = 20
MAX_PATTERN = 200


def _days(v):
    v = [str(d).lower()[:3] for d in (v or [])]
    bad = [d for d in v if d not in DAYS]
    if bad:
        raise ValueError(f"invalid day(s): {bad}")
    return sorted(set(v), key=DAYS.index)


class QuietHours(BaseModel):
    """No watch notifications between ``start`` and ``end`` (local time; may cross midnight)."""
    enabled: bool = False
    start: str = "23:00"
    end: str = "07:00"
    days: list[str] = Field(default_factory=lambda: list(DAYS))     # the day the quiet period *starts* on
    allow_critical: bool = True                                     # critical events are sent anyway

    @field_validator("start", "end")
    @classmethod
    def _hm(cls, v):
        if not HM.fullmatch(v):
            raise ValueError("time must be HH:MM")
        return v

    @field_validator("days")
    @classmethod
    def _d(cls, v):
        return _days(v)

    def active(self, hm: str, day: str, prev_day: str) -> bool:
        if not self.enabled or self.start == self.end:
            return False
        if self.start < self.end:
            return day in self.days and self.start <= hm < self.end
        return (day in self.days and hm >= self.start) or (prev_day in self.days and hm < self.end)


class WatchSettings(BaseModel):
    """Rule-based alerts between AI rounds. Never calls the model."""
    enabled: bool = False
    interval_minutes: int = Field(5, ge=2, le=60)
    channels: list[str] = Field(default_factory=list)       # empty = every configured channel
    quiet: QuietHours = Field(default_factory=QuietHours)
    repeat_hours: float = Field(6, ge=0.25, le=168)         # the same event is not announced again within this
    triggers: dict[str, bool] = Field(default_factory=lambda: dict.fromkeys(TRIGGERS, True))
    critical_level: int = Field(12, ge=1, le=16)            # any alert at or above this level
    rules: list[str] | None = None                          # None = the environment's watch_rules
    groups: list[str] | None = None                         # None = the environment's watch_groups
    group_min_level: int = Field(10, ge=1, le=16)           # watched groups only count at/above this level
    brute_failures: int = Field(10, ge=3, le=1000)          # failed logins before a success, same source
    brute_window_minutes: int = Field(30, ge=5, le=240)
    spike_factor: float = Field(5.0, ge=1.5, le=100)        # × the 7-day average for a window of the same length
    spike_min: int = Field(50, ge=10, le=10_000_000)        # … and at least this many alerts
    spike_min_level: int = Field(7, ge=0, le=16)            # only alerts at or above this level count
    spike_exclude_groups: list[str] | None = None           # None = SPIKE_EXCLUDE (scheduled scans); ["-"] = none
    agent_minutes: int = Field(15, ge=5, le=1440)           # an agent counts as lost after this long
    mute: list[str] = Field(default_factory=list)           # event keys an admin silenced (often an AI suggestion)

    @model_validator(mode="before")
    @classmethod
    def _spike_v2(cls, v):
        # Before 0.12.1 the spike counted every alert, so 500 was the default floor. A stored 500 without the
        # new level setting is that old default: move it to the new one instead of silencing the trigger.
        if isinstance(v, dict) and "spike_min_level" not in v and v.get("spike_min") == 500:
            v = {**v, "spike_min": 50}
        return v

    def spike_excluded(self) -> list[str]:
        if self.spike_exclude_groups is None:
            return list(SPIKE_EXCLUDE)
        return [g for g in self.spike_exclude_groups if g != "-"]

    @field_validator("channels")
    @classmethod
    def _ch(cls, v):
        bad = [c for c in v if c not in CHANNELS]
        if bad:
            raise ValueError(f"unknown channel(s): {bad}")
        return sorted(set(v), key=CHANNELS.index)

    @field_validator("triggers", mode="before")
    @classmethod
    def _tr(cls, v):
        v = v or {}
        return {k: bool(v.get(k, True)) for k in TRIGGERS}

    @field_validator("rules", "groups", "spike_exclude_groups", mode="before")
    @classmethod
    def _list(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            v = re.split(r"[,\s]+", v)
        out = [str(x).strip() for x in v if str(x).strip()]
        bad = [x for x in out if not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", x)]
        if bad:
            raise ValueError(f"invalid rule id / group: {bad}")
        return out[:200]

    @field_validator("mute", mode="before")
    @classmethod
    def _mute(cls, v):
        return sorted({str(x).strip()[:200] for x in (v or []) if str(x).strip()})[:500]

    def on(self, trigger: str) -> bool:
        return self.enabled and self.triggers.get(trigger, True)


class AiRound(BaseModel):
    """When the model is asked. ``None`` keeps the schedule from the YAML file."""
    times: list[str] | None = None        # one or two HH:MM a day
    days: list[str] | None = None

    @field_validator("times")
    @classmethod
    def _t(cls, v):
        if v is None:
            return None
        v = sorted({x.strip() for x in v if x and x.strip()})
        if not v:
            return None
        if any(not HM.fullmatch(x) for x in v):
            raise ValueError("times must be HH:MM")
        if len(v) > 2:
            raise ValueError("at most two AI rounds a day")
        return v

    @field_validator("days")
    @classmethod
    def _d(cls, v):
        return _days(v) if v else None


class BackupSettings(BaseModel):
    remind_days: int = Field(30, ge=0, le=365)         # 0 = no reminder
    auto: bool = False                                 # only effective when S3 and a passphrase are configured
    auto_interval_days: int = Field(7, ge=1, le=90)
    include_runs: bool = True


class CustomDetector(BaseModel):
    name: str
    pattern: str
    description: str = ""

    @field_validator("name")
    @classmethod
    def _n(cls, v):
        v = v.strip().lower()
        if not CUSTOM_NAME.fullmatch(v):
            raise ValueError("custom detector names look like x_customer_no (x_ + lower case letters, digits, _)")
        return v

    @field_validator("pattern")
    @classmethod
    def _p(cls, v):
        from .privacy import compile_custom
        compile_custom(v)          # raises ValueError with the reason
        return v

    @field_validator("description")
    @classmethod
    def _desc(cls, v):
        return v.strip()[:200]


class MaskProfile(BaseModel):
    """The standard profile (built-in detectors) cannot be edited; this is what a site adds on top."""
    custom: list[CustomDetector] = Field(default_factory=list)
    allow: list[str] = Field(default_factory=list)       # regexes for values that are never masked
    disabled: list[str] = Field(default_factory=list)    # built-in, non-secret kinds switched off
    version: int = 0                                     # bumped on every change; recorded with each run

    @field_validator("custom")
    @classmethod
    def _c(cls, v):
        if len(v) > MAX_CUSTOM:
            raise ValueError(f"at most {MAX_CUSTOM} custom detectors")
        names = [d.name for d in v]
        if len(set(names)) != len(names):
            raise ValueError("custom detector names must be unique")
        return v

    @field_validator("allow")
    @classmethod
    def _a(cls, v):
        from .privacy import compile_custom
        out = [x.strip() for x in v if x and x.strip()][:100]
        for x in out:
            compile_custom(x)
        return out

    @field_validator("disabled")
    @classmethod
    def _dis(cls, v):
        from .privacy import DETECTORS
        secret = {d.kind for d in DETECTORS if d.secret}
        known = {d.kind for d in DETECTORS} | {"ip"}
        v = sorted({str(x) for x in v})
        if [x for x in v if x in secret]:
            raise ValueError("secret detectors (passwords, keys, tokens) cannot be switched off")
        if [x for x in v if x not in known]:
            raise ValueError(f"unknown detector(s): {[x for x in v if x not in known]}")
        return v

    def content(self) -> dict:
        return self.model_dump(exclude={"version"})


class EnvSettings(BaseModel):
    watch: WatchSettings = Field(default_factory=WatchSettings)
    ai: AiRound = Field(default_factory=AiRound)
    backup: BackupSettings = Field(default_factory=BackupSettings)
    mask: MaskProfile = Field(default_factory=MaskProfile)
    updated_at: str = ""
    updated_by: str = ""

    def schedule(self, base: Schedule) -> Schedule:
        """The YAML schedule with the AI-round times/days from the UI on top."""
        if self.ai.times is None and self.ai.days is None:
            return base
        return Schedule(enabled=base.enabled, time=base.time, times=self.ai.times or base.all_times,
                        days=self.ai.days or base.days)


DOC_ID = "settings"


def diff(a: Any, b: Any, path: str = "") -> list[str]:
    """Dotted paths whose values differ — for the audit trail (names only, never values)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for k in sorted(set(a) | set(b)):
            out += diff(a.get(k), b.get(k), f"{path}.{k}" if path else str(k))
        return out
    return [path] if a != b else []
