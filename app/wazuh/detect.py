# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Which Wazuh major version an environment talks to.

The server API says it outright (``GET /`` → ``api_version``). Without an API the index patterns tell:
``wazuh-alerts-4.x-*`` holds documents on 4.x, ``wazuh-findings-v5-*`` on 5.x. The result is informational today
(only 4.x is supported); from 1.0 on, ``wazuh_version: auto`` binds the matching schema.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

V5_FINDINGS = "wazuh-findings-v5-*"
_VER = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class Detection:
    major: int | None       # None: could not tell
    version: str            # full version when the API answered, else ""
    source: str             # "api", "indices" or "none"


def major_of(version: str | None) -> int | None:
    m = _VER.match(str(version or "").strip())
    return int(m.group(1)) if m else None


async def detect(api: Any, ix: Any, alerts_index: str) -> Detection:
    if api is not None:
        try:
            v = str((await api.info()).get("api_version") or "")
            if major_of(v):
                return Detection(major_of(v), v.lstrip("v"), "api")
        except Exception:  # noqa: BLE001 - fall back to the indices
            pass
    for pattern, major in ((alerts_index, 4), (V5_FINDINGS, 5)):
        try:
            if await ix.count(pattern, {"match_all": {}}) > 0:
                return Detection(major, "", "indices")
        except Exception:  # noqa: BLE001 - a missing pattern is not an answer
            continue
    return Detection(None, "", "none")


def verdict(configured: str, d: Detection) -> tuple[bool, str]:
    """(ok, detail) for the connection test."""
    seen = f"Wazuh {d.version or str(d.major) + '.x'} (from the {d.source})" if d.major else "version unknown"
    if d.major == 5:
        return False, f"{seen}: Wazuh 5.x is not supported yet — planned for Occultera 1.0 (wiki: Wazuh 5)"
    if configured not in ("auto", "", None) and d.major and str(d.major) != str(configured):
        return False, f"{seen}, but wazuh_version is {configured}"
    if d.major is None:
        return True, f"{seen}; assuming 4.x (set wazuh_version to be explicit)"
    return True, f"{seen}; schema {d.major}.x"
