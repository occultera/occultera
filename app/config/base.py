# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Shared pieces of the configuration: ${VAR} expansion, booleans, languages, weekdays."""
from __future__ import annotations

import os
import re

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
LANGUAGES = ("en", "tr", "es", "de", "fr")


def _expand(value):
    if isinstance(value, str):
        # like the shell's ${VAR:-default}: an empty variable also falls back to the default
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")




DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
