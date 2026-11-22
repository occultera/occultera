# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""User-interface texts: one module per language, the same keys in each.

Add a text: put the key in ``en.py`` and in every other language module (the parity check below fails at import
otherwise). Add a language: copy ``en.py``, translate it, and register it in ``CATALOG``, ``LANG_NAMES`` and
``OUTPUT_LANGUAGE``.
"""
from __future__ import annotations

from .de import MESSAGES as DE
from .en import MESSAGES as EN
from .es import MESSAGES as ES
from .fr import MESSAGES as FR
from .tr import MESSAGES as TR

CATALOG: dict[str, dict[str, str]] = {"en": EN, "tr": TR, "es": ES, "de": DE, "fr": FR}
LANG_NAMES = {'en': 'English', 'tr': 'Türkçe', 'es': 'Español', 'de': 'Deutsch', 'fr': 'Français'}
OUTPUT_LANGUAGE = {'en': 'English', 'tr': 'Turkish', 'es': 'Spanish', 'de': 'German', 'fr': 'French'}

__all__ = ["CATALOG", "DE", "EN", "ES", "FR", "LANG_NAMES", "OUTPUT_LANGUAGE", "TR", "t"]


def _check_parity() -> None:
    """Every catalogue must carry exactly the same keys as English.

    A missing key silently falls back to English, so a half-translated release looks
    fine in tests. Fail at import instead, with the exact keys per language.
    """
    base = set(EN)
    problems = []
    for lang, catalog in CATALOG.items():
        missing = sorted(base - set(catalog))
        extra = sorted(set(catalog) - base)
        if missing or extra:
            problems.append(f"{lang}: missing={missing} extra={extra}")
    if problems:
        raise RuntimeError("i18n catalogues are out of sync with EN — " + "; ".join(problems))


_check_parity()


def t(lang: str, key: str, **kw) -> str:
    s = CATALOG.get(lang, EN).get(key) or EN.get(key) or key
    return s.format(**kw) if kw else s
