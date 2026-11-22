# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""occultera-migrate (preview): custom Wazuh 4.x XML rules → Sigma, with a review list, a field map and a match
check on sample events. Works without the rest of Occultera:  python -m app.migrate local_rules.xml

Wazuh 5.0 moves detection to Sigma-compatible detectors in the indexer and does not migrate custom XML rules.
The target field names follow the Wazuh Common Schema as published for the 5.0 release candidates; they are
re-checked when 5.0 is generally available (see FIELDS in fields.py).
"""
from .convert import convert  # noqa: F401
from .fields import FIELDS, to_wcs  # noqa: F401
